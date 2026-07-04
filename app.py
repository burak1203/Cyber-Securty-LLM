from flask import Flask, render_template_string, request, Response, send_file
import threading
import os
import sys
sys.path.append('.')
from main import run_full_analysis

app = Flask(__name__)

HTML = '''
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Siber Güvenlik Trafik ve Tehdit Analiz Paneli</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: linear-gradient(120deg, #e0eafc, #cfdef3); min-height: 100vh; }
        .container { background: #fff; padding: 50px 60px 40px 60px; border-radius: 28px; box-shadow: 0 4px 24px #b0c4de; max-width: 1200px; margin: 60px auto; }
        h1 { color: #1a355e; font-size: 2.3rem; margin-bottom: 10px; }
        button { padding: 12px 28px; font-size: 17px; background: linear-gradient(90deg, #2980b9, #6dd5fa); color: #fff; border: none; border-radius: 7px; cursor: pointer; margin-right: 10px; transition: background 0.2s; }
        button:disabled { background: #aaa; cursor: not-allowed; }
        .row { margin-bottom: 30px; }
        .panel { background: linear-gradient(120deg, #f7fbff 80%, #e0eafc 100%); border-radius: 18px; box-shadow: 0 4px 24px #b0c4de; padding: 32px 28px 24px 28px; margin-bottom: 38px; border: 1.5px solid #e3eaf3; position: relative; }
        .panel-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
        .panel h2 { font-size: 1.5rem; color: #1a355e; margin: 0; font-weight: 700; letter-spacing: 0.5px; }
        .icon-btn { background: #2980b9; border: none; border-radius: 50%; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: background 0.2s; margin-left: 12px; }
        .icon-btn:hover { background: #1761a0; }
        .icon-btn svg { width: 24px; height: 24px; fill: #fff; }
        pre { background: #222; color: #eee; padding: 22px; border-radius: 12px; max-height: 500px; overflow-y: auto; font-size: 16px; box-shadow: 0 2px 8px #e3eaf3 inset; border: 1px solid #2d5c88; margin: 0; scrollbar-width: thin; scrollbar-color: #b0c4de #222; }
        pre::-webkit-scrollbar { width: 8px; background: #222; }
        pre::-webkit-scrollbar-thumb { background: #b0c4de; border-radius: 6px; }
        .panel-actions { display: flex; align-items: center; gap: 18px; margin-top: 18px; }
        .timer-badge {
            display: inline-flex;
            align-items: center;
            background: linear-gradient(90deg, #e0f7fa 0%, #b2ebf2 100%);
            box-shadow: 0 2px 8px rgba(44, 62, 80, 0.10);
            border-radius: 24px;
            padding: 8px 18px 8px 12px;
            font-size: 1.15rem;
            font-weight: 600;
            color: #1565c0;
            margin-left: 18px;
            transition: box-shadow 0.2s;
            min-width: 110px;
            border: 1.5px solid #b2ebf2;
            animation: timerPulse 2s infinite;
        }
        .timer-badge:hover {
            box-shadow: 0 4px 16px rgba(44, 62, 80, 0.16);
        }
        .timer-icon {
            font-size: 1.3em;
            margin-right: 8px;
        }
        .timer-label {
            margin-right: 6px;
            color: #1976d2;
            font-weight: 500;
        }
        .timer-value {
            background: #fff;
            color: #1976d2;
            border-radius: 12px;
            padding: 2px 10px;
            font-weight: bold;
            margin-left: 2px;
            box-shadow: 0 1px 4px rgba(44, 62, 80, 0.07);
        }
        @keyframes timerPulse {
            0% { box-shadow: 0 2px 8px rgba(44,62,80,0.10);}
            50% { box-shadow: 0 4px 16px rgba(44,62,80,0.18);}
            100% { box-shadow: 0 2px 8px rgba(44,62,80,0.10);}
        }
        @media (max-width: 900px) {
            .container { padding: 10px; max-width: 98vw; }
            .panel { padding: 12px 6px; }
            pre { padding: 10px; font-size: 13px; }
            .panel h2 { font-size: 1.1rem; }
            .timer-badge { font-size: 0.98rem; padding: 6px 10px 6px 8px; min-width: 80px; }
        }
    </style>
    <script>
        let timerInterval = null;
        let totalSeconds = 0;
        function formatTime(secs) {
            let h = Math.floor(secs / 3600);
            let m = Math.floor((secs % 3600) / 60);
            let s = secs % 60;
            return (h > 0 ? (h + ' sa ') : '') + (m > 0 ? (m + ' dk ') : '') + (s + ' sn');
        }
        function updateTimerDisplay() {
            document.getElementById('timer').textContent = formatTime(totalSeconds);
        }
        function startTimer() {
            if (timerInterval) return;
            timerInterval = setInterval(function() {
                totalSeconds++;
                localStorage.setItem('analyzer_timer', totalSeconds);
                updateTimerDisplay();
            }, 1000);
        }
        function stopTimer() {
            if (timerInterval) {
                clearInterval(timerInterval);
                timerInterval = null;
            }
        }
        function resetTimer() {
            totalSeconds = 0;
            localStorage.setItem('analyzer_timer', totalSeconds);
            updateTimerDisplay();
        }
        function fetchLogs() {
            fetch('/logs')
                .then(response => response.text())
                .then(data => {
                    document.getElementById('logbox').textContent = data;
                });
        }
        function fetchLLM() {
            fetch('/llmlogs')
                .then(response => response.text())
                .then(data => {
                    document.getElementById('llmbox').textContent = data;
                });
        }
        setInterval(fetchLogs, 2000);
        setInterval(fetchLLM, 2000);
        window.onload = function() {
            fetchLogs();
            fetchLLM();
            let running = {{ 'true' if running else 'false' }};
            let stored = localStorage.getItem('analyzer_timer');
            totalSeconds = stored ? parseInt(stored) : 0;
            updateTimerDisplay();
            if (running) {
                startTimer();
            } else {
                stopTimer();
            }
        };
        function onStart() {
            resetTimer();
            setTimeout(startTimer, 100);
        }
        function onStop() {
            stopTimer();
        }
    </script>
</head>
<body>
<div class="container">
    <h1>Siber Güvenlik Trafik ve Tehdit Analiz Paneli</h1>
    <div style="color:#3a4d6b; font-size:1.1rem; margin-bottom:18px;">Gerçek zamanlı ağ trafiği ve tehdit tespiti, LLM destekli açıklamalar ile birlikte.</div>
    <form method="post" style="margin-bottom:28px; display: flex; align-items: center; gap: 10px;">
        <button type="submit" name="action" value="start" {% if running %}disabled{% endif %} onclick="onStart()">Analizi Başlat</button>
        <button type="submit" name="action" value="stop" {% if not running %}disabled{% endif %} onclick="onStop()">Analizi Durdur</button>
        <span class="timer-badge" id="timer-badge">
            <span class="timer-icon">⏱️</span>
            <span class="timer-label">Süre:</span>
            <span class="timer-value" id="timer">0 sn</span>
        </span>
    </form>
    <div class="panel">
        <div class="panel-header">
            <h2>Canlı Loglar</h2>
            <a href="/download/logs" class="icon-btn" title="İndir">
                <svg viewBox="0 0 24 24"><path d="M5 20h14v-2H5v2zm7-18c-1.1 0-2 .9-2 2v8.59l-2.3-2.3a1 1 0 0 0-1.4 1.42l4 4a1 1 0 0 0 1.4 0l4-4a1 1 0 1 0-1.4-1.42L13 12.59V4a2 2 0 0 0-2-2z"/><path d="M12 16v-6" stroke="#fff" stroke-width="2" stroke-linecap="round"/><path d="M9 13l3 3 3-3" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </a>
        </div>
        <pre id="logbox">Loglar yükleniyor...</pre>
    </div>
    <div class="panel">
        <div class="panel-header">
            <h2>LLM Loglar</h2>
            <a href="/download/llm" class="icon-btn" title="İndir">
                <svg viewBox="0 0 24 24"><path d="M5 20h14v-2H5v2zm7-18c-1.1 0-2 .9-2 2v8.59l-2.3-2.3a1 1 0 0 0-1.4 1.42l4 4a1 1 0 0 0 1.4 0l4-4a1 1 0 1 0-1.4-1.42L13 12.59V4a2 2 0 0 0-2-2z"/><path d="M12 16v-6" stroke="#fff" stroke-width="2" stroke-linecap="round"/><path d="M9 13l3 3 3-3" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </a>
        </div>
        <pre id="llmbox">LLM logları yükleniyor...</pre>
    </div>
</div>
</body>
</html>
'''

state_lock = threading.Lock()
app_state = {
    'is_running': False,
    'stop_signal': False,
    'analysis_thread': None
}

LOG_FILE = 'network_analysis.log'
LLM_LOG_FILE = 'llm_analysis.log'

def stop_flag():
    with state_lock:
        return app_state['stop_signal']

def run_analysis_task():
    # İşlem başladığında durumu kilitleyerek güncelle
    with state_lock:
        app_state['is_running'] = True
        app_state['stop_signal'] = False
        
    try:
        run_full_analysis(stop_flag=stop_flag)
    except Exception as e:
        print(f"Arka plan analiz hatası: {str(e)}")
    finally:
        # İşlem bittiğinde veya çöktüğünde durumu güvenli bir şekilde sıfırla
        with state_lock:
            app_state['is_running'] = False
            app_state['analysis_thread'] = None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        action = request.form.get('action')
        
        with state_lock:
            running_status = app_state['is_running']
            
        if action == 'start' and not running_status:
            with state_lock:
                app_state['stop_signal'] = False
                app_state['analysis_thread'] = threading.Thread(target=run_analysis_task, daemon=True)
                app_state['analysis_thread'].start()
                
        elif action == 'stop' and running_status:
            with state_lock:
                app_state['stop_signal'] = True

    # Sayfa renderlanırken güncel durumu güvenli bir şekilde al
    with state_lock:
        current_running_status = app_state['is_running']
        
    return render_template_string(HTML, running=current_running_status)

@app.route('/logs')
def logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            return Response(f.read(), mimetype='text/plain')
    return Response('Log dosyası henüz oluşturulmadı.', mimetype='text/plain')

@app.route('/llmlogs')
def llmlogs():
    if os.path.exists(LLM_LOG_FILE):
        with open(LLM_LOG_FILE, 'r', encoding='utf-8') as f:
            return Response(f.read(), mimetype='text/plain')
    return Response('LLM analiz dosyası henüz oluşturulmadı.', mimetype='text/plain')

@app.route('/download/logs')
def download_logs():
    return send_file(LOG_FILE, as_attachment=True, download_name='canli_loglar.txt')

@app.route('/download/llm')
def download_llm():
    return send_file(LLM_LOG_FILE, as_attachment=True, download_name='llm_analizleri.txt')

if __name__ == '__main__':
    # Production'da debug=False olmalıdır
    app.run(host='0.0.0.0', port=5000, debug=False)
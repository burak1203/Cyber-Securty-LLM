from flask import Flask, render_template, request, Response, send_file
import threading
import os
import sys

# Ensure local imports work correctly
sys.path.append('.')
from main import run_full_analysis

app = Flask(__name__)

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
    with state_lock:
        app_state['is_running'] = True
        app_state['stop_signal'] = False
        
    try:
        run_full_analysis(stop_flag=stop_flag)
    except Exception as e:
        print(f"[ERROR] Background analysis failed: {str(e)}")
    finally:
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

    with state_lock:
        current_running_status = app_state['is_running']
        
    return render_template('index.html', running=current_running_status)

@app.route('/logs')
def logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            return Response(f.read(), mimetype='text/plain')
    return Response('Log file has not been created yet.', mimetype='text/plain')

@app.route('/llmlogs')
def llmlogs():
    if os.path.exists(LLM_LOG_FILE):
        with open(LLM_LOG_FILE, 'r', encoding='utf-8') as f:
            return Response(f.read(), mimetype='text/plain')
    return Response('LLM analysis file has not been created yet.', mimetype='text/plain')

@app.route('/download/logs')
def download_logs():
    return send_file(LOG_FILE, as_attachment=True, download_name='live_network_logs.txt')

@app.route('/download/llm')
def download_llm():
    return send_file(LLM_LOG_FILE, as_attachment=True, download_name='llm_insights.txt')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
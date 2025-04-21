# app.py
from flask import Flask, render_template, request, jsonify
from scanner import DomainScanner
import threading
import uuid
from queue import Queue
import time

app = Flask(__name__)

# Store scan results with thread-safe queue
scan_results = {}
active_scans = {}  # To track active scans for stopping

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    domain = request.form.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {'status': 'running', 'results': [], 'lock': threading.Lock()}
    active_scans[scan_id] = {'thread': None, 'stop_event': threading.Event()}
    
    def run_scan():
        try:
            scanner = DomainScanner(domain)
            
            def log_callback(msg):
                with scan_results[scan_id]['lock']:
                    scan_results[scan_id]['results'].append(msg)
            
            scanner.log_message = log_callback
            scanner.stop_event = active_scans[scan_id]['stop_event']
            scanner.scan()
            
            with scan_results[scan_id]['lock']:
                if active_scans[scan_id]['stop_event'].is_set():
                    scan_results[scan_id]['status'] = 'stopped'
                else:
                    scan_results[scan_id]['status'] = 'completed'
                
        except Exception as e:
            with scan_results[scan_id]['lock']:
                scan_results[scan_id]['status'] = 'error'
                scan_results[scan_id]['results'].append(f"Error: {str(e)}")
        finally:
            if scan_id in active_scans:
                del active_scans[scan_id]
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    active_scans[scan_id]['thread'] = thread
    thread.start()
    
    return jsonify({'scan_id': scan_id})

@app.route('/scan/<scan_id>/stop', methods=['POST'])
def stop_scan(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found or already completed'}), 404
    
    active_scans[scan_id]['stop_event'].set()
    return jsonify({'status': 'stopping'})

@app.route('/scan/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    with scan_results[scan_id]['lock']:
        return jsonify({
            'status': scan_results[scan_id]['status'],
            'results': scan_results[scan_id]['results']
        })

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
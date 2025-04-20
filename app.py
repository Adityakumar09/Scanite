from flask import Flask, render_template, request, jsonify
from scanner import DomainScanner
import threading
import uuid
import os

app = Flask(__name__)

# Store scan results in memory
scan_results = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    domain = request.form.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {'status': 'running', 'results': []}
    
    def run_scan():
        scanner = DomainScanner(domain)
        scanner.LogMessage = lambda msg: scan_results[scan_id]['results'].append(msg)
        try:
            scanner.Scan()
            scan_results[scan_id]['status'] = 'completed'
        except Exception as e:
            scan_results[scan_id]['status'] = 'error'
            scan_results[scan_id]['results'].append(f"Error: {str(e)}")
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    return jsonify({'scan_id': scan_id})

@app.route('/scan/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'status': scan_results[scan_id]['status'],
        'results': scan_results[scan_id]['results']
    })

if __name__ == '__main__':
    app.run(debug=True)
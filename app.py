"""
Advanced SQL Dumper Pro - Flask Application
"""
from flask import Flask, render_template, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
import json
import csv
import io
import os
from datetime import datetime
from engine import SQLiScanner
import threading

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dumper.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

db = SQLAlchemy(app)

# Database model for session history
class ScanSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    param = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.Column(db.JSON)
    status = db.Column(db.String(50), default='pending')
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'param': self.param,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status,
            'results': self.results,
        }


# Create tables
with app.app_context():
    db.create_all()


# Store active scans
active_scans = {}
scan_logs = {}


@app.route('/')
def index():
    """Serve main page."""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new SQL injection scan."""
    try:
        data = request.json
        
        # Validate input
        url = data.get('url')
        param = data.get('param', 'id')
        method = data.get('method', 'GET')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Create scan session
        session = ScanSession(
            url=url,
            param=param,
            status='running'
        )
        db.session.add(session)
        db.session.commit()
        
        # Initialize scan logs
        scan_logs[session.id] = []
        
        # Parse additional options
        proxy = data.get('proxy')
        cookies = data.get('cookies')
        user_agent = data.get('user_agent')
        custom_headers = data.get('custom_headers', {})
        tamper_options = data.get('tamper_options', [])
        
        if isinstance(custom_headers, str):
            try:
                custom_headers = json.loads(custom_headers)
            except:
                custom_headers = {}
        
        # Create scanner
        def progress_callback(log_entry):
            """Callback for scan progress."""
            scan_logs[session.id].append(log_entry)
        
        scanner = SQLiScanner(
            url=url,
            param=param,
            method=method,
            timeout=10,
            tamper_options=tamper_options,
            proxy=proxy,
            cookies=cookies,
            user_agent=user_agent,
            custom_headers=custom_headers,
            progress_callback=progress_callback,
        )
        
        # Run scan in background
        def run_scan():
            try:
                results = scanner.scan()
                session.results = results
                session.status = 'completed'
            except Exception as e:
                session.results = {'error': str(e)}
                session.status = 'failed'
            finally:
                db.session.commit()
        
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        active_scans[session.id] = thread
        
        return jsonify({
            'scan_id': session.id,
            'status': 'started',
        }), 202
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/<int:scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status and progress."""
    try:
        session = ScanSession.query.get(scan_id)
        if not session:
            return jsonify({'error': 'Scan not found'}), 404
        
        logs = scan_logs.get(scan_id, [])
        
        return jsonify({
            'scan_id': scan_id,
            'status': session.status,
            'logs': logs,
            'results': session.results if session.status == 'completed' else None,
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/<int:scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get scan results."""
    try:
        session = ScanSession.query.get(scan_id)
        if not session:
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify(session.results), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/<int:scan_id>/export', methods=['GET'])
def export_scan_results(scan_id):
    """Export scan results as CSV."""
    try:
        session = ScanSession.query.get(scan_id)
        if not session or not session.results:
            return jsonify({'error': 'Scan not found or no results'}), 404
        
        results = session.results
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output, delimiter='|')
        
        # Write header
        writer.writerow(['Database', 'Table', 'Column', 'Data'])
        
        # Write data
        for db_name, tables in results.get('data', {}).items():
            for table_name, rows in tables.items():
                for row in rows:
                    for col, value in row.items():
                        writer.writerow([db_name, table_name, col, value])
        
        # Create response
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'dump_{scan_id}.csv'
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sessions', methods=['GET'])
def get_sessions():
    """Get list of recent scan sessions."""
    try:
        sessions = ScanSession.query.order_by(ScanSession.timestamp.desc()).limit(10).all()
        return jsonify([s.to_dict() for s in sessions]), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sessions/<int:session_id>', methods=['DELETE'])
def delete_session(session_id):
    """Delete a scan session."""
    try:
        session = ScanSession.query.get(session_id)
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        db.session.delete(session)
        db.session.commit()
        
        # Clean up logs
        if session_id in scan_logs:
            del scan_logs[session_id]
        
        return jsonify({'status': 'deleted'}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors."""
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

"""
Flask Web Application for Intrusion Detection Dashboard
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
import datetime
import functools
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash
from intrusion_detector import IntrusionDetector
from alert_system import AlertSystem
from utils import setup_logging, load_model
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG, BEST_MODEL_PATH

logger = setup_logging(__name__)

# ── File-based user storage ───────────────────────────────────────────────────
USERS_FILE = os.path.join(os.path.dirname(__file__), 'users.json')

def load_users():
    """Load users from users.json file."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading users: {e}")
    return {}

def save_users(users):
    """Save users to users.json file."""
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        logger.info("users.json updated successfully")
        return True
    except Exception as e:
        logger.error(f"Error saving users: {e}")
        return False

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'intrusion-detection-secret-key-2024'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
detector = None
monitoring_active = False
stats = {
    'total_packets': 0,
    'normal_traffic': 0,
    'attacks_detected': 0,
    'attack_rate': 0.0
}

# In-memory alert store — keeps ALL detected attacks regardless of confidence threshold
from collections import deque
all_alerts = deque(maxlen=200)       # last 200 alerts
traffic_history = deque(maxlen=100)  # last 100 traffic events (normal + attack)

# ── Auth helper ───────────────────────────────────────────────────────────────
def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access the dashboard.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ── Home / Landing page ──────────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('home.html')

# ── Login ────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        users = load_users()

        if username in users and check_password_hash(users[username]['password'], password):
            session['logged_in'] = True
            session['username']  = username
            session['role']      = users[username].get('role', 'user')
            flash(f'Welcome back, {username}! Dashboard is ready.', 'success')
            logger.info(f"User '{username}' logged in.")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
            logger.warning(f"Failed login attempt for username: '{username}'")

    return render_template('login.html')

# ── Sign Up ───────────────────────────────────────────────────────────────────
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        users    = load_users()

        # Validate
        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
        elif not username.isalnum():
            flash('Username can only contain letters and numbers.', 'error')
        elif username in users:
            flash(f'Username "{username}" is already taken. Choose another.', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
        elif password != confirm:
            flash('Passwords do not match. Please try again.', 'error')
        else:
            # All good — save new user
            users[username] = {
                'password': generate_password_hash(password),
                'role':     'user',
                'created':  datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
            }
            if save_users(users):
                flash(f'Account created successfully! Welcome, {username}. You can now log in.', 'success')
                logger.info(f"New user registered: '{username}'")
                return redirect(url_for('login'))
            else:
                flash('Registration failed due to a server error. Please try again.', 'error')

    return render_template('signup.html')

# ── Logout ───────────────────────────────────────────────────────────────────
@app.route('/logout')
def logout():
    username = session.get('username', 'User')
    session.clear()
    flash(f'You have been logged out successfully. Goodbye, {username}!', 'success')
    logger.info(f"User '{username}' logged out.")
    return redirect(url_for('home'))

# ── Dashboard (protected) ────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html', username=session.get('username', 'Admin'))

@app.route('/api/status')
def get_status():
    """
    Get system status
    """
    return jsonify({
        'monitoring_active': monitoring_active,
        'model_loaded': detector is not None,
        'stats': stats
    })

@app.route('/api/stats')
def get_stats():
    """
    Get detection statistics
    """
    global detector, stats
    
    if detector:
        stats['total_packets'] = detector.total_packets
        stats['normal_traffic'] = detector.total_normal
        stats['attacks_detected'] = detector.total_attacks
        
        if detector.total_packets > 0:
            stats['attack_rate'] = (detector.total_attacks / detector.total_packets) * 100
    
    return jsonify(stats)

@app.route('/api/alerts')
def get_alerts():
    """
    Get recent alerts — returns ALL detected attacks (not threshold-filtered)
    """
    global all_alerts, detector

    alerts_list = list(all_alerts)[-50:]  # most recent 50
    alerts_list.reverse()  # newest first

    # Attack distribution summary
    dist = {}
    for a in all_alerts:
        atype = a.get('attack_type', 'Unknown')
        dist[atype] = dist.get(atype, 0) + 1

    alert_stats = {
        'total_alerts': len(all_alerts),
        'attack_distribution': dist,
        'recent_alerts_count': len(alerts_list)
    }

    return jsonify({'alerts': alerts_list, 'stats': alert_stats})

@app.route('/api/traffic')
def get_traffic():
    """Return recent traffic history for page-load population of the Live Feed."""
    global traffic_history
    events = list(traffic_history)[-50:]
    events.reverse()   # newest first
    return jsonify(events)

@app.route('/debug/simulate_attack')
@login_required
def simulate_attack():
    """Simulated alert for testing dashboard UI — cycles through all attack types"""
    import itertools
    # Use a persistent counter stored in app config
    ATTACK_TYPES = ['DoS', 'Probe', 'R2L', 'U2R']
    if not hasattr(app, '_sim_attack_idx'):
        app._sim_attack_idx = 0
    test_prediction = ATTACK_TYPES[app._sim_attack_idx % len(ATTACK_TYPES)]
    app._sim_attack_idx += 1

    conf_f   = 0.90 + (app._sim_attack_idx % 10) * 0.005
    src_str  = f'192.168.1.{(app._sim_attack_idx % 200) + 10}'
    dst_str  = f'10.0.0.{(app._sim_attack_idx % 50) + 1}'
    proto_str = ['TCP/HTTP', 'UDP/DNS', 'TCP/FTP', 'ICMP'][app._sim_attack_idx % 4]

    attack_alert = {
        'timestamp':   datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'attack_type': test_prediction.upper(),
        'confidence':  f'{conf_f*100:.1f}%',
        'source_ip':   src_str,
        'dest_ip':     dst_str,
        'protocol':    proto_str,
        'severity':    'HIGH' if conf_f > 0.85 else 'MEDIUM'
    }
    all_alerts.append(attack_alert)
    socketio.emit('new_alert', attack_alert)

    if detector:
        detector.total_packets += 1
        detector.total_attacks += 1

    socketio.emit('stats_update', {
        'total_packets':    detector.total_packets if detector else app._sim_attack_idx,
        'normal_traffic':   detector.total_normal  if detector else 0,
        'attacks_detected': detector.total_attacks if detector else app._sim_attack_idx,
        'attack_rate': (detector.total_attacks / detector.total_packets * 100)
                       if detector and detector.total_packets > 0 else 100
    })

    return jsonify({'success': True, 'message': f'Simulated {test_prediction} attack sent to dashboard'})

@app.route('/api/hosts')
def get_known_hosts():
    """
    Get list of known hosts
    """
    global detector
    
    if detector:
        hosts = detector.host_tracker.get_all_hosts()
        # Sort by last_seen descending
        hosts.sort(key=lambda x: x.get('last_seen', ''), reverse=True)
        return jsonify(hosts)
    
    return jsonify([])

@app.route('/api/start_monitoring', methods=['POST'])
def start_monitoring():
    """
    Start real-time monitoring
    """
    global detector, monitoring_active
    
    try:
        data = request.get_json()
        interface = data.get('interface', None)
        
        if not detector:
            detector = IntrusionDetector(interface=interface)
        
        if not monitoring_active:
            monitoring_active = True  # Set BEFORE starting thread to avoid race condition

            # Start monitoring in background thread
            monitoring_thread = threading.Thread(
                target=run_monitoring,
                daemon=True
            )
            monitoring_thread.start()

            logger.info("Monitoring thread started")
            return jsonify({'success': True, 'message': 'Monitoring started'})
        else:
            return jsonify({'success': False, 'message': 'Monitoring already active'})
    
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/stop_monitoring', methods=['POST'])
def stop_monitoring():
    """
    Stop real-time monitoring
    """
    global detector, monitoring_active
    
    try:
        if detector and monitoring_active:
            detector.packet_capture.stop_capture()
            monitoring_active = False
            
            return jsonify({'success': True, 'message': 'Monitoring stopped'})
        else:
            return jsonify({'success': False, 'message': 'Monitoring not active'})
    
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/model_info')
def get_model_info():
    """
    Get model information
    """
    try:
        import os
        model_exists = os.path.exists(BEST_MODEL_PATH)
        
        return jsonify({
            'model_path': BEST_MODEL_PATH,
            'model_exists': model_exists,
            'model_loaded': detector is not None
        })
    
    except Exception as e:
        return jsonify({'error': str(e)})

def run_monitoring():
    """
    Background monitoring task
    """
    global detector, monitoring_active

    try:
        logger.info("run_monitoring() started")

        # Start packet capture
        detector.packet_capture.start_capture_async()
        logger.info("Packet capture started inside run_monitoring")

        # Monitor and emit updates
        while monitoring_active:
            time.sleep(2)  # Process every 2 seconds

            # Flush buffer and get any queued flows
            flow_features_list = detector.packet_capture.get_flow_features()

            # If nothing in the queue, force-flush remaining buffer
            if not flow_features_list and detector.packet_capture.packet_buffer:
                detector.packet_capture._process_buffer()
                flow_features_list = detector.packet_capture.get_flow_features()

            logger.debug(f"Got {len(flow_features_list)} flow(s) this cycle")

            if flow_features_list:
                for flow_features in flow_features_list:
                    try:
                        prediction, confidence = detector.classify_traffic(flow_features)
                    except Exception as ce:
                        logger.error(f"classify_traffic error: {ce}")
                        continue

                    if not prediction:
                        continue

                    # ── Extract network metadata once ─────────────────────
                    ff        = flow_features if isinstance(flow_features, dict) else {}
                    src_ip    = ff.get('src_ip') or 'N/A'
                    dst_ip    = ff.get('dst_ip') or 'N/A'
                    protocol  = (ff.get('protocol_type') or ff.get('protocol') or 'N/A')
                    if isinstance(protocol, int):
                        proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
                        protocol  = proto_map.get(protocol, str(protocol))
                    protocol  = str(protocol).upper()
                    service   = ff.get('service', '')
                    src_port  = ff.get('src_port', '')
                    dst_port  = ff.get('dst_port', '')
                    src_str   = f"{src_ip}:{src_port}" if src_port else src_ip
                    dst_str   = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
                    proto_str = f"{protocol}/{str(service).upper()}" if service and str(service) != 'other' else protocol
                    conf_f    = float(confidence)

                    logger.info(f"DETECTED: [{prediction}] | Confidence: {conf_f*100:.1f}% | {src_str} -> {dst_str}")

                    # ── Live Traffic Feed (ALL predictions) ───────────────
                    traffic_event = {
                        'prediction':     prediction,
                        'confidence':     conf_f,
                        'confidence_pct': f'{conf_f*100:.1f}%',
                        'timestamp':      time.time(),
                        'time_str':       datetime.datetime.now().strftime('%H:%M:%S'),
                        'source_ip':      src_str,
                        'dest_ip':        dst_str,
                        'protocol':       proto_str,
                    }
                    traffic_history.append(traffic_event)
                    socketio.emit('traffic_update', traffic_event)

                    # ── Stats update ──────────────────────────────────────
                    socketio.emit('stats_update', {
                        'total_packets':    detector.total_packets,
                        'normal_traffic':   detector.total_normal,
                        'attacks_detected': detector.total_attacks,
                        'attack_rate': (detector.total_attacks / detector.total_packets * 100)
                                       if detector.total_packets > 0 else 0
                    })

                    # ── Alert (non-normal only) ───────────────────────────
                    if prediction.lower() != 'normal':
                        attack_alert = {
                            'timestamp':   datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'attack_type': prediction.upper(),
                            'confidence':  f'{conf_f*100:.1f}%',
                            'source_ip':   src_str,
                            'dest_ip':     dst_str,
                            'protocol':    proto_str,
                            'severity':    'HIGH' if conf_f > 0.85 else 'MEDIUM'
                        }
                        all_alerts.append(attack_alert)
                        socketio.emit('new_alert', attack_alert)
                        logger.warning(
                            f"ATTACK DETECTED: {prediction} | {src_str} -> {dst_str} "
                            f"| {proto_str} | {conf_f*100:.1f}%"
                        )

    except Exception as e:
        logger.error(f"FATAL ERROR in run_monitoring: {e}", exc_info=True)
        monitoring_active = False

@socketio.on('connect')
def handle_connect():
    """
    Handle WebSocket connection
    """
    logger.info("Client connected to WebSocket")
    emit('connection_response', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """
    Handle WebSocket disconnection
    """
    logger.info("Client disconnected from WebSocket")

def initialize_detector():
    """
    Initialize detector on startup
    """
    global detector
    
    try:
        logger.info("Initializing intrusion detector...")
        detector = IntrusionDetector()
        logger.info("Detector initialized successfully")
    except Exception as e:
        logger.warning(f"Could not initialize detector: {e}")
        logger.warning("Please train the model first using train_models.py")

if __name__ == '__main__':
    logger.info("="*60)
    logger.info("INTRUSION DETECTION DASHBOARD")
    logger.info("="*60)
    logger.info(f"Starting server on {FLASK_HOST}:{FLASK_PORT}")
    logger.info("="*60)
    
    # Initialize detector
    # initialize_detector()  # Comment out if model not trained yet
    
    # Run Flask app
    socketio.run(app, host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)

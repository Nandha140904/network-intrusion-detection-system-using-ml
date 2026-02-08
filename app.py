"""
Flask Web Application for Intrusion Detection Dashboard
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
from intrusion_detector import IntrusionDetector
from alert_system import AlertSystem
from utils import setup_logging, load_model
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG, BEST_MODEL_PATH

logger = setup_logging(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'intrusion-detection-secret-key'
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

@app.route('/')
def index():
    """
    Render main dashboard
    """
    return render_template('index.html')

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
    Get recent alerts
    """
    global detector
    
    if detector:
        recent_alerts = detector.alert_system.get_recent_alerts(count=50)
        alert_stats = detector.alert_system.get_alert_stats()
        
        return jsonify({
            'alerts': recent_alerts,
            'stats': alert_stats
        })
    
    return jsonify({'alerts': [], 'stats': {}})

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
            # Start monitoring in background thread
            monitoring_thread = threading.Thread(
                target=run_monitoring,
                daemon=True
            )
            monitoring_thread.start()
            monitoring_active = True
            
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
        # Start packet capture
        detector.packet_capture.start_capture_async()
        
        # Monitor and emit updates
        while monitoring_active:
            time.sleep(2)  # Update every 2 seconds
            
            # Get flow features
            flow_features = detector.packet_capture.get_flow_features()
            
            if flow_features:
                # Classify traffic
                prediction, confidence = detector.classify_traffic(flow_features)
                
                if prediction:
                    # Emit real-time update via WebSocket
                    socketio.emit('traffic_update', {
                        'prediction': prediction,
                        'confidence': float(confidence),
                        'timestamp': time.time()
                    })
                    
                    # Emit stats update
                    socketio.emit('stats_update', {
                        'total_packets': detector.total_packets,
                        'normal_traffic': detector.total_normal,
                        'attacks_detected': detector.total_attacks,
                        'attack_rate': (detector.total_attacks / detector.total_packets * 100) if detector.total_packets > 0 else 0
                    })
                    
                    # Emit alert if attack detected
                    if prediction != 'normal':
                        recent_alerts = detector.alert_system.get_recent_alerts(count=1)
                        if recent_alerts:
                            socketio.emit('new_alert', recent_alerts[0])
    
    except Exception as e:
        logger.error(f"Error in monitoring: {e}")
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

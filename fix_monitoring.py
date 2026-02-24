"""Fixes the run_monitoring function in app.py"""
import re

with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

NEW_FUNC = '''def run_monitoring():
    """
    Background monitoring task
    """
    global detector, monitoring_active

    try:
        # Start packet capture
        detector.packet_capture.start_capture_async()

        # Monitor and emit updates
        while monitoring_active:
            time.sleep(1)

            # Get flow features
            flow_features_list = detector.packet_capture.get_flow_features()

            # Wrap single dict in list
            if isinstance(flow_features_list, dict):
                flow_features_list = [flow_features_list]

            if flow_features_list:
                for flow_features in flow_features_list:
                    prediction, confidence = detector.classify_traffic(flow_features)

                    if prediction:
                        # ── Extract network metadata once ─────────────────────
                        ff        = flow_features if isinstance(flow_features, dict) else {}
                        src_ip    = ff.get('src_ip') or 'N/A'
                        dst_ip    = ff.get('dst_ip') or 'N/A'
                        protocol  = (ff.get('protocol_type') or ff.get('protocol') or 'N/A')
                        if isinstance(protocol, int):
                            proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
                            protocol  = proto_map.get(protocol, str(protocol))
                        protocol  = protocol.upper()
                        service   = ff.get('service', '')
                        src_port  = ff.get('src_port', '')
                        dst_port  = ff.get('dst_port', '')
                        src_str   = f"{src_ip}:{src_port}" if src_port else src_ip
                        dst_str   = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
                        proto_str = f"{protocol}/{service.upper()}" if service and service != 'other' else protocol
                        conf_f    = float(confidence)

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
                        if prediction != 'normal':
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
                                f"ATTACK: {prediction} | {src_str} -> {dst_str} "
                                f"| {proto_str} | {conf_f*100:.1f}%"
                            )

    except Exception as e:
        logger.error(f"Error in monitoring: {e}")
        monitoring_active = False
'''

# Replace from 'def run_monitoring' up to the next top-level @socketio or def
pattern = r'def run_monitoring\(\):.*?(?=\n@socketio\.on)'
replacement = NEW_FUNC.rstrip('\n')

new_content, count = re.subn(pattern, replacement, content, flags=re.DOTALL)
if count == 0:
    print("ERROR: pattern not matched - no replacement made")
else:
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f"SUCCESS: replaced {count} occurrence(s)")

"""Local-only UI and API. Response actions require operator interaction."""
import os
import math
from flask import Flask, jsonify, render_template, request
from .storage import initialize, read_dashboard, read_observation, read_suspicious_ips
from .response import audit, policies, request_action, valid_ip
from .investigation import (risk_assessment, list_incidents, create_incident, update_incident, traffic_analysis, initialize_incidents)

app = Flask(__name__, template_folder='templates')


@app.get('/')
def index():
    return render_template('index.html')


def _filter_number(name):
    raw = request.args.get(name)
    if raw is None or raw == '':
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError(f'{name} must be a Unix timestamp')
    if not math.isfinite(value) or value < 0 or value > 4102444800:
        raise ValueError(f'{name} is outside the allowed timestamp range')
    return value


def _bounds(prefix):
    start, end = _filter_number(prefix + '_from'), _filter_number(prefix + '_to')
    if start is not None and end is not None and start > end:
        raise ValueError('Start time must be before end time')
    return start, end


def _severity():
    severity = request.args.get('severity', 'all')
    if severity not in ('all', 'High', 'Medium', 'Low'):
        raise ValueError('Invalid severity')
    return None if severity == 'all' else severity


def _page_number(name, default, minimum, maximum):
    raw = request.args.get(name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f'{name} must be an integer') from None
    if not minimum <= value <= maximum:
        raise ValueError(f'{name} must be between {minimum} and {maximum}')
    return value


@app.get('/api/stats')
def stats():
    try:
        start, end = _bounds('alert')
        return jsonify(read_dashboard(alert_start=start, alert_end=end, alert_severity=_severity(),
             alert_limit=_page_number('limit', 30, 1, 100),
             alert_offset=_page_number('offset', 0, 0, 1000000)))
    except ValueError as error:
        return jsonify({'error': str(error)}), 400


@app.get('/api/suspicious-ips')
def suspicious_ips():
    return jsonify({'sources': read_suspicious_ips()})


@app.get('/api/response')
def response_view():
    return jsonify({'policies': policies(), 'audit': audit()})


@app.post('/api/response')
def response_post():
    # Browser same-origin safeguard: no remote browser origins or simple cross-site forms.
    if request.headers.get('X-NetSentry-Action') != 'human-review':
        return jsonify({'error': 'Missing operator action header'}), 403
    origin = request.headers.get('Origin', '')
    if not origin or origin != request.host_url.rstrip('/'):
        return jsonify({'error': 'Same-origin requests only'}), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'JSON request required'}), 400
    try:
        ip = valid_ip(data.get('ip'))
        # Only sources with actual alerts can be actioned; enforcer separately validates lab subnet.
        # For alerts beyond latest 40, use database directly.
        from .storage import connect
        with connect() as db:
            seen = db.execute('SELECT 1 FROM alerts WHERE source_ip=? LIMIT 1', (ip,)).fetchone()
        if not seen:
            return jsonify({'error': 'IP must have a NetSentry alert before containment'}), 400
        result = request_action(ip, data.get('mode'), data.get('reason', ''))
    except ValueError as error:
        return jsonify({'error': str(error)}), 400
    return jsonify(result), 202  # Applied asynchronously by the lab-only enforcer.


@app.get('/observe/<ip>')
def observation_page(ip):
    try:
        ip = valid_ip(ip)
    except ValueError:
        return 'Invalid IP address', 400
    return render_template('observation.html', ip=ip)


@app.get('/api/observe/<ip>')
def observation_data(ip):
    try:
        a_start, a_end = _bounds('alert')
        p_start, p_end = _bounds('packet')
        return jsonify(read_observation(ip, alert_start=a_start, alert_end=a_end,
                        alert_severity=_severity(), packet_start=p_start, packet_end=p_end,
                        packet_protocol=request.args.get('protocol', 'all')))
    except ValueError as error:
        return jsonify({'error': str(error)}), 400


@app.get('/health')
def health():
    return jsonify({'status': 'ok'})


@app.get('/api/investigate/<ip>')
def investigate(ip):
    try:
        return jsonify({'risk':risk_assessment(ip), 'traffic':traffic_analysis(ip), **list_incidents(ip)})
    except ValueError as error:
        return jsonify({'error':str(error)}), 400


@app.post('/api/investigate/<ip>/incidents')
def incident_create(ip):
    if not _allowed_human_action():
        return jsonify({'error':'Same-origin human action required'}), 403
    data=request.get_json(silent=True)
    if not isinstance(data,dict):
        return jsonify({'error':'JSON required'}),400
    try:
        result=create_incident(ip,data.get('title'),data.get('actor'),data.get('note'))
    except ValueError as error:
        return jsonify({'error':str(error)}),400
    return jsonify(result),201


@app.post('/api/investigate/<ip>/incidents/<int:incident_id>')
def incident_update(ip,incident_id):
    if not _allowed_human_action():
        return jsonify({'error':'Same-origin human action required'}),403
    data=request.get_json(silent=True)
    if not isinstance(data,dict):return jsonify({'error':'JSON required'}),400
    try:
        result=update_incident(ip,incident_id,data.get('actor'),data.get('status'),data.get('note'))
    except ValueError as error:
        return jsonify({'error':str(error)}),400
    return jsonify(result)


def _allowed_human_action():
    return (request.headers.get('X-NetSentry-Action')=='human-review' and
            bool(request.headers.get('Origin')) and
            request.headers.get('Origin')==request.host_url.rstrip('/'))


if __name__ == '__main__':
    initialize()
    initialize_incidents()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=False)

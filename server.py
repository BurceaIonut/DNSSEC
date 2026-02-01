# server.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from dataclasses import asdict
from inspector import DnssecChainCollector

app = Flask(__name__)
CORS(app)  

@app.route('/api/inspect', methods=['POST'])
def inspect():
    data = request.json
    domain = data.get('domain')
    rrtype = data.get('type', 'A')

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    try:
        collector = DnssecChainCollector(timeoutSeconds=4.0)
        trace = collector.inspectDomain(domain, rrtype)
        
        # Convertim obiectul Trace în JSON
        return jsonify(asdict(trace))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print(" DNSSEC API Server running on port 5000...")
    app.run(debug=True, port=5000)
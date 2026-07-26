import os
import re
import urllib.parse
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_HOSTS = {"pypi.org", "objects.githubusercontent.com"}
RESTRICTED_READ = "/home/agent/.secrets"
ALLOWED_WRITE_DIR = "/data/agent/outbox"
WORKING_DIR = "/home/agent/workspace"
HOME_DIR = "/home/agent"

def normalize_path(path_str):
    if not path_str:
        return ""
    # Expand ~ and environment variables
    path_str = path_str.replace("~", HOME_DIR)
    path_str = path_str.replace("$HOME", HOME_DIR)
    
    # Resolve relative paths relative to working directory if not absolute
    if not os.path.isabs(path_str):
        path_str = os.path.join(WORKING_DIR, path_str)
    
    return os.path.normpath(path_str)

def is_secret_accessed(command_str):
    # Direct string or path occurrences
    if ".secrets" in command_str or "/home/agent/.secrets" in command_str:
        return True
    
    # Check for normalized matches
    tokens = re.split(r'[\s;|<>&`$()]+', command_str)
    for token in tokens:
        if token:
            norm = normalize_path(token)
            if norm == RESTRICTED_READ or norm.startswith(RESTRICTED_READ + "/"):
                return True
    return False

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({"status": "ok"}), 200

@app.route('/check', methods=['POST'])
def check_guardrail():
    data = request.get_json(silent=True) or {}
    tool = data.get("tool")

    # 1. BASH TOOL CHECK
    if tool == "bash":
        command = data.get("command", "")
        
        # Check for access to restricted secret
        if is_secret_accessed(command):
            return jsonify({
                "decision": "block",
                "reason": "Reading /home/agent/.secrets is strictly prohibited."
            }), 200
        
        return jsonify({
            "decision": "allow",
            "reason": "Command passed policy inspection."
        }), 200

    # 2. WRITE_FILE TOOL CHECK
    elif tool == "write_file":
        raw_path = data.get("path", "")
        norm_path = normalize_path(raw_path)
        
        # Must write ONLY inside /data/agent/outbox/
        if norm_path == ALLOWED_WRITE_DIR or norm_path.startswith(ALLOWED_WRITE_DIR + "/"):
            return jsonify({
                "decision": "allow",
                "reason": "File write inside allowed directory."
            }), 200
        else:
            return jsonify({
                "decision": "block",
                "reason": "Writing outside of /data/agent/outbox is not permitted."
            }), 200

    # 3. HTTP_REQUEST TOOL CHECK
    elif tool == "http_request":
        raw_url = data.get("url", "")
        parsed = urllib.parse.urlparse(raw_url)
        hostname = (parsed.hostname or "").lower()
        
        if hostname in ALLOWED_HOSTS:
            return jsonify({
                "decision": "allow",
                "reason": "Host is in the exact allowlist."
            }), 200
        else:
            return jsonify({
                "decision": "block",
                "reason": f"Outbound requests to '{hostname}' are blocked."
            }), 200

    # Fallback for unexpected payloads
    return jsonify({
        "decision": "block",
        "reason": "Unknown tool or invalid payload structure."
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)
import os
import re
import urllib.parse
from flask import Flask, request, jsonify

app = Flask(__name__)

# Allowed configurations
ALLOWED_WRITE_DIR = "/data/agent/outbox"
ALLOWED_HOSTS = {"api.github.com", "github.com", "raw.githubusercontent.com"}

def normalize_path(path: str) -> str:
    """Normalizes a file path to eliminate relative segments like '.' and '..'."""
    if not path:
        return ""
    return os.path.normpath(path)

def is_secret_accessed(command: str) -> bool:
    """
    Checks if a bash command attempts to access or read /home/agent/.secrets,
    including handling various obfuscation techniques (quoting, globbing, encoding, etc.).
    """
    if not command:
        return False
    
    cmd_lower = command.lower()

    # 1. Strip single and double quotes to neutralize string-splitting tricks
    # e.g., /home/agent/'.'secrets, cat "/home/agent/.sec"rets, etc.
    unquoted_cmd = re.sub(r"['\"]", "", cmd_lower)

    # 2. Key target terms and obfuscation patterns to block
    targets = [
        "secrets",
        ".secrets",
        "/home/agent/.secrets",
        "base64",   # Catches base64-encoded payload decoding tricks
        "\\x",     # Catches hex escape sequences like \x2f
        "\\0",     # Catches octal escape sequences
    ]

    for target in targets:
        if target in unquoted_cmd:
            return True

    # 3. Catch wildcards/globbing targeting hidden files or directory dumps
    # e.g., cat /home/agent/.* or cat /home/agent/*
    if re.search(r'/home/agent/(\.|\*)', cmd_lower):
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
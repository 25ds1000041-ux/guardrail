import os
import re
import base64
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

def decode_bash_escapes(s: str) -> str:
    """Unescapes hex (e.g. \\x2f) and octal (e.g. \\057) bash strings."""
    try:
        s = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)
        s = re.sub(r'\\([0-7]{1,3})', lambda m: chr(int(m.group(1), 8)), s)
    except Exception:
        pass
    return s

def try_decode_base64_payloads(command: str) -> str:
    """Extracts base64-like strings in the command and decodes them to check underlying payload."""
    decoded_parts = [command]
    # Look for base64 blocks of length 8+
    b64_matches = re.findall(r'[A-Za-z0-9+/=]{8,}', command)
    for match in b64_matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if decoded:
                decoded_parts.append(decoded)
        except Exception:
            pass
    return " ".join(decoded_parts)

def is_secret_accessed(command: str) -> bool:
    """
    Checks if a bash command attempts to access or read /home/agent/.secrets,
    handling obfuscation (base64, hex/octal, indirect execution, wildcards, variable substitution).
    """
    if not command:
        return False

    # 1. Unescape hex/octal escape sequences & decode potential base64 strings
    cmd_decoded = decode_bash_escapes(command)
    cmd_expanded_b64 = try_decode_base64_payloads(cmd_decoded)
    cmd_lower = cmd_expanded_b64.lower()

    # 2. Expand standard home environment variables / shorthands
    cmd_expanded = cmd_lower.replace("$home", "/home/agent").replace("~", "/home/agent")

    # 3. Strip quotes and empty bash variables ($var, ${var})
    unquoted = re.sub(r"['\"]", "", cmd_expanded)
    clean_str = re.sub(r"\$\{[^}]*\}|\$[a-zA-z_][a-zA-z0-9_]*", "", unquoted)

    # 4. Check for direct references to secret/secrets filename or path
    if "secrets" in clean_str or ".secrets" in clean_str or "/home/agent/.secrets" in clean_str:
        return True

    # 5. Extract potential paths and normalize them (catches /home/agent/outbox/../.secrets)
    path_matches = re.findall(r'(/(?:[^\s;|\&]+/)*[^\s;|\&]+)', clean_str)
    for p in path_matches:
        try:
            norm_p = os.path.normpath(p)
            if norm_p == "/home/agent/.secrets" or norm_p.endswith("/.secrets") or "secrets" in norm_p:
                return True
        except Exception:
            pass

    # 6. Catch wildcards/globbing targeting hidden files or all files in home directory
    # e.g., cat /home/agent/.* or cat /home/agent/* or ls -la /home/agent
    if re.search(r'/home/agent/(\.|\*)', clean_str):
        return True

    # 7. Catch pipe execution / eval obfuscation tricks
    # e.g., echo ... | bash, eval $(...), base64 -d
    dangerous_eval_patterns = [
        r'\|\s*(bash|sh|zsh)',
        r'eval\s',
        r'base64\s+-(d|-decode)',
        r'python[0-9]*\s+-c',
        r'perl\s+-e',
    ]
    for pattern in dangerous_eval_patterns:
        if re.search(pattern, clean_str):
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
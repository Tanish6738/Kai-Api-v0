from flask import Flask, request, jsonify
import tempfile
import subprocess
import os
import re
import shutil
import stat
from functools import wraps
import time

app = Flask(__name__)

# Define regex patterns for API keys (copied from Kai.py)
key_patterns = {
    "AWS": r"AKIA[0-9A-Z]{16}",
    "Google": r"AIza[0-9A-Za-z-_]{35}",
    "Slack": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Stripe": r"sk_live_[0-9a-zA-Z]{24}",
    "SendGrid": r"SG\.[A-Za-z0-9-_]{22}\.[A-Za-z0-9-_]{43}",
    "Twilio": r"SK[0-9a-fA-F]{32}",
    "GitHub": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "OpenAI": r"sk-[a-zA-Z0-9]{48}",
    "Heroku": r"[hH]eroku[a-z0-9]{32}",
    "Mailgun": r"key-[0-9a-zA-Z]{32}",
    "Firebase": r"AAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "DigitalOcean": r"dop_v1_[a-f0-9]{64}",
    "Cloudflare": r"(cf-[a-z0-9]{32}|Bearer [a-zA-Z0-9_-]{40,60})",
    "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Facebook": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Azure Storage": r"DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]+",
    "Dropbox": r"sl\.[A-Za-z0-9-_]{20,}",
    "Notion": r"secret_[a-zA-Z0-9]{43}",
    "Netlify": r"Bearer [a-zA-Z0-9_-]{40,60}",
    "Terraform": r"tfr_[A-Za-z0-9]{32}",
    "CircleCI": r"circle-token [a-f0-9]{40}",
    "BasicAuth": r"https?:\/\/[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@",
    "Generic Base64": r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])",
}

# Define sensitive filenames that shouldn't be committed
sensitive_filenames = [
    ".env", ".env.local", ".env.production", ".env.dev", ".env.test",
    "credentials.json", "firebase.json", ".aws/credentials", ".npmrc", ".dockercfg",
    "id_rsa", "id_rsa.pub", ".pypirc"
]

def cleanup_temp_dir(func):
    """Decorator to ensure temporary directories are cleaned up"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        temp_dirs = []
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            # Clean up any temp directories created during the request
            for temp_dir in getattr(wrapper, 'temp_dirs', []):
                try:
                    if os.path.exists(temp_dir):
                        force_remove_dir(temp_dir)
                except:
                    pass
    return wrapper
 
def force_remove_dir(path):
    """Force remove directory on Windows by handling read-only files"""
    def handle_remove_readonly(func, path, exc):
        """Error handler for removing read-only files on Windows"""
        if os.path.exists(path):
            os.chmod(path, stat.S_IWRITE)
            func(path)
    
    if os.path.exists(path):
        shutil.rmtree(path, onerror=handle_remove_readonly)

def clone_repo(repo_url):
    """Clone a repository to a temporary directory"""
    temp_dir = tempfile.mkdtemp()
    try:
        result = subprocess.run(
            ["git", "clone", repo_url, temp_dir], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.PIPE,
            timeout=60  # 60 second timeout
        )
        if result.returncode != 0:
            raise Exception(f"Failed to clone repository: {result.stderr.decode()}")
        return temp_dir
    except subprocess.TimeoutExpired:
        if os.path.exists(temp_dir):
            force_remove_dir(temp_dir)
        raise Exception("Repository cloning timed out")
    except Exception as e:
        if os.path.exists(temp_dir):
            force_remove_dir(temp_dir)
        raise e

def scan_file(file_path, seen_matches):
    """Scan a single file for API keys and sensitive patterns"""
    matches = []
    try:
        # Skip binary files and very large files
        if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10MB limit
            return matches
            
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
            for key_type, pattern in key_patterns.items():
                for match in re.findall(pattern, content):
                    key = (key_type, match)
                    if key not in seen_matches:
                        seen_matches.add(key)
                        matches.append({
                            "file": file_path, 
                            "type": key_type, 
                            "match": match[:50] + "..." if len(match) > 50 else match  # Truncate long matches
                        })
    except Exception as e:
        # Log error but continue scanning
        pass
    return matches

def scan_repo(path):
    """Scan a repository for API keys and sensitive files"""
    leaks = []
    seen_matches = set()
    file_count = 0
    max_files = 1000  # Limit number of files to scan
    
    for root, _, files in os.walk(path):
        for file in files:
            if file_count >= max_files:
                break
                
            full_path = os.path.join(root, file)
            
            # Skip certain directories and file types
            if any(skip_dir in full_path for skip_dir in ['.git', 'node_modules', '__pycache__', '.pytest_cache']):
                continue
                
            file_count += 1
            leaks.extend(scan_file(full_path, seen_matches))
            
            # Check for sensitive filenames
            for sensitive_file in sensitive_filenames:
                if file.endswith(sensitive_file) or sensitive_file in full_path:
                    key = ("Sensitive File", sensitive_file)
                    if key not in seen_matches:
                        seen_matches.add(key)
                        leaks.append({
                            "file": full_path, 
                            "type": "Sensitive File", 
                            "match": sensitive_file
                        })
                        
        if file_count >= max_files:
            break
            
    return leaks, file_count

@app.route("/", methods=["GET"])
def home():
    """API documentation endpoint"""
    return jsonify({
        "service": "Kai API",
        "version": "1.0.0",
        "description": "API to scan repositories for API key leaks and sensitive files",
        "endpoints": {
            "/scan": {
                "method": "POST",
                "description": "Scan a repository for secrets using JSON payload",
                "parameters": {
                    "repo": "GitHub repository URL (required)",
                },
                "example": {
                    "repo": "https://github.com/username/repo.git"
                }
            },
            "/scan/<username>/<repo_name>": {
                "method": "GET",
                "description": "Scan a repository for secrets using URL parameters",
                "parameters": {
                    "username": "GitHub username (URL parameter)",
                    "repo_name": "Repository name (URL parameter)"
                },
                "example": "GET /scan/octocat/Hello-World"
            },
            "/health": {
                "method": "GET",
                "description": "Health check endpoint"
            }
        }
    })

@app.route("/scan", methods=["POST"])
@cleanup_temp_dir
def scan():
    """Main scanning endpoint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        repo_url = data.get("repo")
        local_path = data.get("local")

        if not repo_url and not local_path:
            return jsonify({
                "error": "Either 'repo' URL must be provided",
                "example": {"repo": "https://github.com/username/repo.git"}
            }), 400

        # For hosted deployment, we only support repo scanning for security
        if local_path:
            return jsonify({
                "error": "Local path scanning is not supported in hosted version for security reasons"
            }), 400

        if not repo_url:
            return jsonify({"error": "Repository URL is required"}), 400

        # Validate GitHub URL format
        if not (repo_url.startswith("https://github.com/") or repo_url.startswith("git@github.com:")):
            return jsonify({"error": "Only GitHub repositories are supported"}), 400

        return perform_scan(repo_url)

    except Exception as e:
        return jsonify({
            "error": f"Request processing failed: {str(e)}"
        }), 500

@app.route("/scan/<username>/<repo_name>", methods=["GET"])
@cleanup_temp_dir
def scan_repo_get(username, repo_name):
    """GET endpoint to scan repository using URL parameters"""
    try:
        # Construct GitHub repository URL
        repo_url = f"https://github.com/{username}/{repo_name}.git"
        return perform_scan(repo_url)
    
    except Exception as e:
        return jsonify({
            "error": f"Request processing failed: {str(e)}"
        }), 500

def perform_scan(repo_url):
    """Common function to perform repository scanning"""
    try:
        start_time = time.time()
          
        # Clone repository
        try:
            path = clone_repo(repo_url)
        except Exception as e:
            return jsonify({
                "error": f"Failed to clone repository: {str(e)}"
            }), 400
            
        # Scan repository
        try:
            leaks, files_scanned = scan_repo(path)
            scan_time = time.time() - start_time
            
            # Clean up cloned repository
            if os.path.exists(path):
                force_remove_dir(path)

            return jsonify({
                "status": "success",
                "repository": repo_url,
                "scan_duration_seconds": round(scan_time, 2),
                "files_scanned": files_scanned,
                "issues_found": len(leaks),
                "results": leaks[:100]  # Limit results to prevent huge responses
            })
            
        except Exception as e:
            # Clean up on error
            if os.path.exists(path):
                force_remove_dir(path)
            return jsonify({
                "error": f"Scanning failed: {str(e)}"
            }), 500

    except Exception as e:
        return jsonify({
            "error": f"Request processing failed: {str(e)}"
        }), 500

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": time.time()
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Endpoint not found",
        "available_endpoints": ["/", "/scan", "/scan/<username>/<repo_name>", "/health"]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "error": "Internal server error"
    }), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

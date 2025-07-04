from flask import Flask, request, jsonify, send_from_directory, render_template_string
import tempfile
import subprocess
import os
import re
import shutil
import stat
from functools import wraps
import time
import yaml

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
    "id_rsa", "id_rsa.pub", ".pypirc", "openai_api_key", "aws_access_key_id", "aws_secret_access_key",
    "google_api_key", "slack_token", "stripe_secret_key", "twilio_auth_token",
    "docker-compose.yml", "docker-compose.override.yml", "docker-compose.prod.yml", "docker-compose.dev.yml",
    "docker-compose.test.yml", "docker-compose.staging.yml", "docker-compose.local.yml"
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

def scan_file(file_path, seen_matches, custom_patterns=None, exclude_paths=None, file_types=None):
    """Scan a single file for API keys and sensitive patterns"""
    matches = []
    try:
        # Check if file should be excluded
        if exclude_paths:
            for exclude_path in exclude_paths:
                if exclude_path in file_path:
                    return matches
        
        # Check file type filter
        if file_types:
            if not any(file_path.endswith(ext) for ext in file_types):
                return matches
        
        # Skip binary files and very large files
        if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10MB limit
            return matches
            
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
            
            # Use custom patterns if provided, otherwise use default patterns
            patterns_to_use = custom_patterns if custom_patterns else key_patterns
            
            for key_type, pattern in patterns_to_use.items():
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

def scan_repo(path, custom_patterns=None, exclude_paths=None, file_types=None):
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
            skip_dirs = ['.git', 'node_modules', '__pycache__', '.pytest_cache']
            if exclude_paths:
                skip_dirs.extend(exclude_paths)
                
            if any(skip_dir in full_path for skip_dir in skip_dirs):
                continue
                
            file_count += 1
            leaks.extend(scan_file(full_path, seen_matches, custom_patterns, exclude_paths, file_types))
            
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
    """Serve the landing page"""
    try:
        static_path = os.path.join(os.path.dirname(__file__), 'static')
        return send_from_directory(static_path, 'index.html')
    except Exception as e:
        return jsonify({"error": f"Failed to load landing page: {str(e)}"}), 500

@app.route("/api-docs", methods=["GET"])
def api_documentation():
    """API documentation endpoint"""
    return jsonify({
        "service": "Kai API",
        "version": "1.0.0",
        "description": "API to scan repositories for API key leaks and sensitive files",
        "endpoints": {
            "/health": {
                "method": "GET",
                "description": "Health check to ensure the service is alive"
            },
            "/scan": {
                "method": "POST",
                "description": "Scan a single repository for secrets",
                "parameters": {
                    "repo": "GitHub repository URL (required)"
                },
                "example": {
                    "repo": "https://github.com/username/repo.git"
                }
            },
            "/scan/bulk": {
                "method": "POST",
                "description": "Scan multiple repositories in one request",
                "parameters": {
                    "repos": "Array of GitHub repository URLs"
                },
                "example": {
                    "repos": [
                        "https://github.com/org1/service-a.git",
                        "https://github.com/org2/service-b.git"
                    ]
                }
            },
            "/scan/<username>/<repo_name>": {
                "method": "GET",
                "description": "Shortcut for scanning public GitHub repos using URL parameters",
                "example": "GET /scan/octocat/Hello-World"
            },
            "/scan/with-config": {
                "method": "POST",
                "description": "Scan with custom configuration",
                "parameters": {
                    "repo": "Repository URL",
                    "rules": "Custom regex rules (optional)",
                    "exclude_paths": "Folders/files to skip (optional)",
                    "file_types": "File types to scan (optional)"
                }
            },
            "/secrets/types": {
                "method": "GET",
                "description": "Return a list of secret types and patterns"
            },
            "/rules/default": {
                "method": "GET",
                "description": "Return all default built-in rules"
            },
            "/config/rules": {
                "method": "POST",
                "description": "Test custom rules format (validation only)"
            },
            "/example-payloads": {
                "method": "GET",
                "description": "Return sample payloads for testing (dev only)"
            },
            "/docs": {
                "method": "GET", 
                "description": "Interactive Swagger UI documentation"
            },
            "/api-docs": {
                "method": "GET",
                "description": "JSON API documentation"
            },
            "/openapi.json": {
                "method": "GET",
                "description": "OpenAPI specification in JSON format"
            },
            "/openapi.yaml": {
                "method": "GET", 
                "description": "OpenAPI specification in YAML format"
            }
        }
    })

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": time.time(),
        "service": "Kai API",
        "version": "1.0.0"
    })

@app.route("/secrets/types", methods=["GET"])
def get_secret_types():
    """Return a static list of secret types and patterns"""
    return jsonify({
        "types": list(key_patterns.keys()),
        "count": len(key_patterns),
        "categories": {
            "cloud_providers": ["AWS", "Google", "Azure Storage", "DigitalOcean", "Cloudflare"],
            "communication": ["Slack", "Twilio", "SendGrid", "Mailgun"],
            "development": ["GitHub", "Heroku", "CircleCI", "Terraform", "Netlify"],
            "payments": ["Stripe"],
            "databases": ["Firebase"],
            "storage": ["Dropbox"],
            "productivity": ["Notion"],
            "ai_services": ["OpenAI"],
            "authentication": ["JWT", "BasicAuth"],
            "keys": ["RSA Private Key"],
            "generic": ["Generic Base64"]
        }
    })

@app.route("/rules/default", methods=["GET"])
def get_default_rules():
    """Return all default built-in rules for client-side visibility"""
    rules = []
    descriptions = {
        "AWS": "Amazon Web Services Access Key",
        "Google": "Google API Key",
        "Slack": "Slack API Token",
        "Stripe": "Stripe Live Secret Key",
        "SendGrid": "SendGrid API Key",
        "Twilio": "Twilio API Key",
        "GitHub": "GitHub Personal Access Token",
        "OpenAI": "OpenAI API Key",
        "Heroku": "Heroku API Key",
        "Mailgun": "Mailgun API Key",
        "Firebase": "Firebase Private Key",
        "DigitalOcean": "DigitalOcean Personal Access Token",
        "Cloudflare": "Cloudflare API Token",
        "JWT": "JSON Web Token",
        "RSA Private Key": "RSA Private Key",
        "Facebook": "Facebook Access Token",
        "Azure Storage": "Azure Storage Connection String",
        "Dropbox": "Dropbox API Token",
        "Notion": "Notion API Key",
        "Netlify": "Netlify Access Token",
        "Terraform": "Terraform Cloud/Enterprise Token",
        "CircleCI": "CircleCI Personal API Token",
        "BasicAuth": "Basic Authentication in URL",
        "Generic Base64": "Generic Base64 Encoded String"
    }
    
    for name, pattern in key_patterns.items():
        rules.append({
            "name": name,
            "pattern": pattern,
            "description": descriptions.get(name, f"{name} pattern")
        })
    
    return jsonify({
        "rules": rules,
        "count": len(rules)
    })

@app.route("/config/rules", methods=["POST"])
def validate_custom_rules():
    """Accepts custom rules for validation (not stored server-side)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            return jsonify({"error": "Rules must be an array"}), 400
            
        validated_rules = []
        for rule in rules:
            if not isinstance(rule, dict):
                return jsonify({"error": "Each rule must be an object"}), 400
                
            name = rule.get("name")
            pattern = rule.get("pattern")
            description = rule.get("description", "")
            
            if not name or not pattern:
                return jsonify({"error": "Each rule must have 'name' and 'pattern' fields"}), 400
                
            # Validate regex pattern
            try:
                re.compile(pattern)
            except re.error as e:
                return jsonify({"error": f"Invalid regex pattern in rule '{name}': {str(e)}"}), 400
                
            validated_rules.append({
                "name": name,
                "pattern": pattern,
                "description": description,
                "status": "valid"
            })
            
        return jsonify({
            "status": "success",
            "message": "All rules are valid",
            "validated_rules": validated_rules,
            "count": len(validated_rules)
        })
        
    except Exception as e:
        return jsonify({
            "error": f"Rule validation failed: {str(e)}"
        }), 500

@app.route("/example-payloads", methods=["GET"])
def get_example_payloads():
    """Return sample payloads for testing (dev only)"""
    return jsonify({
        "description": "Sample payloads for testing the Kai API endpoints",
        "payloads": {
            "scan_single_repo": {
                "endpoint": "POST /scan",
                "payload": {
                    "repo": "https://github.com/octocat/Hello-World.git"
                }
            },
            "scan_bulk_repos": {
                "endpoint": "POST /scan/bulk",
                "payload": {
                    "repos": [
                        "https://github.com/octocat/Hello-World.git",
                        "https://github.com/octocat/Spoon-Knife.git"
                    ]
                }
            },
            "scan_with_config": {
                "endpoint": "POST /scan/with-config",
                "payload": {
                    "repo": "https://github.com/octocat/Hello-World.git",
                    "rules": [
                        {
                            "name": "MY_CUSTOM_API_KEY",
                            "pattern": "my-[a-zA-Z0-9]{32}",
                            "description": "Custom internal API key format"
                        }
                    ],
                    "exclude_paths": ["test/", "docs/"],
                    "file_types": [".env", ".yml", ".json"]
                }
            },
            "custom_rules_validation": {
                "endpoint": "POST /config/rules",
                "payload": {
                    "rules": [
                        {
                            "name": "CUSTOM_TOKEN",
                            "pattern": "ct_[A-Za-z0-9]{40}",
                            "description": "Custom token format"
                        }
                    ]
                }
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

@app.route("/scan/bulk", methods=["POST"])
@cleanup_temp_dir
def scan_bulk():
    """Scan multiple repositories in one request"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        repos = data.get("repos", [])
        if not repos or not isinstance(repos, list):
            return jsonify({
                "error": "Field 'repos' must be a non-empty array",
                "example": {
                    "repos": [
                        "https://github.com/org1/service-a.git",
                        "https://github.com/org2/service-b.git"
                    ]
                }
            }), 400

        if len(repos) > 10:  # Limit bulk scanning
            return jsonify({"error": "Maximum 10 repositories allowed per bulk scan"}), 400

        start_time = time.time()
        results = []
        
        for repo_url in repos:
            # Validate GitHub URL format
            if not (repo_url.startswith("https://github.com/") or repo_url.startswith("git@github.com:")):
                results.append({
                    "repository": repo_url,
                    "status": "error",
                    "error": "Only GitHub repositories are supported"
                })
                continue
                
            try:
                # Clone repository
                path = clone_repo(repo_url)
                
                # Scan repository
                leaks, files_scanned = scan_repo(path)
                
                # Clean up cloned repository
                if os.path.exists(path):
                    force_remove_dir(path)
                
                results.append({
                    "repository": repo_url,
                    "status": "success",
                    "files_scanned": files_scanned,
                    "issues_found": len(leaks),
                    "results": leaks[:50]  # Limit results per repo
                })
                
            except Exception as e:
                results.append({
                    "repository": repo_url,
                    "status": "error",
                    "error": str(e)
                })

        total_time = time.time() - start_time
        successful_scans = sum(1 for r in results if r["status"] == "success")
        total_issues = sum(r.get("issues_found", 0) for r in results if r["status"] == "success")

        return jsonify({
            "status": "completed",
            "scan_duration_seconds": round(total_time, 2),
            "repositories_requested": len(repos),
            "repositories_scanned": successful_scans,
            "total_issues_found": total_issues,
            "results": results
        })

    except Exception as e:
        return jsonify({
            "error": f"Bulk scan failed: {str(e)}"
        }), 500

@app.route("/scan/with-config", methods=["POST"])
@cleanup_temp_dir
def scan_with_config():
    """Scan repository with custom configuration"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        repo_url = data.get("repo")
        if not repo_url:
            return jsonify({"error": "Repository URL is required"}), 400

        # Validate GitHub URL format
        if not (repo_url.startswith("https://github.com/") or repo_url.startswith("git@github.com:")):
            return jsonify({"error": "Only GitHub repositories are supported"}), 400

        # Parse configuration options
        custom_rules = data.get("rules", [])
        exclude_paths = data.get("exclude_paths", [])
        file_types = data.get("file_types", [])
        
        # Validate and process custom rules
        custom_patterns = {}
        if custom_rules:
            for rule in custom_rules:
                if not isinstance(rule, dict):
                    return jsonify({"error": "Each rule must be an object"}), 400
                    
                name = rule.get("name")
                pattern = rule.get("pattern")
                
                if not name or not pattern:
                    return jsonify({"error": "Each rule must have 'name' and 'pattern' fields"}), 400
                    
                # Validate regex pattern
                try:
                    re.compile(pattern)
                    custom_patterns[name] = pattern
                except re.error as e:
                    return jsonify({"error": f"Invalid regex pattern in rule '{name}': {str(e)}"}), 400

        # Merge custom patterns with default ones
        patterns_to_use = key_patterns.copy()
        patterns_to_use.update(custom_patterns)

        return perform_scan_with_config(repo_url, patterns_to_use, exclude_paths, file_types, custom_rules)

    except Exception as e:
        return jsonify({
            "error": f"Configured scan failed: {str(e)}"
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

def perform_scan(repo_url, custom_patterns=None, exclude_paths=None, file_types=None):
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
            leaks, files_scanned = scan_repo(path, custom_patterns, exclude_paths, file_types)
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

def perform_scan_with_config(repo_url, patterns_to_use, exclude_paths, file_types, custom_rules):
    """Perform repository scanning with custom configuration"""
    try:
        start_time = time.time()
          
        # Clone repository
        try:
            path = clone_repo(repo_url)
        except Exception as e:
            return jsonify({
                "error": f"Failed to clone repository: {str(e)}"
            }), 400
            
        # Scan repository with custom configuration
        try:
            leaks, files_scanned = scan_repo(path, patterns_to_use, exclude_paths, file_types)
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
                "configuration": {
                    "custom_rules_applied": len(custom_rules) if custom_rules else 0,
                    "exclude_paths": exclude_paths if exclude_paths else [],
                    "file_types_filter": file_types if file_types else [],
                    "total_patterns": len(patterns_to_use)
                },
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

@app.route("/docs", methods=["GET"])
def swagger_ui():
    """Serve Swagger UI for interactive API documentation"""
    swagger_ui_html = """
    <!DOCTYPE html>
    <html>
      <head>
        <title>Kai API Documentation</title>
        <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui.css" />
        <style>
          html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
          }
          *, *:before, *:after {
            box-sizing: inherit;
          }
          body {
            margin:0;
            background: #fafafa;
          }
        </style>
      </head>
      <body>
        <div id="swagger-ui"></div>
        <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-bundle.js"></script>
        <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-standalone-preset.js"></script>
        <script>
          window.onload = function() {
            const ui = SwaggerUIBundle({
              url: '/openapi.json',
              dom_id: '#swagger-ui',
              deepLinking: true,
              presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIStandalonePreset
              ],
              plugins: [
                SwaggerUIBundle.plugins.DownloadUrl
              ],
              layout: "StandaloneLayout"
            })
          }
        </script>
      </body>
    </html>
    """
    return swagger_ui_html

@app.route("/openapi.json", methods=["GET"])
def openapi_json():
    """Serve OpenAPI specification in JSON format"""
    try:
        # Read the YAML file and convert to JSON
        yaml_path = os.path.join(os.path.dirname(__file__), 'openapi.yaml')
        with open(yaml_path, 'r', encoding='utf-8') as file:
            openapi_spec = yaml.safe_load(file)
        
        # Update the server URL dynamically
        server_url = request.url_root.rstrip('/')
        openapi_spec['servers'] = [
            {
                "url": server_url,
                "description": "Current server"
            },
            {
                "url": "http://localhost:5000",
                "description": "Development server"
            }
        ]
        
        return jsonify(openapi_spec)
    except Exception as e:
        return jsonify({"error": f"Failed to load OpenAPI specification: {str(e)}"}), 500

@app.route("/openapi.yaml", methods=["GET"])
def openapi_yaml():
    """Serve OpenAPI specification in YAML format"""
    try:
        yaml_path = os.path.join(os.path.dirname(__file__), 'openapi.yaml')
        with open(yaml_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Update server URL in YAML content
        server_url = request.url_root.rstrip('/')
        updated_content = content.replace(
            'servers:\n  - url: http://localhost:5000',
            f'servers:\n  - url: {server_url}\n    description: Current server\n  - url: http://localhost:5000'
        )
        
        from flask import Response
        return Response(updated_content, mimetype='text/yaml')
    except Exception as e:
        return jsonify({"error": f"Failed to load OpenAPI specification: {str(e)}"}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Endpoint not found",
        "available_endpoints": [
            "/", "/health", "/scan", "/scan/bulk", "/scan/<username>/<repo_name>", 
            "/scan/with-config", "/secrets/types", "/rules/default", 
            "/config/rules", "/example-payloads", "/docs", "/api-docs", "/openapi.json", "/openapi.yaml"
        ]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "error": "Internal server error"
    }), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

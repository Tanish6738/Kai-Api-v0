# Kai API - Secret Scanner 🔐

A comprehensive API service for scanning GitHub repositories to detect API keys, secrets, and sensitive files.

## 🚀 Features

- **Single Repository Scanning**: Scan individual GitHub repositories
- **Bulk Scanning**: Scan up to 10 repositories in one request
- **Custom Rules**: Define your own regex patterns for detection
- **File Filtering**: Include/exclude specific file types and paths
- **24+ Secret Types**: Detect AWS keys, Google API keys, Slack tokens, and more
- **Real-time Processing**: No data storage, immediate results
- **Interactive Documentation**: Built-in Swagger UI

## 📚 API Documentation

### Interactive Documentation
Visit the Swagger UI for interactive API exploration:
```
GET /docs
```

### OpenAPI Specifications
- **JSON Format**: `GET /openapi.json`
- **YAML Format**: `GET /openapi.yaml`

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.7+
- Git (for repository cloning)

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run the Application
```bash
python app.py
```

The API will be available at `http://localhost:5000`

## 🔍 Quick Start Examples

### 1. Health Check
```bash
curl -X GET "http://localhost:5000/health"
```

### 2. Scan a Single Repository
```bash
curl -X POST "http://localhost:5000/scan" \
  -H "Content-Type: application/json" \
  -d '{"repo": "https://github.com/octocat/Hello-World.git"}'
```

### 3. Scan Multiple Repositories
```bash
curl -X POST "http://localhost:5000/scan/bulk" \
  -H "Content-Type: application/json" \
  -d '{
    "repos": [
      "https://github.com/octocat/Hello-World.git",
      "https://github.com/octocat/Spoon-Knife.git"
    ]
  }'
```

### 4. Scan with Custom Configuration
```bash
curl -X POST "http://localhost:5000/scan/with-config" \
  -H "Content-Type: application/json" \
  -d '{
    "repo": "https://github.com/octocat/Hello-World.git",
    "rules": [
      {
        "name": "CUSTOM_API_KEY",
        "pattern": "custom-[a-zA-Z0-9]{32}",
        "description": "Custom API key format"
      }
    ],
    "exclude_paths": ["test/", "docs/"],
    "file_types": [".env", ".yml", ".json"]
  }'
```

### 5. Quick Repository Scan (URL Parameters)
```bash
curl -X GET "http://localhost:5000/scan/octocat/Hello-World"
```

## 📋 Available Endpoints

| Endpoint | Method | Description |
|----------|---------|-------------|
| `/` | GET | API documentation |
| `/health` | GET | Health check |
| `/docs` | GET | Interactive Swagger UI |
| `/openapi.json` | GET | OpenAPI spec (JSON) |
| `/openapi.yaml` | GET | OpenAPI spec (YAML) |
| `/scan` | POST | Scan single repository |
| `/scan/bulk` | POST | Scan multiple repositories |
| `/scan/with-config` | POST | Scan with custom configuration |
| `/scan/{username}/{repo}` | GET | Quick scan by URL parameters |
| `/secrets/types` | GET | List supported secret types |
| `/rules/default` | GET | Get default detection rules |
| `/config/rules` | POST | Validate custom rules |
| `/example-payloads` | GET | Sample request payloads |
  - Stripe Keys
  - OpenAI Keys
  - JWT Tokens
  - RSA Private Keys
  - And many more...

- **Sensitive File Detection**: Identifies potentially dangerous files like:
  - Environment files (`.env`, `.env.local`, etc.)
  - Credential files (`credentials.json`, `firebase.json`)
  - SSH keys (`id_rsa`, `id_rsa.pub`)
  - Configuration files (`.npmrc`, `.dockercfg`)

- **Multiple Scanning Modes**:
  - Repository URL scanning (POST endpoint)
  - Direct GitHub repo scanning (GET endpoint)
  - Local file scanning (CLI tool)

- **Performance Optimized**:
  - 10MB file size limit to prevent memory issues
  - 1000 file scan limit per repository
  - Timeout protection for long-running operations
  - Efficient pattern matching with regex

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- Git (for repository cloning)
- Flask web framework

### Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/KeySentry.git
cd KeySentry
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables (create `.env` file):
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Run the application:
```bash
python app.py
```

The API will be available at `http://localhost:5000`

## 📚 API Documentation

### Base URL
- Development: `http://localhost:5000`
- Production: `https://your-deployed-app.render.com`

### Endpoints

#### 1. Home/Documentation
```http
GET /
```

Returns API documentation and available endpoints.

**Response:**
```json
{
  "service": "Kai API",
  "version": "1.0.0",
  "description": "API to scan repositories for API key leaks and sensitive files",
  "endpoints": {
    "/scan": { ... },
    "/scan/<username>/<repo_name>": { ... },
    "/health": { ... }
  }
}
```

#### 2. Scan Repository (POST)
```http
POST /scan
Content-Type: application/json
```

**Request Body:**
```json
{
  "repo": "https://github.com/username/repository.git"
}
```

**Response:**
```json
{
  "status": "success",
  "repository": "https://github.com/username/repository.git",
  "scan_duration_seconds": 2.45,
  "files_scanned": 156,
  "issues_found": 3,
  "results": [
    {
      "file": "/path/to/file.js",
      "type": "OpenAI",
      "match": "sk-abcdef1234567890..."
    },
    {
      "file": "/path/to/.env",
      "type": "Sensitive File",
      "match": ".env"
    }
  ]
}
```

#### 3. Scan Repository (GET)
```http
GET /scan/{username}/{repo_name}
```

**Parameters:**
- `username`: GitHub username
- `repo_name`: Repository name

**Example:**
```http
GET /scan/octocat/Hello-World
```

**Response:** Same format as POST endpoint

#### 4. Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1640995200.0
}
```

### Error Responses

#### 400 Bad Request
```json
{
  "error": "Repository URL is required",
  "example": {
    "repo": "https://github.com/username/repo.git"
  }
}
```

#### 404 Not Found
```json
{
  "error": "Endpoint not found",
  "available_endpoints": ["/", "/scan", "/scan/<username>/<repo_name>", "/health"]
}
```

#### 500 Internal Server Error
```json
{
  "error": "Internal server error"
}
```

## 🔧 Usage Examples

### Using cURL

#### Scan a repository:
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo": "https://github.com/username/repo.git"}'
```

#### Quick scan using GET:
```bash
curl http://localhost:5000/scan/username/repo-name
```

#### Health check:
```bash
curl http://localhost:5000/health
```

### Using Python

```python
import requests

# Scan repository
response = requests.post('http://localhost:5000/scan', 
                        json={'repo': 'https://github.com/username/repo.git'})
result = response.json()

print(f"Found {result['issues_found']} issues in {result['files_scanned']} files")
for issue in result['results']:
    print(f"⚠️  {issue['type']}: {issue['match']} in {issue['file']}")
```

### Using JavaScript/Node.js

```javascript
const fetch = require('node-fetch');

async function scanRepository(repoUrl) {
  const response = await fetch('http://localhost:5000/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repo: repoUrl })
  });
  
  const result = await response.json();
  return result;
}

scanRepository('https://github.com/username/repo.git')
  .then(result => console.log(result))
  .catch(error => console.error(error));
```

## 🛠️ Local CLI Usage

For local file scanning, use the `Local.py` script:

```bash
python Local.py --path /path/to/local/repository
# or
python Local.py --repo https://github.com/username/repo.git
```

## 🏗️ Architecture

### Components

1. **Flask Web API** (`app.py`): Main REST API service
2. **Local Scanner** (`Local.py`): Command-line interface for local scanning
3. **Pattern Detection Engine**: Regex-based secret detection
4. **Repository Cloning**: Git-based repository fetching
5. **File System Scanner**: Recursive directory traversal

### Security Features

- Repository cloning timeout protection (60 seconds)
- File size limits (10MB per file)
- Directory traversal protection
- Temporary file cleanup
- GitHub-only repository support for hosted version
- Result limiting (100 issues max per scan)

## 🌐 Deployment

### Render (Recommended)

The application is configured for easy deployment on Render using the included `render.yaml`:

1. Connect your GitHub repository to Render
2. The service will automatically deploy using the configuration in `render.yaml`
3. Environment variables can be set in the Render dashboard

### Manual Deployment

For other platforms:

1. Set up Python environment
2. Install dependencies: `pip install -r requirements.txt`
3. Set environment variables
4. Run: `python app.py`

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `5000` |
| `FLASK_ENV` | Flask environment | `production` |
| `PYTHON_VERSION` | Python version | `3.9` |

## 🔍 Supported Secret Types

KeySentry detects the following types of secrets:

| Service | Pattern Type | Example |
|---------|--------------|---------|
| AWS | Access Key ID | `AKIA1234567890123456` |
| Google | API Key | `AIzaSyABC123...` |
| Slack | Bot Token | `xoxb-1234-5678-...` |
| Stripe | Secret Key | `sk_live_ABC123...` |
| SendGrid | API Key | `SG.ABC123...` |
| Twilio | Account SID | `SK1234567890abcdef...` |
| GitHub | Personal Token | `ghp_ABC123...` |
| OpenAI | API Key | `sk-ABC123...` |
| JWT | JSON Web Token | `eyJhbGciOiJIUzI1NiIs...` |
| RSA | Private Key | `-----BEGIN RSA PRIVATE KEY-----` |
| Firebase | Config | `AAA123...` |
| And more... | | |

## 🚨 Security Considerations

### For API Users
- Never commit real API keys to test repositories
- Regularly rotate exposed secrets
- Use environment variables for sensitive configuration
- Enable secret scanning in your repositories

### For Developers
- The hosted version only accepts GitHub repositories for security
- Local path scanning is disabled in production
- All temporary files are cleaned up after scanning
- Repository cloning has timeout protection

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Commit changes: `git commit -am 'Add new feature'`
4. Push to branch: `git push origin feature/new-feature`
5. Submit a Pull Request

### Adding New Secret Patterns

To add support for new API key types, update the `key_patterns` dictionary in both `app.py` and `Local.py`:

```python
key_patterns["ServiceName"] = r"your-regex-pattern-here"
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Flask web framework
- Regex pattern matching
- Git version control system
- Render hosting platform

## 📞 Support

- Create an issue on GitHub for bugs or feature requests
- Check the API documentation at the root endpoint (`/`)
- Review the health endpoint for service status (`/health`)

---

**⚠️ Disclaimer**: KeySentry is a security tool designed to help identify potential vulnerabilities. Always validate findings and follow security best practices. This tool should be used as part of a comprehensive security strategy, not as the sole security measure.
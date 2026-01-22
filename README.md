# AI-Spotter

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A CLI tool that scans repositories to detect usage of external AI services, LLMs, and AI providers by analyzing code, dependencies, configuration files, and API keys.

## Features

- **Comprehensive Detection**: Identifies AI service usage through:
  - Dependency analysis (requirements.txt, package.json, pyproject.toml, etc.)
  - Code pattern matching (imports, API calls, client instantiation)
  - Configuration file scanning (.env, YAML, JSON, TOML)

- **Multiple Output Formats**: JSON, text, or CSV reports with GitHub hyperlinks

- **Flexible Configuration**: YAML-based service definitions, environment variables

- **Performance Optimized**: Parallel file processing for fast scanning

## Installation

### Option 1: Run Directly (No Installation)

```bash
git clone https://github.com/yourusername/ai-spotter.git
cd ai-spotter
pip install -r requirements.txt

# Run directly
python run.py --help
python run.py --local-path /path/to/repo
```

### Option 2: Install as Package

```bash
git clone https://github.com/yourusername/ai-spotter.git
cd ai-spotter
pip install .

# Use the ai-detector command
ai-detector --help
```

### Option 3: Install in Development Mode

```bash
pip install -e ".[dev]"
```


## Usage

```bash
# If installed as package:
ai-detector --help

# If running directly:
python run.py --help
```

### Scan Local Repository

```bash
ai-detector --local-path /path/to/repo
```

### Scan Remote Repository

```bash
ai-detector --repo-url https://github.com/owner/repo
```

### Scan Private Repository

```bash
ai-detector --repo-url https://github.com/owner/private-repo --github-token YOUR_TOKEN

# Or use environment variable
export GITHUB_TOKEN=your_token
ai-detector --repo-url https://github.com/owner/private-repo
```

### Batch Scanning

```bash
# Create repos.txt with one repo per line:
#   owner/repo
#   https://github.com/owner/other-repo

ai-detector --repo-file repos.txt --output-format csv --output-file results.csv
```

### Output Formats

```bash
# JSON output
ai-detector --local-path /path/to/repo --output-format json

# CSV output  
ai-detector --local-path /path/to/repo --output-format csv

# All formats at once
ai-detector --local-path /path/to/repo --output-format all --output-file report
```

## Command-Line Options

```
Usage: ai-detector [OPTIONS]

Options:
  --repo-url TEXT        Remote Git repository URL
  --repo-file PATH       File with repository names (org/repo per line)
  --local-path PATH      Local repository directory
  --output-format TEXT   Output format: json, text, csv, or all (default: text)
  --output-file PATH     File path to write output
  --github-token TEXT    Token for private repos (or GITHUB_TOKEN env var)
  --verbose, -v          Enable verbose logging
  --max-workers INTEGER  Parallel workers (default: 4)
  --help                 Show this message and exit
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITHUB_TOKEN` | Token for private repository access | - |
| `AI_DETECTOR_MAX_WORKERS` | Number of parallel workers (1-32) | 4 |
| `AI_DETECTOR_MAX_FILE_SIZE_MB` | Max file size to scan in MB (1-100) | 1 |
| `AI_DETECTOR_GIT_CLONE_TIMEOUT` | Git clone timeout in seconds (30-3600) | 300 |
| `AI_DETECTOR_GIT_COMMAND_TIMEOUT` | Git command timeout in seconds (5-120) | 10 |

### Custom AI Services

Add or modify AI services by editing `ai_detector/services.yaml`:

```yaml
services:
  - name: My Custom AI
    package_names:
      - my-ai-sdk
    import_patterns:
      - "from\\s+my_ai\\s+import"
    api_endpoints:
      - api.myai.com
    api_key_patterns:
      - "mai_[a-zA-Z0-9]{32,}"
    config_key_patterns:
      - MY_AI_API_KEY
    model_patterns:
      - "my-model-[\\w-]+"
    client_patterns:
      - "MyAIClient\\s*\\("
```

## Output Example

### Text Report

```
================================================================================
AI SERVICE DETECTION REPORT
================================================================================
Scan Date: 2024-01-15 10:30:00 UTC
Total Detections: 4
Services Found: 2

Summary by Severity:
  WARNING: 1
  INFO: 3

--------------------------------------------------------------------------------
Service: OpenAI
--------------------------------------------------------------------------------

DEPENDENCY Detections:
  File: requirements.txt
    Package 'openai' found in dependencies
    Severity: info

CODE Detections:
  File: src/llm_client.py
    Line 5: from openai import OpenAI
    Severity: info
```

### JSON Output

```json
{
  "scan_timestamp": "2024-01-15T10:30:00",
  "total_detections": 4,
  "services_found": ["OpenAI", "Anthropic"],
  "summary": {
    "by_type": {"dependency": 2, "code": 2},
    "by_severity": {"info": 3, "warning": 1}
  }
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No AI services detected |
| 1 | AI services detected |
| 2 | Error occurred during scanning |
| 130 | Scan interrupted by user (Ctrl+C) |

## Programmatic Usage

```python
from ai_detector import scan_repository

# Basic scan
results = scan_repository(repo_path="/path/to/repo")

for result in results:
    print(f"{result.service_name}: {result.detection_type} - {result.evidence}")

# Check findings by service
openai_usage = [r for r in results if r.service_name == "OpenAI"]
if openai_usage:
    print(f"Found {len(openai_usage)} OpenAI usage instances!")
```


## Limitations

- May produce false positives for example code, comments, or test fixtures
- May miss detections in obfuscated/minified code or indirect dependencies
- Local LLM patterns (Ollama, LocalAI) require explicit context to avoid false positives

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

# Contributing to AI Detector

Thank you for your interest in contributing to AI Detector! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git

### Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/check-ai-usage.git
   cd check-ai-usage
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install development dependencies:**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Run tests to verify setup:**
   ```bash
   pytest
   ```

## Making Changes

### Code Style

We use the following tools to maintain code quality:

- **Black** for code formatting
- **Ruff** for linting
- **MyPy** for type checking

Before submitting a PR, run:

```bash
black ai_detector/
ruff check ai_detector/
mypy ai_detector/
```

### Adding New AI Services

To add support for a new AI service, edit `ai_detector/services.yaml`:

```yaml
- name: New AI Service
  package_names:
    - new-ai-sdk
  import_patterns:
    - 'from\s+new_ai\s+import'
  api_endpoints:
    - api.newai.com
  api_key_patterns:
    - 'nai_[a-zA-Z0-9]{32,}'
  config_key_patterns:
    - NEW_AI_API_KEY
  model_patterns:
    - 'new-model-[\w-]+'
  client_patterns:
    - 'NewAIClient\s*\('
```

### Testing

- Write tests for any new functionality
- Ensure all existing tests pass
- Add test cases for edge cases

Run tests:
```bash
pytest
pytest --cov=ai_detector  # With coverage
```

## Pull Request Process

1. **Fork the repository** and create a feature branch
2. **Make your changes** following the code style guidelines
3. **Write or update tests** as needed
4. **Update documentation** if you're changing behavior
5. **Run the test suite** to ensure nothing is broken
6. **Submit a pull request** with a clear description

### PR Checklist

- [ ] Code follows the project's style guidelines
- [ ] Tests pass locally
- [ ] New functionality includes tests
- [ ] Documentation is updated (if applicable)
- [ ] Commit messages are clear and descriptive

## Reporting Issues

When reporting issues, please include:

1. **Description** of the issue
2. **Steps to reproduce**
3. **Expected behavior**
4. **Actual behavior**
5. **Environment** (Python version, OS, etc.)
6. **Relevant logs or error messages**

## Feature Requests

We welcome feature requests! Please:

1. Check existing issues to avoid duplicates
2. Provide a clear use case
3. Describe the expected behavior

## Questions?

Feel free to open an issue for any questions about contributing.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.


"""Detection modules for identifying AI service usage."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Optional, Pattern, Iterator

from .services import AIServiceRegistry
from .utils import (
    parse_requirements_file, parse_package_json, parse_pyproject_toml,
    get_dependency_files, get_config_files, get_code_file_extensions
)

# Security: Maximum line length to prevent ReDoS attacks on pathological input
MAX_LINE_LENGTH = 10000


def _truncate_for_regex(text: str, max_length: int = MAX_LINE_LENGTH) -> str:
    """Truncate text to prevent ReDoS on pathologically long input."""
    if len(text) > max_length:
        return text[:max_length]
    return text


def safe_regex_search(pattern: Pattern, text: str, max_length: int = MAX_LINE_LENGTH) -> Optional[re.Match]:
    """Safely search for regex pattern with length limits to prevent ReDoS.
    
    Args:
        pattern: Compiled regex pattern.
        text: Text to search in.
        max_length: Maximum text length to process.
        
    Returns:
        Match object if found, None otherwise.
    """
    return pattern.search(_truncate_for_regex(text, max_length))


def safe_regex_finditer(pattern: Pattern, text: str, max_length: int = MAX_LINE_LENGTH) -> Iterator[re.Match]:
    """Safely iterate regex matches with length limits to prevent ReDoS.
    
    Args:
        pattern: Compiled regex pattern.
        text: Text to search in.
        max_length: Maximum text length to process.
        
    Yields:
        Match objects found.
    """
    return pattern.finditer(_truncate_for_regex(text, max_length))


def safe_re_search(pattern: str, text: str, flags: int = 0, max_length: int = MAX_LINE_LENGTH) -> Optional[re.Match]:
    """Safely search with a pattern string (not compiled) with length limits.
    
    Args:
        pattern: Regex pattern string.
        text: Text to search in.
        flags: Regex flags.
        max_length: Maximum text length to process.
        
    Returns:
        Match object if found, None otherwise.
    """
    return re.search(pattern, _truncate_for_regex(text, max_length), flags)


def safe_re_finditer(pattern: str, text: str, flags: int = 0, max_length: int = MAX_LINE_LENGTH) -> Iterator[re.Match]:
    """Safely iterate matches with a pattern string (not compiled) with length limits.
    
    Args:
        pattern: Regex pattern string.
        text: Text to search in.
        flags: Regex flags.
        max_length: Maximum text length to process.
        
    Yields:
        Match objects found.
    """
    return re.finditer(pattern, _truncate_for_regex(text, max_length), flags)


def safe_re_findall(pattern: str, text: str, flags: int = 0, max_length: int = MAX_LINE_LENGTH) -> List[str]:
    """Safely find all matches with a pattern string with length limits.
    
    Args:
        pattern: Regex pattern string.
        text: Text to search in.
        flags: Regex flags.
        max_length: Maximum text length to process.
        
    Returns:
        List of matches found.
    """
    return re.findall(pattern, _truncate_for_regex(text, max_length), flags)


@dataclass
class DetectionResult:
    """Represents a single detection finding."""
    service_name: str
    detection_type: str  # 'dependency', 'code', 'config', 'endpoint'
    file_path: str
    line_number: Optional[int] = None
    evidence: str = ""
    severity: str = "info"  # 'info', 'warning'
    repo_url: Optional[str] = None  # Original repository URL/path for hyperlinks
    relative_file_path: Optional[str] = None  # Relative path from repo root
    default_branch: Optional[str] = None  # Default branch name for hyperlinks
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON output."""
        return {
            'service_name': self.service_name,
            'detection_type': self.detection_type,
            'file_path': self.file_path,
            'relative_file_path': self.relative_file_path,
            'repo_url': self.repo_url,
            'line_number': self.line_number,
            'evidence': self.evidence,
            'severity': self.severity,
        }
    
    def get_hyperlink(self) -> str:
        """Generate hyperlink for the file path."""
        if not self.repo_url:
            return self.file_path
        
        # Extract relative path
        rel_path = self.relative_file_path or self.file_path
        
        # Handle GitHub URLs
        if 'github.com' in self.repo_url:
            # Extract owner/repo from URL
            match = re.search(r'github\.com[:/]([\w\-\.]+)/([\w\-\.]+?)(?:\.git)?(?:\/|$|#|\?|\.)', self.repo_url)
            if match:
                owner = match.group(1)
                repo = match.group(2)
                # Use detected branch or fallback to master
                branch = self.default_branch or 'master'
                line_ref = f"#L{self.line_number}" if self.line_number else ""
                return f"https://github.com/{owner}/{repo}/blob/{branch}/{rel_path}{line_ref}"
        
        # For other Git providers or local paths, return formatted path
        return f"{self.repo_url}/{rel_path}" if self.repo_url else self.file_path


class DependencyDetector:
    """Detects AI services through dependency files."""
    
    def __init__(self, registry: AIServiceRegistry):
        self.registry = registry
        self.all_packages = {pkg.lower() for pkg in registry.get_all_package_names()}
    
    def detect(self, file_path: Path, content: str) -> List[DetectionResult]:
        """Detect AI services in dependency files."""
        results = []
        file_name = file_path.name.lower()
        
        # Parse based on file type
        packages = set()
        if file_name == 'requirements.txt':
            packages = parse_requirements_file(content)
        elif file_name == 'package.json':
            packages = parse_package_json(content)
        elif file_name in ['pyproject.toml', 'poetry.lock']:
            packages = parse_pyproject_toml(content)
        elif file_name == 'pom.xml':
            # Maven - simple regex for artifactId (with safe truncation)
            for match in safe_re_finditer(r'<artifactId>([^<]+)</artifactId>', content, re.IGNORECASE):
                packages.add(match.group(1).lower())
        elif file_name == 'build.gradle':
            # Gradle - look for implementation/compile lines (with safe truncation)
            for match in safe_re_finditer(r'(?:implementation|compile|api)\s+["\']([^"\']+)["\']', content, re.IGNORECASE):
                packages.add(match.group(1).lower())
        elif file_name == 'go.mod':
            # Go modules (with safe truncation)
            for match in safe_re_finditer(r'^\s*([\w\.\-/]+)', content, re.MULTILINE):
                pkg = match.group(1).lower()
                if not pkg.startswith('module') and not pkg.startswith('go '):
                    packages.add(pkg)
        elif file_name == 'Cargo.toml':
            # Rust - parse dependencies section
            deps_section = False
            for line in content.split('\n'):
                if '[dependencies]' in line.lower():
                    deps_section = True
                    continue
                if line.strip().startswith('['):
                    deps_section = False
                    continue
                if deps_section:
                    match = re.match(r'([\w\-_]+)', line)
                    if match:
                        packages.add(match.group(1).lower())
        
        # Match found packages against AI service packages
        for service in self.registry.get_all_services():
            for pkg in packages:
                if pkg in [p.lower() for p in service.package_names]:
                    results.append(DetectionResult(
                        service_name=service.name,
                        detection_type='dependency',
                        file_path=str(file_path),
                        evidence=f"Package '{pkg}' found in dependencies",
                        severity='info'
                    ))
                    break  # Only report once per service per file
        
        return results


class CodePatternDetector:
    """Detects AI services through code patterns."""
    
    def __init__(self, registry: AIServiceRegistry):
        self.registry = registry
    
    def _is_comment_or_string_literal(self, line: str) -> bool:
        """Check if line is a comment or contains only string literals."""
        stripped = line.strip()
        # Skip comments
        if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*'):
            return True
        # Skip shebangs
        if stripped.startswith('#!/'):
            return True
        # Skip lines that are mostly JSON/string content (quoted strings)
        if stripped.startswith('"') and stripped.endswith('"') and len(stripped) > 50:
            return True
        if stripped.startswith("'") and stripped.endswith("'") and len(stripped) > 50:
            return True
        return False
    
    def _is_false_positive_pattern(self, line: str, pattern_match: str) -> bool:
        """Check if a pattern match is likely a false positive."""
        line_lower = line.lower()
        
        # Skip common false positive patterns
        false_positive_indicators = [
            'api/', 'admin/', 'http://', 'https://',  # API endpoints
            'application/', 'content-type',  # HTTP headers
            'true/false', 'n/a', 'none', 'null', 'undefined',  # Common values
            '#!/usr/bin',  # Shebangs
            'merchant/payment', 'payment/',  # Business domain terms
            'timezone(', 'pytz.',  # Timezone libraries
            'f"https://', 'f\'https://',  # F-strings with URLs
        ]
        
        for indicator in false_positive_indicators:
            if indicator in line_lower:
                return True
        
        # Skip if pattern is in a URL path
        if '/api/' in line_lower or '/admin/' in line_lower:
            return True
        
        # Skip if it's just a variable assignment with the pattern
        if '=' in line and pattern_match in line and not any(keyword in line_lower for keyword in ['model', 'client', 'api_key', 'token']):
            # Check if it's likely a model name assignment
            if 'model' in line_lower or 'client' in line_lower:
                return False
            return True
        
        # LangChain-specific false positives
        if 'agent' in pattern_match.lower():
            # Skip if it's not actually a LangChain agent
            if any(false_pos in line_lower for false_pos in [
                'possalesagent', 'possalesagent', 'salesagent', 'ekycagent',
                'parseuseragent', 'useragent', 'switchtopossalesagent',
                'checkifpossalesagent', 'ispossalesagent', 'ispospartnerowneraccount'
            ]):
                return True
        
        # Ollama-specific false positives
        if 'ollama' in pattern_match.lower() or any(word in pattern_match.lower() for word in ['llama', 'mistral', 'phi']):
            # Skip if it's part of other words
            if any(false_pos in line_lower for false_pos in [
                'philippine', 'philippines', 'geographical', 'graphical', 'graphic',
                'graphinterval', 'graphintervals', 'graphpanel', 'graphicone',
                'sidebar_graphic', 'sidebar graphic', 'adbe vector graphic',
                'view graphical data', 'graphicalexplanation', 'graphical-explain',
                'gallabox', 'oneTapHide', 'oneTapHideReason'
            ]):
                return True
        
        return False
    
    def detect(self, file_path: Path, content: str) -> List[DetectionResult]:
        """Detect AI services in source code files."""
        results = []
        lines = content.split('\n')
        
        for service in self.registry.get_all_services():
            # Check import patterns
            for pattern in service.import_patterns:
                for line_num, line in enumerate(lines, 1):
                    if self._is_comment_or_string_literal(line):
                        continue
                    if safe_regex_search(pattern, line):
                        results.append(DetectionResult(
                            service_name=service.name,
                            detection_type='code',
                            file_path=str(file_path),
                            line_number=line_num,
                            evidence=line.strip(),
                            severity='info'
                        ))
                        break  # Only report once per pattern per file
            
            # Special handling for AWS Bedrock - check for boto3 with Bedrock context
            if service.name == 'AWS Bedrock':
                # Check if boto3 is imported
                boto3_import_line_num = None
                for line_num, line in enumerate(lines, 1):
                    if self._is_comment_or_string_literal(line):
                        continue
                    if safe_re_search(r'import\s+boto3|from\s+boto3', line, re.IGNORECASE):
                        boto3_import_line_num = line_num
                        break
                
                # If boto3 is imported, check for Bedrock-specific usage in the file
                if boto3_import_line_num is not None:
                    bedrock_context_line_num = None
                    bedrock_context_line = None
                    for line_num, line in enumerate(lines, 1):
                        if self._is_comment_or_string_literal(line):
                            continue
                        line_lower = line.lower()
                        # Check for Bedrock-specific patterns (models, clients, endpoints, API calls)
                        if any(indicator in line_lower for indicator in [
                            'bedrock', 'bedrock-runtime', 'bedrockruntime',
                            'anthropic.claude', 'amazon.titan', 'ai21.j2', 'meta.llama',
                            'invoke_model', 'invoke_model_with_response_stream',
                            'bedrockclient', 'bedrockruntimeclient'
                        ]):
                            bedrock_context_line_num = line_num
                            bedrock_context_line = line.strip()
                            break
                    
                    # Only flag boto3 import if Bedrock context is found
                    if bedrock_context_line_num is not None:
                        # Use the Bedrock-specific line as evidence, not the import line
                        results.append(DetectionResult(
                            service_name=service.name,
                            detection_type='code',
                            file_path=str(file_path),
                            line_number=bedrock_context_line_num,
                            evidence=bedrock_context_line,
                            severity='info'
                        ))
            
            # Check client instantiation patterns
            for pattern in service.client_patterns:
                for line_num, line in enumerate(lines, 1):
                    if self._is_comment_or_string_literal(line):
                        continue
                    match = safe_regex_search(pattern, line)
                    if match:
                        matched_text = match.group(0)
                        
                        # Skip if it's a false positive
                        if self._is_false_positive_pattern(line, matched_text):
                            continue
                        
                        # Additional check for vLLM - only match if it's actually vLLM usage
                        if service.name == 'vLLM':
                            if 'vllm' not in line.lower() and 'from vllm' not in line.lower():
                                continue
                        
                        # Additional check for LangChain Agent - must have LangChain context
                        if service.name == 'LangChain' and 'agent' in matched_text.lower():
                            line_lower = line.lower()
                            # Skip if it's just "Agent(" without LangChain context
                            if not any(ctx in line_lower for ctx in ['langchain', 'from langchain', 'import langchain', 'llmchain', 'conversationchain']):
                                # Only allow if it's at the start of the line (likely a class instantiation)
                                if not line.strip().startswith('Agent(') and not line.strip().startswith('agent('):
                                    continue
                        
                        results.append(DetectionResult(
                            service_name=service.name,
                            detection_type='code',
                            file_path=str(file_path),
                            line_number=line_num,
                            evidence=line.strip(),
                            severity='info'
                        ))
                        break
            
            # Check API endpoints - only in actual code, not comments
            for endpoint in service.api_endpoints:
                for line_num, line in enumerate(lines, 1):
                    if self._is_comment_or_string_literal(line):
                        continue
                    line_lower = line.lower()
                    # Only match if endpoint appears in a meaningful context
                    if endpoint.lower() in line_lower:
                        # Skip localhost endpoints unless there's explicit service context
                        if 'localhost' in endpoint.lower() or '127.0.0.1' in endpoint.lower():
                            # For LocalAI, require explicit LocalAI context
                            if service.name == 'LocalAI':
                                if 'localai' not in line_lower and 'local-ai' not in line_lower:
                                    continue
                            # For Ollama, require explicit Ollama context
                            elif service.name == 'Ollama':
                                if 'ollama' not in line_lower:
                                    continue
                        
                        # Skip if it's just in a URL string without context
                        if line.count('"') >= 2 or line.count("'") >= 2:
                            # Check if it's an actual API call, not just a string
                            if any(keyword in line_lower for keyword in ['http', 'request', 'api', 'client', 'endpoint']):
                                results.append(DetectionResult(
                                    service_name=service.name,
                                    detection_type='endpoint',
                                    file_path=str(file_path),
                                    line_number=line_num,
                                    evidence=line.strip(),
                                    severity='warning'
                                ))
                                break
                        else:
                            results.append(DetectionResult(
                                service_name=service.name,
                                detection_type='endpoint',
                                file_path=str(file_path),
                                line_number=line_num,
                                evidence=line.strip(),
                                severity='warning'
                            ))
                            break
            
            # Check model patterns - be more restrictive
            for pattern in service.model_patterns:
                for line_num, line in enumerate(lines, 1):
                    if self._is_comment_or_string_literal(line):
                        continue
                    
                    match = safe_regex_search(pattern, line)
                    if match:
                        matched_text = match.group(0)
                        
                        # Skip if it's a false positive
                        if self._is_false_positive_pattern(line, matched_text):
                            continue
                        
                        # For generic model patterns like [\w-]+/[\w-]+, require more context
                        if pattern.pattern == r'[\w-]+/[\w-]+':
                            # Only match if it looks like a model identifier
                            # Should have context like "model", "name", "id", or be in quotes with model context
                            line_lower = line.lower()
                            if not any(keyword in line_lower for keyword in ['model', 'name', 'id', 'repo', 'huggingface', 'hf_', 'transformers']):
                                # Check if it's in a JSON-like structure with model context nearby
                                if 'model' not in line_lower and 'name' not in line_lower:
                                    continue
                        
                        results.append(DetectionResult(
                            service_name=service.name,
                            detection_type='code',
                            file_path=str(file_path),
                            line_number=line_num,
                            evidence=line.strip(),
                            severity='info'
                        ))
                        break
        
        return results


class ConfigDetector:
    """Detects AI services in configuration files."""
    
    def __init__(self, registry: AIServiceRegistry):
        self.registry = registry
    
    def detect(self, file_path: Path, content: str) -> List[DetectionResult]:
        """Detect AI services in configuration files."""
        results = []
        lines = content.split('\n')
        file_ext = file_path.suffix.lower()
        
        # Parse JSON/YAML configs
        config_data = {}
        if file_ext in ['.json']:
            try:
                config_data = json.loads(content)
            except json.JSONDecodeError:
                pass
        elif file_ext in ['.yaml', '.yml']:
            # Simple YAML parsing (could use PyYAML for better parsing)
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    config_data[key.strip()] = value.strip().strip('"').strip("'")
        
        # Check for config key patterns
        for service in self.registry.get_all_services():
            for config_key in service.config_key_patterns:
                # Check in parsed config
                if config_key in config_data:
                    results.append(DetectionResult(
                        service_name=service.name,
                        detection_type='config',
                        file_path=str(file_path),
                        evidence=f"Configuration key '{config_key}' found",
                        severity='info'
                    ))
                    break
                
                # Check in raw content (for .env files)
                for line_num, line in enumerate(lines, 1):
                    if config_key in line and '=' in line:
                        results.append(DetectionResult(
                            service_name=service.name,
                            detection_type='config',
                            file_path=str(file_path),
                            line_number=line_num,
                            evidence=line.strip(),
                            severity='info'
                        ))
                        break
        
        return results


class DetectorManager:
    """Manages all detectors and coordinates detection."""
    
    def __init__(self, registry: AIServiceRegistry):
        self.registry = registry
        self.dependency_detector = DependencyDetector(registry)
        self.code_detector = CodePatternDetector(registry)
        self.config_detector = ConfigDetector(registry)
    
    def detect_file(self, file_path: Path, repo_path: Optional[Path] = None, repo_url: Optional[str] = None, default_branch: Optional[str] = None) -> List[DetectionResult]:
        """Detect AI services in a single file."""
        results = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (IOError, OSError, UnicodeDecodeError):
            return results
        
        # Calculate relative file path from repo root
        relative_file_path = None
        if repo_path:
            try:
                relative_file_path = str(file_path.relative_to(repo_path))
            except ValueError:
                # File is not under repo_path, use absolute path
                relative_file_path = str(file_path)
        
        file_name = file_path.name.lower()
        
        # Route to appropriate detector
        if file_name in get_dependency_files():
            detector_results = self.dependency_detector.detect(file_path, content)
            results.extend(self._add_repo_context(detector_results, repo_url, relative_file_path, default_branch))
        
        if file_path.suffix.lower() in get_code_file_extensions():
            detector_results = self.code_detector.detect(file_path, content)
            results.extend(self._add_repo_context(detector_results, repo_url, relative_file_path, default_branch))
        
        if file_name in get_config_files() or file_path.suffix.lower() in ['.yaml', '.yml', '.json', '.toml', '.env']:
            detector_results = self.config_detector.detect(file_path, content)
            results.extend(self._add_repo_context(detector_results, repo_url, relative_file_path, default_branch))
        
        return results
    
    def _add_repo_context(self, results: List[DetectionResult], repo_url: Optional[str], relative_file_path: Optional[str], default_branch: Optional[str]) -> List[DetectionResult]:
        """Add repository context to detection results."""
        for result in results:
            result.repo_url = repo_url
            result.relative_file_path = relative_file_path
            result.default_branch = default_branch
        return results


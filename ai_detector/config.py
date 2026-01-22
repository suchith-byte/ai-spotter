"""Configuration settings for the AI detector.

This module contains all configurable values used throughout the application.
Default values can be overridden via environment variables or a config file.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set, FrozenSet


@dataclass(frozen=True)
class ScannerConfig:
    """Configuration for the repository scanner."""
    
    # Number of parallel workers for file scanning
    max_workers: int = 4
    
    # Maximum file size in MB to scan (larger files are skipped)
    max_file_size_mb: int = 1
    
    # Git clone timeout in seconds
    git_clone_timeout: int = 300
    
    # Git command timeout in seconds
    git_command_timeout: int = 10
    
    # Default branch names to try (in order)
    default_branch_names: tuple = ('main', 'master', 'develop', 'trunk')


@dataclass(frozen=True)
class FileFilterConfig:
    """Configuration for file filtering during scans."""
    
    # Directories to skip during scanning
    skip_directories: FrozenSet[str] = field(default_factory=lambda: frozenset({
        '.git', 'node_modules', '__pycache__', '.pytest_cache',
        '.venv', 'venv', 'env', '.env', 'dist', 'build',
        '.idea', '.vscode', 'target', '.gradle', '.mvn',
        '.tox', '.eggs', '.mypy_cache', '.ruff_cache',
        'htmlcov', '.coverage', '.hypothesis',
    }))
    
    # File extensions to skip (binary/non-text files)
    skip_extensions: FrozenSet[str] = field(default_factory=lambda: frozenset({
        # Compiled Python
        '.pyc', '.pyo', '.pyd',
        # Compiled/binary
        '.so', '.dll', '.dylib', '.exe', '.bin', '.o', '.a',
        # Images
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp',
        # Documents
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        # Archives
        '.zip', '.tar', '.gz', '.bz2', '.xz', '.rar', '.7z',
        # Media
        '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flac', '.mkv', '.webm',
        # Fonts
        '.ttf', '.otf', '.woff', '.woff2', '.eot',
        # Database
        '.db', '.sqlite', '.sqlite3',
        # Lock files (large, auto-generated)
        '.lock',
    }))
    
    # Code file extensions to scan
    code_extensions: FrozenSet[str] = field(default_factory=lambda: frozenset({
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb',
        '.php', '.cpp', '.c', '.h', '.hpp', '.cs', '.swift', '.kt',
        '.scala', '.rs', '.sh', '.bash', '.zsh', '.ps1', '.r', '.m',
        '.sql', '.pl', '.pm', '.lua', '.dart', '.vue', '.svelte',
        '.mjs', '.cjs', '.cts', '.mts',
    }))
    
    # Dependency file names to scan
    dependency_files: FrozenSet[str] = field(default_factory=lambda: frozenset({
        'requirements.txt',
        'package.json',
        'pipfile',
        'poetry.lock',
        'pyproject.toml',
        'cargo.toml',
        'go.mod',
        'go.sum',
        'pom.xml',
        'build.gradle',
        'build.gradle.kts',
        'gemfile',
        'gemfile.lock',
        'composer.json',
        'composer.lock',
        'yarn.lock',
        'pnpm-lock.yaml',
        'package-lock.json',
    }))
    
    # Configuration file names to scan
    config_files: FrozenSet[str] = field(default_factory=lambda: frozenset({
        '.env',
        '.env.local',
        '.env.production',
        '.env.development',
        '.env.example',
        '.env.sample',
        'config.yaml',
        'config.yml',
        'config.json',
        'settings.yaml',
        'settings.yml',
        'settings.json',
        'application.yaml',
        'application.yml',
        'application.properties',
        'docker-compose.yml',
        'docker-compose.yaml',
        '.envrc',
    }))


@dataclass(frozen=True)
class OutputConfig:
    """Configuration for output formatting."""
    
    # Maximum evidence length in CSV output
    max_evidence_length: int = 500
    
    # Line width for text reports
    report_line_width: int = 80
    
    # Date format for reports
    date_format: str = '%Y-%m-%d %H:%M:%S UTC'


@dataclass
class AppConfig:
    """Main application configuration."""
    
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    file_filter: FileFilterConfig = field(default_factory=FileFilterConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    
    @classmethod
    def _safe_int(cls, value: str, default: int, min_val: int = 1, max_val: int = 10000) -> int:
        """Safely parse integer from string with bounds checking.
        
        Args:
            value: String value to parse.
            default: Default value if parsing fails.
            min_val: Minimum allowed value.
            max_val: Maximum allowed value.
            
        Returns:
            Parsed and bounded integer.
        """
        try:
            parsed = int(value)
            return max(min_val, min(parsed, max_val))
        except (ValueError, TypeError):
            return default
    
    @classmethod
    def from_env(cls) -> 'AppConfig':
        """Create configuration from environment variables."""
        scanner = ScannerConfig(
            max_workers=cls._safe_int(os.getenv('AI_DETECTOR_MAX_WORKERS', '4'), 4, 1, 32),
            max_file_size_mb=cls._safe_int(os.getenv('AI_DETECTOR_MAX_FILE_SIZE_MB', '1'), 1, 1, 100),
            git_clone_timeout=cls._safe_int(os.getenv('AI_DETECTOR_GIT_CLONE_TIMEOUT', '300'), 300, 30, 3600),
            git_command_timeout=cls._safe_int(os.getenv('AI_DETECTOR_GIT_COMMAND_TIMEOUT', '10'), 10, 5, 120),
        )
        return cls(scanner=scanner)


# Thread-safe global configuration instance
import threading
_config_lock = threading.Lock()
_default_config: AppConfig = None


def get_config() -> AppConfig:
    """Get the global configuration instance (thread-safe)."""
    global _default_config
    if _default_config is None:
        with _config_lock:
            # Double-check locking pattern
            if _default_config is None:
                _default_config = AppConfig.from_env()
    return _default_config


def set_config(config: AppConfig) -> None:
    """Set the global configuration instance (thread-safe)."""
    global _default_config
    with _config_lock:
        _default_config = config


# Convenience accessors for backward compatibility
def get_dependency_files() -> List[str]:
    """Get list of dependency file names to scan."""
    return list(get_config().file_filter.dependency_files)


def get_config_files() -> List[str]:
    """Get list of configuration file names to scan."""
    return list(get_config().file_filter.config_files)


def get_code_file_extensions() -> Set[str]:
    """Get set of code file extensions to scan."""
    return set(get_config().file_filter.code_extensions)


def get_skip_directories() -> Set[str]:
    """Get set of directories to skip during scanning."""
    return set(get_config().file_filter.skip_directories)


def get_skip_extensions() -> Set[str]:
    """Get set of file extensions to skip."""
    return set(get_config().file_filter.skip_extensions)


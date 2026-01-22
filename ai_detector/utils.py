"""Utility functions for the AI detector."""

import json
import re
from pathlib import Path
from typing import Set

from .config import get_config, get_skip_directories, get_skip_extensions


def is_binary_file(file_path: Path) -> bool:
    """Check if a file is likely binary."""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            # Check for null bytes
            if b'\x00' in chunk:
                return True
            # Check if more than 30% are non-printable (excluding common whitespace)
            non_printable = sum(1 for b in chunk if b < 32 and b not in (9, 10, 13))
            if len(chunk) > 0 and non_printable / len(chunk) > 0.3:
                return True
    except (IOError, OSError):
        return True
    return False


def should_skip_file(file_path: Path, max_size_mb: int = None) -> bool:
    """Determine if a file should be skipped during scanning.
    
    Args:
        file_path: Path to the file to check.
        max_size_mb: Maximum file size in MB. Uses config default if not specified.
    
    Returns:
        True if the file should be skipped, False otherwise.
    """
    if max_size_mb is None:
        max_size_mb = get_config().scanner.max_file_size_mb
    
    # Skip binary files
    if is_binary_file(file_path):
        return True
    
    # Skip large files
    try:
        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > max_size_mb:
            return True
    except (OSError, IOError):
        return True
    
    # Skip configured directories
    skip_dirs = get_skip_directories()
    parts = file_path.parts
    if any(part in skip_dirs for part in parts):
        return True
    
    # Skip configured extensions
    skip_extensions = get_skip_extensions()
    if file_path.suffix.lower() in skip_extensions:
        return True
    
    return False


def parse_requirements_file(content: str) -> Set[str]:
    """Parse a requirements.txt file and extract package names.
    
    Args:
        content: Raw content of the requirements.txt file.
    
    Returns:
        Set of lowercase package names.
    """
    packages = set()
    for line in content.split('\n'):
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        # Handle various requirement formats
        # Remove version specifiers, extras, etc.
        package = re.split(r'[>=<!=;\[\]#\s@]', line)[0].strip()
        if package:
            packages.add(package.lower())
    return packages


def parse_package_json(content: str) -> Set[str]:
    """Parse a package.json file and extract package names.
    
    Args:
        content: Raw content of the package.json file.
    
    Returns:
        Set of lowercase package names.
    """
    packages = set()
    try:
        data = json.loads(content)
        # Check dependencies, devDependencies, and peerDependencies
        dep_keys = ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies')
        for key in dep_keys:
            deps = data.get(key, {})
            if isinstance(deps, dict):
                packages.update(k.lower() for k in deps.keys())
    except (json.JSONDecodeError, KeyError, TypeError):
        pass
    return packages


def parse_pyproject_toml(content: str) -> Set[str]:
    """Parse a pyproject.toml file and extract package names.
    
    Args:
        content: Raw content of the pyproject.toml file.
    
    Returns:
        Set of lowercase package names.
    """
    packages = set()
    # Simple regex-based parsing (could be improved with toml library)
    # Look for dependencies in [project.dependencies] or [tool.poetry.dependencies]
    deps_section = False
    for line in content.split('\n'):
        line = line.strip()
        if line.startswith('[') and 'dependencies' in line.lower():
            deps_section = True
            continue
        if line.startswith('['):
            deps_section = False
            continue
        if deps_section and line and not line.startswith('#'):
            # Extract package name (before =, ", ', or [)
            package = re.split(r'[=\'"\[\]]', line)[0].strip()
            if package:
                packages.add(package.lower().strip('"').strip("'"))
    return packages


# Re-export config functions for backward compatibility
from .config import get_dependency_files, get_config_files, get_code_file_extensions

__all__ = [
    'is_binary_file',
    'should_skip_file',
    'parse_requirements_file',
    'parse_package_json',
    'parse_pyproject_toml',
    'get_dependency_files',
    'get_config_files',
    'get_code_file_extensions',
]

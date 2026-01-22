"""Repository scanner for local and GitHub repositories."""

import os
import subprocess
import tempfile
import shutil
import secrets
import urllib.parse
from pathlib import Path
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from .config import get_config
from .detectors import DetectorManager, DetectionResult
from .services import AIServiceRegistry
from .utils import should_skip_file

logger = logging.getLogger(__name__)


class RepositoryScanner:
    """Scans repositories for AI service usage."""
    
    def __init__(self, github_token: Optional[str] = None, max_workers: int = None):
        self.registry = AIServiceRegistry()
        self.detector_manager = DetectorManager(self.registry)
        self.github_token = github_token
        self.config = get_config()
        self.max_workers = max_workers or self.config.scanner.max_workers
        self.temp_dirs = []  # Track temp dirs for cleanup
    
    def _get_default_branch(self, repo_path: str, verbose: bool = False) -> str:
        """Get the default branch name from a git repository."""
        timeout = self.config.scanner.git_command_timeout
        
        try:
            # Try to get the current branch (what was checked out)
            result = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if result.returncode == 0:
                branch = result.stdout.strip()
                if branch and branch != 'HEAD':
                    if verbose:
                        logger.debug(f"Detected default branch: {branch}")
                    return branch
            
            # Fallback: try to get from origin/HEAD
            result = subprocess.run(
                ['git', 'symbolic-ref', 'refs/remotes/origin/HEAD'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if result.returncode == 0:
                # Extract branch name from refs/remotes/origin/main or similar
                ref = result.stdout.strip()
                if '/origin/' in ref:
                    branch = ref.split('/origin/')[-1]
                    if verbose:
                        logger.debug(f"Detected default branch from origin: {branch}")
                    return branch
            
            # Fallback: check common branch names from config
            for branch_name in self.config.scanner.default_branch_names:
                result = subprocess.run(
                    ['git', 'show-ref', f'refs/heads/{branch_name}'],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                if result.returncode == 0:
                    if verbose:
                        logger.debug(f"Found branch: {branch_name}")
                    return branch_name
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, Exception) as e:
            if verbose:
                logger.warning(f"Could not detect default branch: {e}")
        
        # Final fallback - use first configured default branch
        default = self.config.scanner.default_branch_names[0] if self.config.scanner.default_branch_names else 'main'
        if verbose:
            logger.debug(f"Using default branch: {default}")
        return default
    
    def scan_local(self, repo_path: Path, verbose: bool = False, repo_url: Optional[str] = None, default_branch: Optional[str] = None) -> List[DetectionResult]:
        """Scan a local repository directory."""
        if not repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        
        if not repo_path.is_dir():
            raise ValueError(f"Path is not a directory: {repo_path}")
        
        if verbose:
            logger.info(f"Scanning local repository: {repo_path}")
        
        # Try to detect default branch for local repos too (if it's a git repo)
        if default_branch is None and (repo_path / '.git').exists():
            default_branch = self._get_default_branch(str(repo_path), verbose)
        
        all_results = []
        files_to_scan = []
        
        # Resolve repo_path to absolute for symlink validation
        repo_path_resolved = repo_path.resolve()
        
        # Collect all files to scan (followlinks=False to prevent symlink escape)
        for root, dirs, files in os.walk(repo_path, followlinks=False):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                file_path = Path(root) / file
                
                # Security: Skip symlinks to prevent escaping the repository
                if file_path.is_symlink():
                    if verbose:
                        logger.debug(f"Skipping symlink: {file_path}")
                    continue
                
                # Security: Verify file is within repo bounds (defense in depth)
                try:
                    file_resolved = file_path.resolve()
                    file_resolved.relative_to(repo_path_resolved)
                except ValueError:
                    if verbose:
                        logger.warning(f"Skipping file outside repository bounds: {file_path}")
                    continue
                
                if not should_skip_file(file_path):
                    files_to_scan.append(file_path)
        
        if verbose:
            logger.info(f"Found {len(files_to_scan)} files to scan")
        
        # Scan files in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(self.detector_manager.detect_file, file_path, repo_path, repo_url, default_branch): file_path
                for file_path in files_to_scan
            }
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                    if verbose and results:
                        logger.debug(f"Found {len(results)} detections in {file_path}")
                except Exception as e:
                    if verbose:
                        logger.warning(f"Error scanning {file_path}: {e}")
        
        return all_results
    
    def _validate_repo_url(self, repo_url: str) -> str:
        """Validate and sanitize repository URL to prevent injection and SSRF attacks.
        
        Args:
            repo_url: The repository URL to validate.
            
        Returns:
            Sanitized URL.
            
        Raises:
            ValueError: If URL is invalid or potentially malicious.
        """
        import re
        import socket
        
        # Strip whitespace
        url = repo_url.strip()
        
        # Block obviously malicious patterns
        dangerous_patterns = [
            '--upload-pack', '--receive-pack', '-c ', ' -c ',
            '$(', '`', '|', ';', '&', '\n', '\r', '\x00'
        ]
        for pattern in dangerous_patterns:
            if pattern in url:
                raise ValueError(f"Invalid repository URL: contains forbidden pattern")
        
        # Validate URL format
        if url.startswith('https://') or url.startswith('http://'):
            parsed = urllib.parse.urlparse(url)
            # Ensure it's a valid URL with host
            if not parsed.netloc:
                raise ValueError(f"Invalid repository URL: missing host")
            
            # Extract hostname (without port)
            hostname = parsed.hostname or ''
            
            # SSRF Protection: Block internal/private network addresses
            blocked_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
            if hostname.lower() in blocked_hosts:
                raise ValueError(f"Invalid repository URL: localhost/loopback addresses not allowed")
            
            # Block private IP ranges (basic check)
            ip_parts = hostname.split('.')
            if len(ip_parts) == 4:
                try:
                    octets = [int(p) for p in ip_parts]
                    if all(0 <= o <= 255 for o in octets):
                        first_octet, second_octet = octets[0], octets[1]
                        # 10.0.0.0/8
                        if first_octet == 10:
                            raise ValueError(f"Invalid repository URL: private IP addresses not allowed")
                        # 172.16.0.0/12
                        if first_octet == 172 and 16 <= second_octet <= 31:
                            raise ValueError(f"Invalid repository URL: private IP addresses not allowed")
                        # 192.168.0.0/16
                        if first_octet == 192 and second_octet == 168:
                            raise ValueError(f"Invalid repository URL: private IP addresses not allowed")
                        # 169.254.0.0/16 (link-local)
                        if first_octet == 169 and second_octet == 254:
                            raise ValueError(f"Invalid repository URL: link-local addresses not allowed")
                except (ValueError, IndexError) as e:
                    # Re-raise if it's our security ValueError
                    if "private IP" in str(e) or "link-local" in str(e):
                        raise
                    # Otherwise, not a valid IP, continue validation
            
            # Reconstruct URL to remove any injection attempts in path
            # Only allow alphanumeric, dash, underscore, dot, slash in path
            if parsed.path and not re.match(r'^[a-zA-Z0-9/_.-]*$', parsed.path):
                raise ValueError(f"Invalid repository URL: path contains invalid characters")
        elif url.startswith('git@'):
            # SSH format: git@github.com:owner/repo.git
            if not re.match(r'^git@[\w.-]+:[\w./-]+$', url):
                raise ValueError(f"Invalid repository URL format")
            # Extract hostname from SSH URL
            ssh_host = url.split('@')[1].split(':')[0] if '@' in url and ':' in url else ''
            if ssh_host.lower() in ['localhost', '127.0.0.1']:
                raise ValueError(f"Invalid repository URL: localhost not allowed")
        else:
            raise ValueError(f"Invalid repository URL: must start with https://, http://, or git@")
        
        return url
    
    def scan_remote(self, repo_url: str, verbose: bool = False) -> List[DetectionResult]:
        """Scan a remote Git repository by cloning it locally."""
        # Validate URL before processing
        repo_url = self._validate_repo_url(repo_url)
        
        if verbose:
            logger.info(f"Cloning repository from: {repo_url}")
        
        # Clone repository to temporary directory with unpredictable name
        temp_dir = tempfile.mkdtemp(prefix=f"ai_detector_{secrets.token_hex(8)}_")
        self.temp_dirs.append(temp_dir)
        
        try:
            # Prepare clone URL with authentication if token is provided
            clone_url = repo_url
            
            # For HTTPS URLs, embed token if provided (URL-encoded for safety)
            if self.github_token and clone_url.startswith('https://'):
                # Insert token into URL: https://github.com/owner/repo -> https://token@github.com/owner/repo
                if '@' not in clone_url.split('//')[1]:  # Only if no token already present
                    # URL-encode token to handle special characters safely
                    encoded_token = urllib.parse.quote(self.github_token, safe='')
                    clone_url = clone_url.replace('https://', f'https://{encoded_token}@')
            
            # Clone using git command
            if verbose:
                logger.debug(f"Cloning to: {temp_dir}")
            
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', '--quiet', clone_url, temp_dir],
                capture_output=True,
                text=True,
                timeout=self.config.scanner.git_clone_timeout
            )
            
            # Check if clone directory exists and has content (even if checkout partially failed)
            clone_succeeded = os.path.exists(temp_dir) and os.path.isdir(temp_dir)
            has_content = clone_succeeded and any(Path(temp_dir).iterdir())
            
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
                
                # If clone directory exists with content, we can still scan (git-lfs issues, etc.)
                if clone_succeeded and has_content:
                    if verbose:
                        logger.warning(f"Clone completed with warnings (may be missing git-lfs files): {error_msg}")
                else:
                    # Provide helpful error messages (sanitize to avoid token leakage)
                    # Remove any tokens from error messages
                    safe_error = error_msg
                    if self.github_token and self.github_token in safe_error:
                        safe_error = safe_error.replace(self.github_token, '[REDACTED]')
                    
                    if 'Authentication failed' in error_msg or 'fatal: could not read Username' in error_msg:
                        raise ValueError(
                            f"Authentication failed. For private repositories, ensure --github-token is provided "
                            f"and has 'repo' scope."
                        )
                    elif 'Repository not found' in error_msg or 'fatal: repository' in error_msg:
                        raise ValueError(
                            f"Repository not found or access denied: {repo_url}. "
                            f"Verify the URL is correct and you have access."
                        )
                    else:
                        raise RuntimeError(f"Failed to clone repository: {safe_error}")
            
            if not clone_succeeded or not has_content:
                raise RuntimeError(f"Repository clone failed: directory is empty or does not exist")
            
            if verbose:
                logger.info(f"Repository cloned successfully. Starting scan...")
            
            # Detect the default branch
            default_branch = self._get_default_branch(temp_dir, verbose)
            
            # Scan the cloned repository with original repo URL and branch
            return self.scan_local(Path(temp_dir), verbose=verbose, repo_url=repo_url, default_branch=default_branch)
        
        except subprocess.TimeoutExpired:
            timeout_mins = self.config.scanner.git_clone_timeout // 60
            raise RuntimeError(f"Git clone operation timed out after {timeout_mins} minutes")
        except Exception as e:
            # Clean up on error (ignore cleanup failures)
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except OSError as cleanup_error:
                logger.debug(f"Cleanup failed for {temp_dir}: {cleanup_error}")
            raise
    
    
    def cleanup_temp_dirs(self):
        """Clean up temporary directories."""
        for temp_dir in self.temp_dirs:
            try:
                # Use ignore_errors to handle race conditions (TOCTOU safe)
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception as e:
                # Shouldn't reach here with ignore_errors=True, but log just in case
                logger.debug(f"Cleanup note for {temp_dir}: {e}")
        self.temp_dirs = []
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup_temp_dirs()


def scan_repository(
    repo_path: Optional[Path] = None,
    repo_url: Optional[str] = None,
    github_token: Optional[str] = None,
    verbose: bool = False,
    max_workers: int = 4
) -> List[DetectionResult]:
    """
    Convenience function to scan a repository.
    
    Args:
        repo_path: Path to local repository
        repo_url: Remote Git repository URL (any Git remote: GitHub, GitLab, Bitbucket, etc.)
        github_token: Git token for private repos (works with any Git provider)
        verbose: Enable verbose logging
        max_workers: Number of parallel workers
    
    Returns:
        List of detection results
    """
    with RepositoryScanner(github_token=github_token, max_workers=max_workers) as scanner:
        if repo_path:
            return scanner.scan_local(repo_path, verbose=verbose)
        elif repo_url:
            return scanner.scan_remote(repo_url, verbose=verbose)
        else:
            raise ValueError("Either repo_path or repo_url must be provided")


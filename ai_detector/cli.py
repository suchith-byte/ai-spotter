"""Command-line interface for AI detector."""

import argparse
import os
import sys
import logging
from pathlib import Path
from typing import Optional

from .scanner import RepositoryScanner
from .reporters import ReporterManager


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def _print_stderr(message: str) -> None:
    """Print message to stderr."""
    print(message, file=sys.stderr)


def _validate_path_exists(path_str: str) -> Path:
    """Validate that a path exists and return Path object."""
    path = Path(path_str)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Path does not exist: {path_str}")
    return path


def _create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog='ai-detector',
        description='AI Service Detection CLI Tool\n\n'
                    'Scans repositories to detect usage of external AI services, LLMs, and AI providers.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan a local repository
  ai-detector --local-path /path/to/repo

  # Scan a GitHub repository
  ai-detector --repo-url https://github.com/owner/repo

  # Generate JSON output
  ai-detector --local-path /path/to/repo --output-format json

  # Save report to file
  ai-detector --repo-url https://github.com/owner/repo --output-file report.txt
'''
    )
    
    # Input options (mutually exclusive)
    input_group = parser.add_argument_group('Input options (choose one)')
    input_group.add_argument(
        '--repo-url',
        type=str,
        metavar='URL',
        help='Remote Git repository URL (e.g., https://github.com/owner/repo)'
    )
    input_group.add_argument(
        '--repo-file',
        type=_validate_path_exists,
        metavar='FILE',
        help='Path to text file containing repository names (org/repo per line)'
    )
    input_group.add_argument(
        '--local-path',
        type=_validate_path_exists,
        metavar='PATH',
        help='Path to local repository directory'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output options')
    output_group.add_argument(
        '--output-format',
        type=str,
        choices=['json', 'text', 'csv', 'all'],
        default='text',
        help='Output format (default: text)'
    )
    output_group.add_argument(
        '--output-file',
        type=str,
        metavar='FILE',
        help='File path to write output (if not specified, prints to stdout)'
    )
    
    # Authentication
    parser.add_argument(
        '--github-token',
        type=str,
        metavar='TOKEN',
        default=os.environ.get('GITHUB_TOKEN'),
        help='Git token for private repos (or set GITHUB_TOKEN env var)'
    )
    
    # Other options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--max-workers',
        type=int,
        default=4,
        metavar='N',
        help='Number of parallel workers for scanning (default: 4)'
    )
    
    return parser


def main(args: Optional[list] = None) -> None:
    """Main entry point for the CLI."""
    parser = _create_parser()
    parsed_args = parser.parse_args(args)
    
    # Validate that exactly one input option is provided
    input_count = sum([
        bool(parsed_args.repo_url),
        bool(parsed_args.repo_file),
        bool(parsed_args.local_path)
    ])
    
    if input_count == 0:
        parser.error("One of --repo-url, --repo-file, or --local-path must be provided")
    
    if input_count > 1:
        parser.error("Cannot specify multiple input options. Use only one of --repo-url, --repo-file, or --local-path")
    
    if parsed_args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    
    # Initialize scanner and reporter
    scanner = RepositoryScanner(
        github_token=parsed_args.github_token,
        max_workers=parsed_args.max_workers
    )
    reporter_manager = ReporterManager()
    
    try:
        # Perform scan
        if parsed_args.verbose:
            _print_stderr("Starting scan...")
        
        if parsed_args.repo_file:
            # Read repos from file and scan each one
            all_results = []
            try:
                with open(parsed_args.repo_file, 'r', encoding='utf-8') as f:
                    repo_lines = f.readlines()
                
                repos = []
                for line_num, line in enumerate(repo_lines, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):  # Skip empty lines and comments
                        continue
                    # Handle format: org/repo or full URL
                    if '/' in line:
                        if line.startswith('http'):
                            repos.append(line)
                        else:
                            # Convert org/repo to GitHub URL
                            repos.append(f"https://github.com/{line}")
                    else:
                        if parsed_args.verbose:
                            _print_stderr(f"Warning: Skipping invalid repo format on line {line_num}: {line}")
                
                if not repos:
                    _print_stderr("Error: No valid repositories found in file")
                    sys.exit(2)
                
                if parsed_args.verbose:
                    _print_stderr(f"Found {len(repos)} repositories to scan")
                
                # Scan each repository
                for idx, repo_url_item in enumerate(repos, 1):
                    if parsed_args.verbose:
                        _print_stderr(f"\n[{idx}/{len(repos)}] Scanning: {repo_url_item}")
                    try:
                        repo_results = scanner.scan_remote(repo_url_item, verbose=parsed_args.verbose)
                        all_results.extend(repo_results)
                        if parsed_args.verbose:
                            _print_stderr(f"  Found {len(repo_results)} detections")
                    except Exception as e:
                        # Sanitize error output to prevent log injection
                        safe_url = repo_url_item.replace('\n', '').replace('\r', '')[:200]
                        safe_error = str(e).replace('\n', ' ').replace('\r', '')[:500]
                        _print_stderr(f"  Error scanning {safe_url}: {safe_error}")
                        if parsed_args.verbose:
                            logger.exception(f"Exception details for {safe_url}")
                        continue
                
                results = all_results
                
            except IOError as e:
                _print_stderr(f"Error reading repo file: {str(e)}")
                sys.exit(2)
        
        elif parsed_args.local_path:
            results = scanner.scan_local(parsed_args.local_path, verbose=parsed_args.verbose)
        
        else:
            results = scanner.scan_remote(parsed_args.repo_url, verbose=parsed_args.verbose)
        
        if parsed_args.verbose:
            _print_stderr(f"\nScan complete. Found {len(results)} total detections.")
        
        # Generate report
        report = reporter_manager.generate_report(
            results=results,
            format=parsed_args.output_format,
            output_file=parsed_args.output_file
        )
        
        # Output report
        if parsed_args.output_file:
            _print_stderr(f"Report written to: {parsed_args.output_file}")
        else:
            print(report)
        
        # Set exit code based on findings
        if results:
            sys.exit(1)  # AI services detected
        else:
            sys.exit(0)  # No AI services found
    
    except KeyboardInterrupt:
        _print_stderr("\nScan interrupted by user")
        sys.exit(130)
    
    except Exception as e:
        # Sanitize error message to prevent injection
        safe_error = str(e).replace('\n', ' ').replace('\r', '')[:500]
        _print_stderr(f"Error: {safe_error}")
        if parsed_args.verbose:
            logger.exception("Unhandled exception during scan")
        sys.exit(2)
    
    finally:
        scanner.cleanup_temp_dirs()


if __name__ == '__main__':
    main()

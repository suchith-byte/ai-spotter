#!/usr/bin/env python3
"""
Run AI Detector directly without installation.

Usage:
    python run.py --help
    python run.py --local-path /path/to/repo
    python run.py --repo-url https://github.com/owner/repo

Requirements:
    pip install -r requirements.txt
"""

from ai_detector.cli import main

if __name__ == "__main__":
    main()


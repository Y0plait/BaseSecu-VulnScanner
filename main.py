#!/usr/bin/env python3
"""
@file main.py
@brief Vulnerability Scanner - Main entry point

This is the main entry point for the vulnerability scanner application.
It imports and runs the core application logic from src/core/main.py.

@author Anton Moulin
@date 2025-12-24
@version 1.0
"""

import sys
from src.core.main import main

if __name__ == "__main__":
    sys.exit(main())

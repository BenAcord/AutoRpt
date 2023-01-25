#!/usr/bin/python3
"""
autorpt.py
Enforce consistent, dependable workflow for engagement note-taking and report writing.
"""

import sys
from autorpt.main import main_menu, params

if __name__ == '__main__':
    # Take action based on parameters
    if len(sys.argv) <= 1:
        main_menu()
    else:
        params(sys.argv)

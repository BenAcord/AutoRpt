#!/usr/bin/python3
"""
autorpt.py
Enforce consistent, dependable workflow for engagement note-taking and report writing.
"""

import sys
from autorpt.main import main_menu, params
from autorpt.pretty import banner

if __name__ == '__main__':
    # Display pretty ASCII art
    banner()
    # Take action based on parameters
    if len(sys.argv) <= 1:
        main_menu()
    else:
        params(sys.argv)

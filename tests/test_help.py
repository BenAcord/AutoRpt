#!/usr/bin/python3
"""
test_helper.py
Verify output.
"""

import pytest
from autorpt import help

def test_helper():
    """Test"""
    with pytest.raises(SystemExit):
        help.helper()

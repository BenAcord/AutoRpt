#!/usr/bin/python3
"""
test_pretty.py
Verify output formatting module.
"""

import pytest
from autorpt import pretty as out

def test_banner():
    """Test"""
    assert out.banner() is None

def test_clear():
    """Test"""
    assert out.clear_screen() is None

def test_header():
    """Test"""
    assert out.color_header(DUMMY_MSG) is None

def test_subheading():
    """Test"""
    assert out.color_subheading(DUMMY_MSG) is None

def test_menu_item():
    """Test"""
    assert out.color_menu_item(DUMMY_MSG) is None

def test_list():
    """Test"""
    assert out.color_list(DUMMY_MSG) is None

def test_debug():
    """Test"""
    assert out.color_debug(DUMMY_MSG) is None

def test_table_header():
    """Test"""
    assert out.color_table_header(DUMMY_MSG) is None

def test_verify():
    """Test"""
    assert out.color_verify(DUMMY_FIELD, DUMMY_MSG) is None

def test_warn():
    """Test"""
    assert out.color_warn(DUMMY_MSG) is None

def test_pass():
    """Test"""
    assert out.color_pass(DUMMY_FIELD, DUMMY_MSG) is None

def test_fail():
    """Test"""
    assert out.color_fail(DUMMY_FIELD, DUMMY_MSG) is None

def test_notice():
    """Test"""
    assert out.color_notice(DUMMY_MSG) is None


# Global constants for testing function calls.
DUMMY_FIELD = "FIELD TEST"
DUMMY_MSG = "MSG TEST"

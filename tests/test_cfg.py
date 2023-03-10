#!/usr/bin/python3
"""
test_work.py
Verify module use.
"""

from autorpt import cfg

def test_active_path():
    """ Verify variable: ACTIVE_PATH """
    assert len(cfg.ACTIVE_PATH) >= 10

def test_active_session():
    """ Verify variable: ACTIVE_SESSION """
    val_check = cfg.ACTIVE_SESSION.find('-')
    assert val_check >= 1

def test_load_config_values():
    """ Verify loading config values function. """
    assert cfg.load_config_values(cfg.config_path, cfg.config_file) is not None

def test_load_session_config():
    """ Verify load session config function. """
    assert cfg.load_session_config(cfg.session_file) is not None

def test_save_config():
    """ Verify save config finction. """
    assert cfg.save_config(cfg.config_values) is None

def test_save_enagements():
    """ Verify save engagements function. """
    assert cfg.save_enagements() is None

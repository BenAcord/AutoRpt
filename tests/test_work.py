#!/usr/bin/python3
"""
test_work.py
Verify the work modules functionality.
Bare minimum testing so as not to corrupt an existing engagement.
Run with: pytest -sv test_work.py
"""

import pytest
import autorpt_work as work

def test_sitrep_list():
    """ Verify sitrep list functionality. """
    assert work.sitrep_list() is None

#def test_sitrep_auto(DUMMY_MSG):
#    """ Verify sitrep automatic message posting functionality. """
#     # Works but writes to active engagement sitrep log.
#    assert work.sitrep_auto() is None

#----// TBD below this line. //
#def test_sitrep_add_template():
#def test_sitrep_add_target(192.168.55.111):

#def test_sitrep_menu():
#    """ Validate menu response to display a list then exit, two responses."""
#    # 1 = List
#    # 4 = Quit
#    with pytest.raises(SystemExit):
#        work.sitrep_menu()

# Global constants for testing function calls.
#DUMMY_FIELD = "FIELD TEST"
#DUMMY_MSG = "MSG TEST"

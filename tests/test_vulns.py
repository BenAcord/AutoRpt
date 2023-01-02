#!/usr/bin/python3
"""
test_vulns.py
Verify vulns module functionality.
"""

import sys
import pytest
import autorpt_vulns_extras as extras
import autorpt as core
import autorpt_cfg as cfg
import autorpt_pretty as out
import autorpt_vulns as vulns


def test_vuln_list():
    """ Validate vuln function """
    sys.argv == ['autorpt', 'vuln', 'list']
    with pytest.raises(OSError):
        vulns.vuln_list()

#@pytest.mark.parametrize(
#    "known_score_response, cvss_score, cvss_vector", 
#    "Y, 8.9, AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    #[
    #    'Y', 
    #    '8.9', 
    #    'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
    #]
#)
#def test_cvss3_score():
#    # Arrange
#    """Test CVSS3 score results"""
#    with pytest.raises(SystemExit):
#        type(vulns.get_cvss3_score()) is ['High', '8.9', 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N']

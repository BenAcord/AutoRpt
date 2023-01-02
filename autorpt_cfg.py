#!/usr/bin/python3
"""
autorpt_config.py
Global variables.
"""

import os
import sys
import shutil
import configparser
import autorpt_pretty as out

def load_config_values(this_config_path, this_config_file):
    """Read application-level settings configuration file"""
    # Exit without configuration file
    if not os.path.isdir(this_config_path):
        # If umask is not set, incorrect permissions will be assigned on mkdir
        os.umask(0)
        try:
            os.mkdir(this_config_path, 0o770)
        except (FileNotFoundError, PermissionError, IOError, OSError):
            out.color_fail(
                '[e]',
                f'Unable to create directory for AutoRpt settings: {this_config_path}'
            )
            sys.exit(20)

    if not os.path.isfile(this_config_file):
        try:
            # copy configuration file from GitHub clone
            shutil.copy(this_config_file, this_config_path)
        except (FileNotFoundError, PermissionError, IOError, OSError):
            out.color_fail(
                '[e]',
                'Unable to copy configuration file from the GitHub clone:{this_config_file}'
            )
            sys.exit(21)

    config = configparser.ConfigParser()
    config.read(this_config_file)

    # Get Settings.
    # Future: Replace variables throughout with the direct config_values reference
    student_name = config['Settings']['your_name']
    student_email = config['Settings']['email']

    # If blank settings exist prompt for value
    # Prompt to reuse or enter new psuedonym
    if '' == student_name:
        out.color_notice('What is your name?')
        student_name = (str(input('>  ')))
        config['Settings']['your_name'] = student_name
    if '' == student_email:
        this_msg = (
            'What is your email?   Enter to skip.\n'
            'This is used to create a directory for your personal TTP collection.'
        )
        out.color_notice(this_msg)
        student_email = (str(input('>  ')))
        config['Settings']['email'] = student_email

    if not os.path.exists(config['Paths']['pathwork']):
        os.umask(0o007)
        out.color_debug(f"config_path does not exist: {config['Paths']['pathwork']}")
        try:
            os.mkdir(config['Paths']['pathwork'], 0o770)
        except (FileNotFoundError, PermissionError, IOError, OSError):
            out.color_fail(
                '[e]',
                f"Unable to create directory for AutoRpt settings: {config['Paths']['pathwork']} "
            )
            sys.exit(22)

    # Write new config.toml
    save_config(config)
    this_msg = (
        "# WARNING !\n"
        "Use private Git project repositories.\n\n"
        "Do not use public Git projects.\n"
        "Public projects may violate terms of service, non-disclosure agreements,"
        "or leak proprietary information.\n\n\n"
    )
    readme = f"{config['Paths']['pathwork']}/README.md"
    if not os.path.isfile(readme):
        with open(readme, 'w', encoding='utf-8') as readme_writer:
            readme_writer.write(this_msg)
            readme_writer.close()

    # If team notes directory does not exist, create it.
    # This is for your Team TTP collection or company specific documentation.
    ttp_notes_dir = f"{config['Paths']['pathwork']}/All-TTPs"
    if not os.path.exists(ttp_notes_dir):
        # If umask is not set, incorrect permissions will be assigned on mkdir
        os.umask(0o007)
        try:
            os.mkdir(ttp_notes_dir, 0o770)
        except (FileNotFoundError, PermissionError, IOError, OSError):
            out.color_fail('[e]', f'Unable to create directory: {ttp_notes_dir} ')
            sys.exit(23)
    # End of load_config_values
    return config

def load_session_config(app_session_file):
    """Read session engagement file contents"""
    if os.path.isfile(app_session_file):
        config = configparser.ConfigParser()
        config.read(app_session_file)
        return config
    out.color_notice('The session file does not exist. It will be created on first use of startup.')
    return None

def save_config(this_config_values):
    """Store to disk modified application configuration values"""
    with open(config_file, 'w') as config_file_writer: # pylint: disable=unspecified-encoding
        this_config_values.write(config_file_writer)

def save_enagements():
    """Store to disk session engagement values"""
    with open(session_file, 'w') as config_file_writer: # pylint: disable=unspecified-encoding
        session.write(config_file_writer)

def get_active_path():
    """ Deprecated means of getting the active engagement path. """
    active = session['Current']['active']
    if 'None' == active:
        out.color_notice('No active engagement exists.  Use startup to create a new engagement.')
        sys.exit(30)
    else:
        return session[active]["path"]

def get_active_all():
    """ Deprecated means of getting the active engagement name. """
    active = session['Current']['active']
    if 'None' == active:
        out.color_notice('No active engagement exists.  Use startup to create a new engagement.')
        sys.exit(30)
    else:
        return f"{session['Engagements'][active]}"

# Force PYTHONUTF8=1 to prevent PyLint warning,
# Using open without explicitly specifying an encoding (unspecified-encoding)
os.environ["PYTHONUTF8"] = "1"
# Get the script home starting directory (eg. /opt/AutoRpt)
autorpt_runfrom = os.path.dirname(os.path.realpath(__file__))
# Directory for additional, supporting content.
# Currently only the Mitre ATT&CK Framwork.
pathIncludes = autorpt_runfrom + '/includes'  #  This was an error, "pathIncludes:".
# Path to store configuration settings and sessions
config_path = os.path.expanduser("~/.config/AutoRpt")
# Configuration settings
config_file = config_path + '/config.toml'
# Load configuration settings
config_values = load_config_values(config_path, config_file)
# Should be supportedFiletypes
supported_filetypes = config_values['Settings']['output_formats']
# Exclude filetypes that break report creation with pandoc
# File with list of target IP addresses
targets_file = config_values['Files']['targetfile']
# Spreadsheet of all ports per IP address in targets file
ports_spreadsheet = config_values['Files']['portfile']
# Validated list of vulnerabilities
vulnsCsv =  config_values['Files']['vulnfile']
# Situation report
sitrepLog =  config_values['Files']['sitrepfile']
# Constant active working directory for current engagement.
ACTIVE_PATH = config_values['Paths']['pathwork']
# Engagement sessions
session_file = config_path + '/' + config_values['Files']['sessionfile']
session = load_session_config(session_file)
# Constant for the current active engagement or blank if none.
ACTIVE_SESSION = ''
try:
    ACTIVE_SESSION = session['Current']['active']
except (FileNotFoundError, PermissionError, IOError, OSError):
    out.color_fail('Active Session', 'Failed to assign the active session to global variable.')

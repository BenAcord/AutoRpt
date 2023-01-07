#!/usr/bin/python3
"""
autorpt_config.py
Global variables.
"""

import datetime
import os
import sys
import shutil
import configparser
from packaging import version
import autorpt_pretty as out

def load_config_values(this_config_path, this_config_file):
    """Read application-level settings configuration file"""
    # Exit without configuration file
    if not os.path.isdir(this_config_path):
        # If umask is not set, incorrect permissions will be assigned on mkdir
        os.umask(0)
        try:
            os.mkdir(
                os.path.expanduser(this_config_path),
                0o770
            )
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
        out.color_notice(
            'Your name is missing from the settings.  '
            'This is used to personalize reports.\nWhat is your name?'
        )
        student_name = (str(input('>  ')))
        config['Settings']['your_name'] = student_name
    if '' == student_email:
        out.color_notice(
            'Your email address is missing from the settings.  '
            'What is your email?   Enter to skip.\n'
            'This is used for reports and to create a directory \n'
            'for your personal TTP collection.'
        )
        student_email = (str(input('>  ')))
        config['Settings']['email'] = student_email

    if not os.path.exists(os.path.expanduser(config['Paths']['pathwork'])):
        os.umask(0o007)
        out.color_debug(f"config_path does not exist: {config['Paths']['pathwork']}")
        try:
            os.mkdir(
                os.path.expanduser(config['Paths']['pathwork']),
                0o770
            )
        except (FileNotFoundError, PermissionError, IOError, OSError):
            out.color_fail(
                '[e]',
                f"Unable to create directory for AutoRpt settings: {config['Paths']['pathwork']} "
            )
            sys.exit(22)

    # Write new config.toml
    save_config(config)
    readme = f"{os.path.expanduser(config['Paths']['pathwork'])}/README.md"
    if not os.path.isfile(readme):
        with open(readme, 'w', encoding='utf-8') as readme_writer:
            readme_writer.write(
                "# WARNING !\n"
                "Use private Git project repositories.\n\n"
                "Do not use public Git projects.\n"
                "Public projects may violate terms of service, non-disclosure agreements,"
                "or leak proprietary information.\n\n\n"
            )
            readme_writer.close()

    # If team notes directory does not exist, create it.
    # This is for your Team TTP collection or company specific documentation.
    ttp_notes_dir = f"{os.path.expanduser(config['Paths']['pathwork'])}/All-TTPs"
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

def backup_config_file():
    """ Make a copy of the current user config file. """
    backup_time = datetime.datetime.now().strftime('%Y%m%d-%H%M')
    backup_file_name = f'{config_file}.{backup_time}'
    out.color_notice(f'Backing up the current configuration file to {backup_file_name}')
    # Copy in the new template file as a new lab interated file.
    try:
        shutil.copyfile(config_file, backup_file_name)
    except (FileNotFoundError, PermissionError, IOError, OSError):
        out.color_fail(f'Unable to copy {config_file} to {backup_file_name}.')
        sys.exit(23)

def save_config(this_config_values):
    """Store to disk modified application configuration values"""

    try:
        with open(config_file, 'w') as config_file_writer: # pylint: disable=unspecified-encoding
            this_config_values.write(config_file_writer)
            return True
    except (PermissionError, IOError):
        out.color_fail(
            'Save Config', "Failed to save the updated values to the user config.toml file."
        )
        return False

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

def upgrade_config_file(this_config_file):
    """ Manually called to upgrade from a legacy config file to the latest """

    # Check the version to see if an upgrade is needed.
    latest_config_file = f'{autorpt_runfrom}/config.toml'
    latest_config = configparser.ConfigParser()
    latest_config.read(latest_config_file)
    latest_version = latest_config['Version']['autorpt_version']

    # Get current config values for key sections.
    current_config = configparser.ConfigParser()
    current_config.read(this_config_file)
    try:
        current_version = current_config['Version']['autorpt_version']
    except KeyError:
        # Legacy version detected, pre-v1.1.0.
        current_version = '1.0.0'
    if version.parse(current_version) < version.parse(latest_version):
        out.color_notice(
            'An upgrade is needed.  '
            f'Latest Version: {latest_version}  Current Version: {current_version}'
        )
    else:
        out.color_notice('No upgrade is needed at this time.')
        sys.exit(0)

    # Update the in-memory latest config with user preferences in the existing, current config.
    # Ignoring some as they aren't enduser facing: type, output_formats, no_template.
    latest_config['Paths']['pathwork'] = os.path.expanduser(current_config['Paths']['pathwork'])
    latest_config['Paths']['your_name'] = current_config['Settings']['your_name']
    latest_config['Paths']['email'] = current_config['Settings']['email']
    latest_config['Paths']['studentid'] = current_config['Settings']['studentid']
    latest_config['Paths']['preferred_output_format'] = (
        current_config['Settings']['preferred_output_format']
    )
    latest_config['Paths']['style'] = current_config['Settings']['style']
    backup_config_file()
    out.color_notice('Upgrading the user config.toml file.')
    save_config(latest_config)


# Force PYTHONUTF8=1 to prevent PyLint warning,
# Using open without explicitly specifying an encoding (unspecified-encoding)
os.environ["PYTHONUTF8"] = "1"
# Get the script home starting directory (eg. /opt/AutoRpt)
autorpt_runfrom = os.path.dirname(os.path.expanduser(os.path.realpath(__file__)))
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

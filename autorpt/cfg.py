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
import pyperclip as pc
from packaging import version
from autorpt.pretty import color_fail, color_notice, color_debug # pylint: disable=import-error

def load_config_values():
    """Read application-level settings configuration file"""
    # Exit without configuration file
    if not os.path.isdir(CONFIG_PATH):
        # If umask is not set, incorrect permissions will be assigned on mkdir
        os.umask(0)
        try:
            os.mkdir(
                os.path.expanduser(CONFIG_PATH),
                0o770
            )
        except (FileNotFoundError, PermissionError, IOError, OSError):
            color_fail(
                '[e]',
                f'Unable to create directory for AutoRpt settings: {CONFIG_PATH}'
            )
            sys.exit(20)

    if not os.path.isfile(CONFIG_FILE):
        try:
            # copy configuration file from GitHub clone
            shutil.copy(CONFIG_FILE, CONFIG_PATH)
        except (FileNotFoundError, PermissionError, IOError, OSError):
            color_fail(
                '[e]',
                'Unable to copy configuration file from the GitHub clone:{CONFIG_FILE}'
            )
            sys.exit(21)

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    if not os.path.exists(os.path.expanduser(config['Paths']['pathwork'])):
        os.umask(0o007)
        color_notice(
            f"Config path does not exist: {config['Paths']['pathwork']}.  Attempting to create."
        )
        try:
            os.mkdir(
                os.path.expanduser(config['Paths']['pathwork']),
                0o770
            )
        except (FileNotFoundError, PermissionError, IOError, OSError):
            color_fail(
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
            color_fail(
                '[e]', f'Unable to create directory: {ttp_notes_dir} '
            )
            sys.exit(23)
    # End of load_config_values
    return config

def load_session_config():
    """Read session engagement file contents"""
    if os.path.isfile(SESSION_FILE):
        config = configparser.ConfigParser()
        config.read(SESSION_FILE)
        return config
    color_notice(
        'The session file does not exist. It will be created on first use of startup.'
    )
    return None

def backup_config_file():
    """ Make a copy of the current user config file. """
    backup_time = datetime.datetime.now().strftime('%Y%m%d-%H%M')
    backup_file_name = f'{CONFIG_FILE}.{backup_time}'
    color_notice(
        f'Backing up the current configuration file to {backup_file_name}'
    )
    # Copy in the new template file as a new lab interated file.
    try:
        shutil.copyfile(CONFIG_FILE, backup_file_name)

    except (FileNotFoundError, PermissionError, IOError, OSError):
        color_fail(
            'Backup Config', f'Unable to copy {CONFIG_FILE} to {backup_file_name}.'
        )
        sys.exit(23)

def save_config(this_latest_config):
    """Store to disk modified application configuration values"""

    try:
        with open(CONFIG_FILE, 'w') as config_file_writer: # pylint: disable=unspecified-encoding
            this_latest_config.write(config_file_writer)
            return True
    except (PermissionError, IOError):
        color_fail(
            'Save Config', "Failed to save the updated values to the user config.toml file."
        )
        return False

def save_engagements(this_session):
    """Store to disk session engagement values"""
    with open(SESSION_FILE, 'w') as config_file_writer: # pylint: disable=unspecified-encoding
        this_session.write(config_file_writer)

def get_active_path():
    """ Deprecated means of getting the active engagement path. """
    active = SESSION['Current']['active']
    if 'None' == active:
        color_notice(
            'No active engagement exists.  Use startup to create a new engagement.'
        )
        sys.exit(30)
    else:
        return SESSION[active]["path"]

def get_the_active_engagement():
    """ Show the active engagement and path. """

    if 'None' == SESSION['Current']['active']:
        color_notice(
            "No engagements.  Run 'autorpt.py startup' to create an engagement."
        )
    else:
        color_notice("Ready to go!")
        this_msg = SESSION['Current']['active']
        color_notice(
            "Path is in your clipboard: "
            f"{SESSION[this_msg]['path']}"
        )
        this_msg = SESSION['Current']['active']
        pc.copy(
            os.path.expanduser(
                SESSION[this_msg]['path']
            )
        )

def get_active_all():
    """ Deprecated means of getting the active engagement name. """
    active = SESSION['Current']['active']
    if 'None' == active:
        color_notice(
            'No active engagement exists.  Use startup to create a new engagement.'
        )
        sys.exit(30)
    else:
        return f"{SESSION['Engagements'][active]}"

def upgrade_config_file():
    """ Manually called to upgrade from a legacy config file to the latest """

    # Check the version to see if an upgrade is needed.
    latest_config_file = f'{AUTORPT_RUNFROM}/config.toml'
    latest_config = configparser.ConfigParser()
    latest_config.read(latest_config_file)
    latest_version = latest_config['Version']['autorpt_version']

    # Get current config values for key sections.
    current_config = configparser.ConfigParser()
    current_config.read(CONFIG_FILE)
    try:
        current_version = current_config['Version']['autorpt_version']
    except KeyError:
        # Legacy version detected, pre-v1.1.0.
        current_version = '1.0.0'
    if version.parse(current_version) < version.parse(latest_version):
        color_notice(
            'An upgrade is needed.  '
            f'Latest Version: {latest_version}  Current Version: {current_version}'
        )
    else:
        color_notice('No upgrade is needed at this time.')
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
    color_notice('Upgrading the user config.toml file.')
    save_config(latest_config)

# Force PYTHONUTF8=1 to prevent PyLint warning,
# Using open without explicitly specifying an encoding (unspecified-encoding)
os.environ["PYTHONUTF8"] = "1"
# Set the run state argument.
global RUN_STATE # pylint: disable=global-at-module-level
RUN_STATE = ""
for arg in range(1, len(sys.argv)):
    RUN_STATE = RUN_STATE + sys.argv[int(arg)]
#color_debug(f"RUN STATE: [{RUN_STATE}]")
# Get the script home starting directory (eg. /opt/AutoRpt)
global AUTORPT_RUNFROM # pylint: disable=global-at-module-level
AUTORPT_RUNFROM = os.path.dirname(os.path.expanduser(os.path.realpath(__file__)))
AUTORPT_RUNFROM = AUTORPT_RUNFROM.replace(r'/autorpt', "")
# Directory for additional, supporting content.
# Currently only the Mitre ATT&CK Framwork.
global PATH_INCLUDES # pylint: disable=global-at-module-level
PATH_INCLUDES = AUTORPT_RUNFROM + '/includes'
# Path to store configuration settings and sessions
global CONFIG_PATH # pylint: disable=global-at-module-level
CONFIG_PATH = os.path.expanduser("~/.config/AutoRpt")
# Configuration settings
global CONFIG_FILE # pylint: disable=global-at-module-level
CONFIG_FILE = CONFIG_PATH + '/config.toml'
# Load configuration settings
global CONFIG_VALUES # pylint: disable=global-at-module-level
CONFIG_VALUES = load_config_values()
# Should be supportedFiletypes
global SUPPORTED_FILETYPES # pylint: disable=global-at-module-level
SUPPORTED_FILETYPES = CONFIG_VALUES['Settings']['output_formats']
# Exclude filetypes that break report creation with pandoc
# File with list of target IP addresses
global TARGETS_FILE # pylint: disable=global-at-module-level
TARGETS_FILE = CONFIG_VALUES['Files']['targetfile']
# Spreadsheet of all ports per IP address in targets file
global PORTS_SPREADSHEET # pylint: disable=global-at-module-level
PORTS_SPREADSHEET = CONFIG_VALUES['Files']['portfile']
# Validated list of vulnerabilities
global VULNS_CSV # pylint: disable=global-at-module-level
VULNS_CSV =  CONFIG_VALUES['Files']['vulnfile']
# Situation report
global SITREP_LOG # pylint: disable=global-at-module-level
SITREP_LOG =  CONFIG_VALUES['Files']['sitrepfile']
# Constant active working directory for current engagement.
global ACTIVE_PATH # pylint: disable=global-at-module-level
ACTIVE_PATH = CONFIG_VALUES['Paths']['pathwork']
# Engagement sessions
global SESSION_FILE # pylint: disable=global-at-module-level
SESSION_FILE = CONFIG_PATH + '/' + CONFIG_VALUES['Files']['sessionfile']
global SESSION # pylint: disable=global-at-module-level
SESSION = load_session_config()
# Constant for the current active engagement or blank if none.
global ACTIVE_SESSION # pylint: disable=global-at-module-level
ACTIVE_SESSION = ''
try:
    ACTIVE_SESSION = SESSION['Current']['active']
except (FileNotFoundError, PermissionError, IOError, OSError):
    color_fail(
        'Active Session', 'Failed to assign the active session to global variable.'
    )

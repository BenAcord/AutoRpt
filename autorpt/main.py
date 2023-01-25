#!/usr/bin/python3
"""
autorpt.py
Enforce consistent, dependable workflow for engagement note-taking and report writing.
"""

import os
import re
import sys
import autorpt.cfg as cfg # pylint: disable=import-error,consider-using-from-import
from autorpt.help import helper # pylint: disable=import-error
from autorpt.pretty import banner, clear_screen, color_header, color_subheading # pylint: disable=import-error
from autorpt.pretty import color_menu_item, color_verify, color_fail, color_notice # pylint: disable=import-error
from autorpt.startup import startup # pylint: disable=import-error
from autorpt.finalize import get_pandoc_style, finalize, whathaveidone # pylint: disable=import-error
from autorpt.vulns import vuln, vuln_list # pylint: disable=import-error
from autorpt.cvss import ports # pylint: disable=import-error
from autorpt.work import add_target, add_template # pylint: disable=import-error
from autorpt.work import sitrep_menu, sitrep_list, sitrep_auto # pylint: disable=import-error

def show_version():
    """ Display version information. """
    color_notice(
        f"AutoRpt version v{cfg.CONFIG_VALUES['Version']['autorpt_version']}"
    )
    sys.exit(0)

def get_version():
    """ Return the version information. """
    return f"v{cfg.CONFIG_VALUES['Version']['autorpt_version']}"

def dictionary_to_menu(dictionary):
    """ Helper to convert a dictionary to menu item listing. """
    i = 0
    for item in dictionary.split(','):
        color_menu_item(str(i) + ".  " + item)
        i += 1
    color_menu_item('99 for main menu')
    return i

def section_to_menu(section):
    """ Helper to convert a section to menu item listing. """
    i = 0
    items = []
    for item in section:
        color_menu_item(str(i) + ".  " + section[item])
        items.append(section[item])
        i += 1
    color_menu_item('99 for main menu')
    return items

def list_egagements():
    """ List all engagement names and paths. """
    for engagement_section in cfg.session.sections():
        if engagement_section not in ['DEFAULT', 'Current']:
            color_verify(
                engagement_section, cfg.session[engagement_section]['path']
            )
    settings_menu()

def set_app_working_directory():
    """ Set new engagements working directory """
    color_notice(
        'What is the path to store future engagement subdirectories?'
    )
    user_input = str(input('>  '))
    if not os.path.isdir(user_input):
        color_fail(
            '[!]',
            f'{user_input} is not a valid directory.  Creating...'
        )
        # If umask is not set, incorrect permissions will be assigned on mkdir
        os.umask(0o007)
        try:
            os.mkdir(user_input, 0o770)
        except (FileNotFoundError, PermissionError, IOError, OSError):
            color_fail('[e]', f'Unable to create directory: {user_input} ')
            sys.exit(20)
    cfg.CONFIG_VALUES['Paths']['pathwork'] = user_input
    user_input = ""
    cfg.save_config(cfg.CONFIG_VALUES)

def set_author_name():
    """ Set author name """
    color_menu_item('What is your full name as the report author?')
    user_input = str(input('>  '))
    cfg.CONFIG_VALUES['Settings']['your_name'] = user_input
    user_input = ""
    cfg.save_config(cfg.CONFIG_VALUES)

def set_student_name():
    """ Set student ID """
    color_menu_item('What is your student ID?')
    user_input = str(input('>  '))
    cfg.CONFIG_VALUES['Settings']['studentid'] = user_input
    user_input = ''
    cfg.save_config(cfg.CONFIG_VALUES)

def set_email_address():
    """ Set email address """
    color_menu_item('What is your email address?')
    user_input = str(input('>  '))
    if re.match(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', user_input):
        cfg.CONFIG_VALUES['Settings']['email'] = user_input
        user_input = ''
        cfg.save_config(cfg.CONFIG_VALUES)
    else:
        color_notice('Not an email formatted string.  Try again.')
        settings_menu()

def set_preferred_report_format():
    """ Set preferred report format """
    color_menu_item(
        f"What is your preferred report format?  "
        f"{cfg.CONFIG_VALUES['Settings']['preferred_output_format']}"
    )
    i = 0
    for filetype in cfg.SUPPORTED_FILETYPES.split(','):
        color_menu_item(f'{i}) {filetype}')
        i += 1
    user_input = int(input('>  '))
    if user_input <= i:
        this_value = cfg.SUPPORTED_FILETYPES.split(',')[user_input]
        cfg.CONFIG_VALUES['Settings']['preferred_output_format'] = this_value
        cfg.save_config(cfg.CONFIG_VALUES)
        user_input = ''
    else:
        color_notice('Invalid option.')
        settings_menu()

def set_code_block_style():
    """ Set code block style. """
    this_msg = get_pandoc_style()
    cfg.CONFIG_VALUES['Settings']['style'] = this_msg
    cfg.save_config(cfg.CONFIG_VALUES, cfg.CONFIG_FILE)

def settings_for_application_menu():
    """ Application configuration settings menu """
    # Application-level settings
    picker = 0
    color_subheading('Current Settings')

    color_menu_item(
        f"1) Engagements will be stored in "
        f"{str(cfg.CONFIG_VALUES['Paths']['pathwork'])}"
    )
    color_menu_item(
        f"2) Your name: {str(cfg.CONFIG_VALUES['Settings']['your_name'])}"
    )
    color_menu_item(
        f"3) Your student ID: {str(cfg.CONFIG_VALUES['Settings']['studentid'])}"
    )
    color_menu_item(
        f"4) Your email address: {str(cfg.CONFIG_VALUES['Settings']['email'])}"
    )
    color_menu_item(
        f"5) Preferred report format: "
        f"{str(cfg.CONFIG_VALUES['Settings']['preferred_output_format'])}"
    )
    color_menu_item(
        f"6) Code block style: {str(cfg.CONFIG_VALUES['Settings']['style'])}"
    )
    color_menu_item("7) Settings menu")
    color_menu_item("8) Main menu")
    color_menu_item("\nPick a number to modify its setting")
    picker = int(input('>  '))
    match picker:
        case 1: set_app_working_directory()
        case 2: set_author_name()
        case 3: set_student_name()
        case 4: set_email_address()
        case 5: set_preferred_report_format()
        case 6: set_code_block_style()
        case 7: settings_menu()
        case 8: main_menu()
        case _: main_menu()
    settings_for_application_menu()

def settings_for_session_menu():
    """ Session settings menu """
    # Engagement settings
    color_subheading('Engagement Settings')
    color_notice(
        f"Active engagement: {cfg.SESSION['Current']['active']}"
    )
    #color_notice(f"Total engagement: {str(len(session['Engagements']))}\n")
    color_menu_item('1. Set a new active engagement')
    color_menu_item('2. List all engagements')
    color_menu_item('3. Back to main menu')
    color_menu_item('4. Quit')
    picker = int(input('>  '))
    if picker == 3:
        main_menu()
    elif picker == 4:
        sys.exit(0)
    elif picker > 4:
        settings_menu()
    elif picker == 1:
        i = 0
        engagements = {}
        color_notice('Pick a new active engagement')
        for engagement_section in cfg.SESSION.sections():
            if engagement_section not in ['DEFAULT', 'Current']:
                # Future Feature: Would be nice to exclude finalized items
                color_menu_item(f"{i}) {engagement_section}")
                engagements[i] = engagement_section
                i += 1
        picker = int(input('>  '))
        if picker > i:
            settings_menu()
        else:
            cfg.SESSION['Current']['active'] = engagements[picker]
            cfg.save_engagements(cfg.SESSION)
            settings_menu()
    elif picker == 2:
        list_egagements()

def settings_menu():
    """ Submenu for settings """
    color_header('Settings')
    color_menu_item('1. Application-level settings')
    color_menu_item('2. Engagement settings')
    color_menu_item('3. Back to main menu')
    color_menu_item('4. Quit')
    picker = int(input('>  '))
    match picker:
        case 1: settings_for_application_menu()
        case 2: settings_for_session_menu()
        case 3: main_menu()
        case 4: sys.exit(23)
        case _: settings_menu()

def main_menu():
    """ Primary menu """

    #get_runtime_variables()
    picker = ''
    clear_screen()
    banner()
    color_header('Main Menu')
    color_menu_item('1. Startup')
    color_menu_item('2. Vulnerabilities')
    color_menu_item('3. Ports')
    color_menu_item('4. SitRep Log')
    color_menu_item('5. Finalize')
    color_menu_item('6. Settings')
    color_menu_item('7. Quit')
    picker = int(input('>  '))

    if 1 == picker:
        startup()
    elif 2 == picker:
        vuln()
    elif 3 == picker:
        ports()
    elif 4 == picker:
        sitrep_menu()
    elif 5 == picker:
        finalize()
    elif 6 == picker:
        settings_menu()
    elif 7 == picker:
        sys.exit(0)
    else:
        main_menu()

def add_a_new_target():
    """ Add a new target to the engagement. """
    # Add a new target host to the engagement
    if len(sys.argv) == 3:
        this_msg = sys.argv[2]
    else:
        this_msg = ''
    add_target(this_msg)

def display_vuln_menu():
    """ Show the vulnerability menu. """
    # Record a confirmed vulnerability
    if len(sys.argv) == 3 and 'list' == sys.argv[2]:
        vuln_list()
    else:
        vuln()

def display_sitrep_menu():
    """ Situation report actions """
    if len(sys.argv) == 3 and 'list' == sys.argv[2]:
        sitrep_list()
    elif len(sys.argv) > 3:
        this_msg = " ".join(sys.argv[2:])
        sitrep_auto(this_msg)
    else:
        sitrep_menu()

def params(this_arguments):
    """ Set routing action based on argument.  Otherwise, display help. """

    # Display pretty ASCII art
    banner(get_version())

    if len(this_arguments) >= 3:
        param_directive = str.join(' ', (this_arguments[1], this_arguments[2]))
    else:
        param_directive = this_arguments[1]

    # Configuration settings
    match param_directive:
        case "active": cfg.get_the_active_engagement()
        case "addtarget": add_a_new_target()
        case "addtemplate": add_template()
        case "finalize": finalize()
        case "help": helper()
        case "list": whathaveidone()
        case "ports": ports()
        case "sitrep list": sitrep_list()
        case "sitrep":display_sitrep_menu()
        case "startup": startup()
        case "upgrade": cfg.upgrade_config_file()
        case "version": show_version()
        case "vuln": display_vuln_menu()
        case "whathaveidone": whathaveidone()
        case _: helper()

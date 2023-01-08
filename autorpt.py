#!/usr/bin/python3
"""
autorpt.py
Enforce consistent, dependable workflow for engagement note-taking and report writing.
"""

import os
import re
import sys
import pyperclip as pc
import autorpt_cfg as cfg
import autorpt_pretty as out
import autorpt_vulns_extras as extras
import autorpt_vulns as vulns
import autorpt_work as work
import autorpt_startup as startup
import autorpt_finalize as finalize


def show_version():
    """ Display version information. """
    out.color_notice(
        f"AutoRpt version v{cfg.config_values['Version']['autorpt_version']}"
    )
    sys.exit(0)

def dictionary_to_menu(dictionary):
    """ Helper to convert a dictionary to menu item listing. """
    i = 0
    for item in dictionary.split(','):
        out.color_menu_item(str(i) + ".  " + item)
        i += 1
    out.color_menu_item('99 for main menu')
    return i

def section_to_menu(section):
    """ Helper to convert a section to menu item listing. """
    i = 0
    items = []
    for item in section:
        out.color_menu_item(str(i) + ".  " + section[item])
        items.append(section[item])
        i += 1
    out.color_menu_item('99 for main menu')
    return items

def list_egagements():
    """ List all engagement names and paths. """
    for engagement_section in cfg.session.sections():
        if engagement_section not in ['DEFAULT', 'Current']:
            out.color_verify(engagement_section, cfg.session[engagement_section]['path'])
    settings_menu()

def set_app_working_directory():
    """ Set new engagements working directory """
    out.color_notice('What is the path to store future engagement subdirectories?')
    user_input = str(input('>  '))
    if not os.path.isdir(user_input):
        out.color_fail('[!]', f'{user_input} is not a valid directory.  Creating...')
        # If umask is not set, incorrect permissions will be assigned on mkdir
        os.umask(0o007)
        try:
            os.mkdir(user_input, 0o770)
        except (FileNotFoundError, PermissionError, IOError, OSError):
            out.color_fail('[e]', f'Unable to create directory: {user_input} ')
            sys.exit(20)
    cfg.config_values['Paths']['pathwork'] = user_input
    user_input = ""
    cfg.save_config(cfg.config_values)

def set_author_name():
    """ Set author name """
    out.color_menu_item('What is your full name as the report author?')
    user_input = str(input('>  '))
    cfg.config_values['Settings']['your_name'] = user_input
    user_input = ""
    cfg.save_config(cfg.config_values)

def set_student_name():
    """ Set student ID """
    out.color_menu_item('What is your student ID?')
    user_input = str(input('>  '))
    cfg.config_values['Settings']['studentid'] = user_input
    user_input = ''
    cfg.save_config(cfg.config_values)

def set_email_address():
    """ Set email address """
    out.color_menu_item('What is your email address?')
    user_input = str(input('>  '))
    if re.match(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', user_input):
        cfg.config_values['Settings']['email'] = user_input
        user_input = ''
        cfg.save_config(cfg.config_values)
    else:
        out.color_notice('Not an email formatted string.  Try again.')
        settings_menu()

def set_preferred_report_format():
    """ Set preferred report format """
    out.color_menu_item(
        f"What is your preferred report format?  "
        f"{cfg.config_values['Settings']['preferred_output_format']}"
    )
    i = 0
    for filetype in cfg.supported_filetypes.split(','):
        out.color_menu_item(f'{i}) {filetype}')
        i += 1
    user_input = int(input('>  '))
    if user_input <= i:
        this_value = cfg.supported_filetypes.split(',')[user_input]
        cfg.config_values['Settings']['preferred_output_format'] = this_value
        cfg.save_config(cfg.config_values)
        user_input = ''
    else:
        out.color_notice('Invalid option.')
        settings_menu()

def set_code_block_style():
    """ Set code block style. """
    cfg.config_values['Settings']['style'] = finalize.get_pandoc_style()
    cfg.save_config(cfg.config_values)

def settings_for_application_menu():
    """ Application configuration settings menu """
    # Application-level settings
    picker = 0
    out.color_subheading('Current Settings')

    out.color_menu_item(
        f"1) Engagements will be stored in "
        f"{str(cfg.config_values['Paths']['pathwork'])}"
    )
    out.color_menu_item(
        f"2) Your name: {str(cfg.config_values['Settings']['your_name'])}"
    )
    out.color_menu_item(
        f"3) Your student ID: {str(cfg.config_values['Settings']['studentid'])}"
    )
    out.color_menu_item(
        f"4) Your email address: {str(cfg.config_values['Settings']['email'])}"
    )
    out.color_menu_item(
        f"5) Preferred report format: "
        f"{str(cfg.config_values['Settings']['preferred_output_format'])}"
    )
    out.color_menu_item(
        f"6) Code block style: {str(cfg.config_values['Settings']['style'])}"
    )
    out.color_menu_item("7) Settings menu")
    out.color_menu_item("8) Main menu")
    out.color_menu_item("\nPick a number to modify its setting")
    picker = int(input('>  '))
    out.color_debug(f'User selected {picker}')
    match picker:
        case 1: set_app_working_directory()
        case 2: set_author_name()
        case 3: set_student_name()
        case 4: set_email_address()
        case 5: set_preferred_report_format()
        case 6: set_code_block_style()
        case 7: settings_menu()
        case 8: main_menu()
        case _:
            out.color_debug('Could not find a setting number that matches.')
    settings_for_application_menu()

def settings_for_session_menu():
    """ Session settings menu """
    # Engagement settings
    out.color_subheading('Engagement Settings')
    out.color_notice(f"Active engagement: {cfg.session['Current']['active']}")
    #out.color_notice(f"Total engagement: {str(len(session['Engagements']))}\n")
    out.color_menu_item('1. Set a new active engagement')
    out.color_menu_item('2. List all engagements')
    out.color_menu_item('3. Back to main menu')
    out.color_menu_item('4. Quit')
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
        out.color_notice('Pick a new active engagement')
        for engagement_section in cfg.session.sections():
            if engagement_section not in ['DEFAULT', 'Current']:
                # Future Feature: Would be nice to exclude finalized items
                out.color_menu_item(f"{i}) {engagement_section}")
                engagements[i] = engagement_section
                i += 1
        picker = int(input('>  '))
        if picker > i:
            settings_menu()
        else:
            cfg.session['Current']['active'] = engagements[picker]
            cfg.save_enagements()
            settings_menu()
    elif picker == 2:
        list_egagements()

def settings_menu():
    """ Submenu for settings """
    out.color_header('Settings')
    out.color_menu_item('1. Application-level settings')
    out.color_menu_item('2. Engagement settings')
    out.color_menu_item('3. Back to main menu')
    out.color_menu_item('4. Quit')
    picker = int(input('>  '))
    match picker:
        case 1: settings_for_application_menu()
        case 2: settings_for_session_menu()
        case 3: settings_menu()
        case 4: sys.exit(23)
        case _:
            out.color_debug('Could not find a setting number that matches.')

def main_menu():
    """ Primary menu """
    picker = ''
    out.clear_screen()
    out.banner()
    out.color_header('Main Menu')
    out.color_menu_item('1. Startup')
    out.color_menu_item('2. Vulnerabilities')
    out.color_menu_item('3. Ports')
    out.color_menu_item('4. SitRep Log')
    out.color_menu_item('5. Finalize')
    out.color_menu_item('6. Settings')
    out.color_menu_item('7. Quit')
    picker = int(input('>  '))

    if 1 == picker:
        startup.startup()
    elif 2 == picker:
        vulns.vuln()
    elif 3 == picker:
        extras.ports()
    elif 4 == picker:
        work.sitrep_menu()
    elif 5 == picker:
        finalize.finalize()
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
    work.add_target(this_msg)

def display_vuln_menu():
    """ Show the vulnerability menu. """
    # Record a confirmed vulnerability
    if len(sys.argv) == 3 and 'list' == sys.argv[2]:
        vulns.vuln_list()
    else:
        vulns.vuln()

def display_sitrep_menu():
    """ Situation report actions """
    if len(sys.argv) == 3 and 'list' == sys.argv[2]:
        work.sitrep_list()
    elif len(sys.argv) > 3:
        this_msg = " ".join(sys.argv[2:])
        work.sitrep_auto(this_msg)
    else:
        work.sitrep_menu()

def get_the_active_engagement():
    """ Show the active engagement and path. """

    if 'None' == cfg.session['Current']['active']:
        out.color_notice("No engagements.  Run 'autorpt.py startup' to create an engagement.")
    else:
        out.color_notice("Ready to go!")
        out.color_notice(
            f"Path is in your clipboard: {cfg.session[cfg.session['Current']['active']]['path']}"
        )
        pc.copy(os.path.expanduser(cfg.session[cfg.session['Current']['active']]['path']))

def params(this_arguments):
    """ Set routing action based on argument.  Otherwise, display help. """
    match this_arguments[1]:
        case "addtemplate": work.add_template()
        case "addtarget": add_a_new_target()
        case "help": out.helper()
        case "startup": startup.startup()
        case "finalize": finalize.finalize()
        case "list": finalize.whathaveidone()
        case "whathaveidone": finalize.whathaveidone()
        case "vuln": display_vuln_menu()
        case "sitrep": display_sitrep_menu()
        case "ports": extras.ports()
        case "active": get_the_active_engagement()
        case "upgrade": cfg.upgrade_config_file(cfg.config_file)
        case "version": show_version()
        case _: out.color_debug('Could not find params value in match.')

if __name__ == "__main__":
    # Display pretty ASCII art
    out.banner()
    # Take action based on parameters
    if len(sys.argv) <= 1:
        main_menu()
    else:
        params(sys.argv)

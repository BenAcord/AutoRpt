#!/usr/bin/python3
"""
autorpt_pretty.py
Output formatting functions to make it look really nice.
"""

import os
import random
import subprocess
import blessings

def helper():
    """The CLI help output"""
    print(f"{term.bold_bright_blue}USAGE:{term.normal}")
    print("autorpt.py [option]\n")
    print(f"{term.bold_bright_blue}Where option is one of:{term.normal}")
    print(
        "help | settings | active | "
        "startup | vuln [list] | ports | sitrep [message] | "
        "addtarget [IP Address] | addtemplate | "
        "finalize | list | whathaveidone | upgrade\n"
    )
    print(f"{term.bold_bright_blue}OPTIONS:{term.normal}")
    print(
        f'  {term.bright_blue}help{term.normal}\t\t\t'
        'Display this listing of usage and examples.'
    )
    print(
        f'  {term.bright_blue}startup{term.normal}\t\t'
        'Create a clean working directory for a new engagement.'
    )
    print(
        f'  {term.bright_blue}addtarget{term.normal}\t\t'
        'Add a new IP address to target.md and a markdown file in the active project.'
    )
    print(
        f'  {term.bright_blue}addtemplate{term.normal}\t\t'
        'Add a new, blank markdown template file to the active project report directory.'
    )
    print(
        f'  {term.bright_blue}vuln{term.normal}\t\t\t'
        'Record a confirmed vulnerability with CVSS scoring and MITRE ATT&CK attributes.'
    )
    print(
        f'  {term.bright_blue}ports{term.normal}\t\t\t'
        '(AutoRecon specific) Quick display of all open ports per target.'
    )
    print(
        f'  {term.bright_blue}sitrep{term.normal}\t\t'
        'Record a status update of your current progress or display the menu.'
    )
    print(
        f'  {term.bright_blue}finalize{term.normal}\t\t'
        'Compile markdown files into a desired output file format.'
    )
    print(
        f'  {term.bright_blue}settings{term.normal}\t\t'
        'Configuration settings.'
    )
    print(
        f'  {term.bright_blue}active{term.normal}\t\t'
        'Display the active engagement name and path.'
    )
    print(
        f'  {term.bright_blue}list{term.normal}\t\t\t'
        'Same as whathaveidone.'
    )
    print(
        f'  {term.bright_blue}whathaveidone{term.normal}\t\t'
        'Display measurements summarizing all engagements.'
    )
    print(
        f'  {term.bright_blue}upgrade{term.normal}\t\t'
        'Upgrade existing user config file with latest repo updates.'
    )

    print(f"\n{term.bold_bright_blue}EXAMPLES:{term.normal}")
    print("See the wiki for more detailed examples.")
    print("When you are ready to start an exam or training:")
    print(f"    {term.bright_blue}autorpt.py startup{term.normal}")
    print("Log a verified vulnerability:")
    print(f"    {term.bright_blue}autorpt.py vuln{term.normal}")
    print("Display vulnerability list:")
    print(f"    {term.bright_blue}autorpt.py vuln list{term.normal}")
    print("Log your current status:")
    print(
        f"    {term.bright_blue}autorpt.py sitrep Stuck trying to exploit "
        f"system X:8001/login.php via SQLi.  May be a rabbit trail.{term.normal}"
    )
    print("...Or use the menu system:")
    print(f"    {term.bright_blue}autorpt.py sitrep{term.normal}")
    print("Display the sitrep log:")
    print(f"    {term.bright_blue}autorpt.py sitrep list{term.normal}")
    print("After AutoRecon completes, display the ports:")
    print(f"    {term.bright_blue}autorpt.py ports{term.normal}")
    print("Compile the markdown into a polished report document")
    print(f"    {term.bright_blue}autorpt.py finalize{term.normal}")
    print("Display statistics and status of engagements")
    print(f"    {term.bright_blue}autorpt.py whathaveidone{term.normal}")

    print(f"\n{term.bold_bright_blue}WORKFLOW STATUS:{term.normal}")
    print(
        f"[{term.bright_green}Started{term.normal}] -> "
        f"[{term.bright_yellow}In-Progress{term.normal}] -> "
        f"[{term.bright_red}Finalized{term.normal}]"
    )
    print(" │            │                │")
    print(" │            │                │")
    print(" │            │                └──(3) Report complete. After action report optional")
    print(" │            │")
    print(" │            └──(2) Activity underway (e.g. Ports, Sitrep, Vuln)")
    print(" │")
    print(" └──(1) Initial creation of engagement")
    raise SystemExit(1)

def banner():
    """Display required ASCII art and random motto"""
    this_msg = ""
    mottos = ['Train like you PenTest',
            'Persistently consistent',
            'We PenTest like we train',
            'Consistency is the key',
            'Train like you exam like you PenTest',
            'Tag your work',
            'Documentation is never perfect,\nit simply runs out of time',
            'Consistent, dependable, and improving']
    max_size = len(mottos) - 1
    random_message_id = random.randint(0, max_size)
    this_msg = mottos[random_message_id]
    print('')
    print('  ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄   ▄▄▄·▄▄▄▄▄ ')
    print(' ▐█ ▀█ █▪██▌•██  ▪     ▀▄ █·▐█ ▄█•██   ')
    print(' ▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄ ▐▀▀▄  ██▀· ▐█.▪ ')
    print(' ▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█•█▌▐█▪·• ▐█▌· ')
    print('  ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀  ▀.▀    ▀▀▀  ')
    print(f'{term.bright_blue}{this_msg.center(40)}{term.normal}\n')

def clear_screen():
    """Function to clear screen text"""
    _ = subprocess.call('clear' if os.name == 'posix' else 'cls')

def color_header(this_msg):
    """Function to format header text"""
    print(f"\n{term.bold_bright_blue}{this_msg}{term.normal}\n")

def color_subheading(this_msg):
    """Function to format subheader text"""
    print(f"{term.bold_bright_blue}{this_msg}{term.normal}")

def color_menu_item(this_msg):
    """Function to format menu item text"""
    print(f"  {term.yellow}{this_msg}{term.normal}")

def color_list(this_msg):
    """Function to format lists"""
    print(f"{term.bold_bright}{this_msg}{term.normal}")

def color_debug(this_msg):
    """Function to format debug text"""
    print(
        f"{term.on_yellow}{term.black}[d]{term.normal}  "
        f"{term.yellow}{this_msg}{term.normal}"
    )

def color_table_header(this_msg):
    """Function to format table headers"""
    print(
        f"{term.on_blue_underline_bold}{term.bright_white}{this_msg}{term.normal}"
    )

def color_verify(field, this_msg):
    """Function to format verification text"""
    print(
        f'{term.red}{field}{term.normal}  '
        f'{term.bold_bright}{this_msg}{term.normal}'
    )

def color_warn(this_msg):
    """Function to format warning text"""
    print(
        f'{term.bold_on_bright_yellow}[W]{term.normal}  '
        f'{term.bold_bright_yellow}{this_msg}{term.normal}'
    )

def color_pass(field, this_msg):
    """Function to format passing, good text"""
    print(
        f'{term.bold_on_bright_green}[P]{term.normal}  '
        f'{term.bold_bright_green}{field} {this_msg}{term.normal}'
    )

def color_fail(field, this_msg):
    """Function to format failed, bad text"""
    print(
        f'{term.bold_on_bright_red}[E]{term.normal}  '
        f'{term.bold_bright_red}{field} {this_msg}{term.normal}'
    )

def color_notice(this_msg):
    """Function to format a informational notice text"""
    print(f"{term.bright}{this_msg}{term.normal}")

# Define a terminal for color sugar
term = blessings.Terminal(kind='xterm-256color')

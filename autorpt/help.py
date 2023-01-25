#!/usr/bin/python3
"""
help.py
A help file contain syntax and usage examples.
"""

import sys
import blessings

def helper():
    """ The CLI help output """
    # Define a terminal for color sugar
    term = blessings.Terminal(kind='xterm-256color')

    # Display the help text
    print(
        f"{term.bold_bright_blue}USAGE:{term.normal}\n"
        "autorpt.py [option]\n\n"

        f"{term.bold_bright_blue}Where option is one of:{term.normal}\n"
        "help | settings | active | "
        "startup | vuln [list] | ports | sitrep [message] |\n"
        "addtarget [IP Address] | addtemplate | "
        "finalize | list | whathaveidone | upgrade\n"
    )

    print(
        f"{term.bold_bright_blue}OPTIONS:{term.normal}\n"

        f'  {term.bright_blue}help{term.normal}\t\t\t'
        'Display this listing of usage and examples.\n'

        f'  {term.bright_blue}startup{term.normal}\t\t'
        'Create a clean working directory for a new engagement.\n'

        f'  {term.bright_blue}addtarget{term.normal}\t\t'
        'Add a new IP address to target.md and a markdown file in the active project.\n'

        f'  {term.bright_blue}addtemplate{term.normal}\t\t'
        'Add a new, blank markdown template file to the active project report directory.\n'

        f'  {term.bright_blue}vuln{term.normal}\t\t\t'
        'Record a confirmed vulnerability with CVSS scoring and MITRE ATT&CK attributes.\n'

        f'  {term.bright_blue}ports{term.normal}\t\t\t'
        '(AutoRecon specific) Quick display of all open ports per target.\n'

        f'  {term.bright_blue}sitrep{term.normal}\t\t'
        'Record a status update of your current progress or display the menu.\n'

        f'  {term.bright_blue}finalize{term.normal}\t\t'
        'Compile markdown files into a desired output file format.\n'

        f'  {term.bright_blue}settings{term.normal}\t\t'
        'Configuration settings.\n'

        f'  {term.bright_blue}active{term.normal}\t\t'
        'Display the active engagement name and path.\n'

        f'  {term.bright_blue}list{term.normal}\t\t\t'
        'Same as whathaveidone.\n'

        f'  {term.bright_blue}whathaveidone{term.normal}\t\t'
        'Display measurements summarizing all engagements.\n'

        f'  {term.bright_blue}upgrade{term.normal}\t\t'
        'Upgrade existing user config file with latest repo updates.\n'
    )

    print(
        f"\n{term.bold_bright_blue}EXAMPLES:{term.normal}\n"

        "See the wiki for more detailed examples:\n\thttps://github.com/BenAcord/AutoRpt/wiki\n\n"

        "When you are ready to start an exam or training:\n"
        f"    {term.bright_blue}autorpt.py startup{term.normal}\n"
        "Log a verified vulnerability:\n"
        f"    {term.bright_blue}autorpt.py vuln{term.normal}\n"
        "Display vulnerability list:\n"
        f"    {term.bright_blue}autorpt.py vuln list{term.normal}\n"
        "Log your current status:\n"
        f"    {term.bright_blue}autorpt.py sitrep Stuck trying to exploit "
        f"system X:8001/login.php via SQLi.  May be a rabbit trail.{term.normal}\n"
        "...Or use the menu system:\n"
        f"    {term.bright_blue}autorpt.py sitrep{term.normal}\n"
        "Display the sitrep log:\n"
        f"    {term.bright_blue}autorpt.py sitrep list{term.normal}\n"
        "After AutoRecon completes, display the ports:\n"
        f"    {term.bright_blue}autorpt.py ports{term.normal}\n"
        "Compile the markdown into a polished report document\n"
        f"    {term.bright_blue}autorpt.py finalize{term.normal}\n"
        "Display statistics and status of engagements\n"
        f"    {term.bright_blue}autorpt.py whathaveidone{term.normal}\n"
    )

    print(
        f"\n{term.bold_bright_blue}WORKFLOW STATUS:{term.normal}\n"
        f"[{term.bright_green}Started{term.normal}] -> "
        f"[{term.bright_yellow}In-Progress{term.normal}] -> "
        f"[{term.bright_red}Finalized{term.normal}]\n"
        " │            │                │\n"
        " │            │                │\n"
        " │            │                └──(3) Report complete, after action report optional\n"
        " │            │                       (e.g. finalize)\n"
        " │            └──(2) Activity underway\n"
        " │                   (e.g. ports, sitrep, vuln)\n"
        " └──(1) Initial creation of engagement\n"
        "        (e.g. startup)\n"
    )
    raise sys.exit(0)

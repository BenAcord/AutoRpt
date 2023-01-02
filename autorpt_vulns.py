#!/usr/bin/python3
"""
autorpt.py
Enforce consistent, dependable workflow for engagement note-taking and report writing.
"""

import os
import sys
import time
import pandas as pd
import autorpt_vulns_extras as extras
import autorpt as core
import autorpt_cfg as cfg
import autorpt_pretty as out
import autorpt_work as work

def vuln():
    """Menu for vulnerabilities"""
    out.color_header('Vulnerabilities')
    out.color_menu_item("1. Add a new vulnerability")
    out.color_menu_item("2. List all vulnerabilities")
    out.color_menu_item("3. Modify an existing vulnerability")
    out.color_menu_item("4. Remove a vulnerability\n")
    out.color_menu_item('5. Main Menu')
    out.color_menu_item("6. quit")
    vuln_selection = int(input("> "))
    if 1 == vuln_selection:
        add_vuln()
    elif 2 == vuln_selection:
        vuln_list()
    elif 3 == vuln_selection:
        modify_vuln()
    elif 4 == vuln_selection:
        remove_vuln()
    elif 5 == vuln_selection:
        core.main_menu()
    elif 6 == vuln_selection:
        raise SystemExit(0)
    else:
        vuln()

def add_vuln():
    """Manually prompt for details of a validated vulnerability."""
    out.color_header("Add Vulnerability")
    i = 0
    target = ""
    target_file = f"{cfg.get_active_path()}/{cfg.targets_file}"
    out.color_debug(f'Target File: {target_file}')
    if os.path.isfile(target_file):
        out.color_notice("For which target?\nOr '99' to go back to the menu.")
        with open(target_file) as target_file_writer: # pylint: disable=unspecified-encoding
            targets = target_file_writer.readlines()
            target_file_writer.close()
        for target in targets:
            target = target.strip()
            #print(f'  {i}.  {term.yellow}{target}{term.normal}')
            out.color_menu_item(f"{i}.  {target}")
            i = i + 1
        target_id = int(input(">  "))
        if 99 == target_id:
            vuln()
        else:
            target = targets[target_id].strip()
    else:
        out.color_fail(
            'Add Vuln',
            'targets file is empty. Please add IP addresses to the targets file.'
        )
        vuln()

    out.color_notice("What is the port number [0-65535]?")
    port = int(input('>  '))
    if port < 1 or port > 65535:
        out.color_notice("Number is outside the range of acceptable port numbers: 0 - 65535.")
        vuln()

    out.color_notice(
        "What is the name for this vulnerability?\n"
        "(eg. Remote code injection in Vendor_Product_Component)"
    )
    vuln_name = str(input('>  '))

    out.color_notice("Describe the business impact: ")
    vuln_impact = str(input('>  '))

    out.color_notice("What is the remediation?")
    remediation = str(input('>  '))

    out.color_notice("Do you have a comment for where you left off? ")
    vuln_comment = str(input('>  '))
    if len(vuln_comment) > 0:
        work.sitrep_auto(vuln_comment)
    # Wrap with double-quotes as the list has commas and single-quotes.
    raw_cvss = extras.get_cvss3_score()
    mitre_attack = extras.get_mitre_attack()

    user_input_values = [
        target,
        port,
        vuln_name,
        vuln_impact,
        remediation,
        vuln_comment,
        raw_cvss[1],
        raw_cvss[0],
        raw_cvss[2],
        mitre_attack[0],
        mitre_attack[1]
    ]
    verify_values(user_input_values)

    # Return to the vulnerability menu
    vuln()

def verify_values(user_input_values):
    """ Confirm the user supplied values match what they want to log. """
    out.color_notice("\n-----------------\n  Verify the data entered.\n-----------------")
    out.color_verify('[Target]                ', user_input_values[0])
    out.color_verify('[Port]                  ', user_input_values[1])
    out.color_verify('[Name]                  ', user_input_values[2])
    out.color_verify("[Business Impact]       ", user_input_values[3])
    out.color_verify("[Remediation]           ", user_input_values[4])
    out.color_verify("[Comment]               ", user_input_values[5])
    out.color_verify("[CVSS Overall Score]    ", user_input_values[6])
    out.color_verify("[CVSS Severity]         ", user_input_values[7])
    out.color_verify("[CVSS Vector]           ", user_input_values[8])
    out.color_verify('[MITRE ATT&CK Tactic]   ', user_input_values[9])
    out.color_verify('[MITRE ATT&CK Technique]', user_input_values[10])

    check_point = str(input("\nAre these values correct? [Y|N]  > ")).upper()
    if check_point == "Y":
        row  = f'{user_input_values[0]},{user_input_values[1]},'
        row += f'{user_input_values[2]},{user_input_values[3]},'
        row += f'{user_input_values[4]},{user_input_values[5]},'
        row += f'{user_input_values[6]},{user_input_values[7]},'
        row += f'{user_input_values[8]},{user_input_values[9]},{user_input_values[10]}'
        add_new_vuln_csv_row(row)
    else:
        print("[!] Reseting values")
        target = '' # pylint: disable=unused-variable
        port = '' # pylint: disable=unused-variable
        vuln_name = '' # pylint: disable=unused-variable
        raw_cvss = [] # pylint: disable=unused-variable
        vuln_impact = '' # pylint: disable=unused-variable
        remediation = '' # pylint: disable=unused-variable
        vuln_comment = '' # pylint: disable=unused-variable
        raw_cvss = '' # pylint: disable=unused-variable
        mitre_attack = [] # pylint: disable=unused-variable
        add_vuln()

def add_new_vuln_csv_row(row):
    """Formats the vulnerability row and stores in the spreadsheet."""
    vulns_file =  f"{cfg.get_active_path()}/report/{cfg.vulnsCsv}"
    if not os.path.isfile(vulns_file):
        headings = 'IpAddress,Port,'
        headings += 'Name,Impact,Remediation,Comment'
        headings += ',CvssScore,CvssSeverity,CvssVector'
        headings += ',MitreTactic,MitreTechnique'
        with open(vulns_file, 'a', encoding='utf-8') as vulns_file_writer:
            vulns_file_writer.write(headings + "\n")
            vulns_file_writer.write(row)
            vulns_file_writer.write("\n")
            vulns_file_writer.close()
    else:
        with open(vulns_file, 'a', encoding='utf-8') as vulns_file_writer:
            vulns_file_writer.write(row)
            vulns_file_writer.write("\n")
            vulns_file_writer.close()
    this_msg = f'Added new vulnerability: {str(row)}'
    work.sitrep_auto(this_msg)

def vuln_list():
    """Displays a list of current vulnerabilities from the spreadsheet."""
    out.color_header("List of Current Vulnerabilities")
    vulns_file =  f"{cfg.get_active_path()}/report/{cfg.vulnsCsv}"
    if os.path.exists(vulns_file):
        this_dataframe = pd.read_csv(vulns_file, sep=",", engine="python") # , index_col=False
        out.color_list(this_dataframe.to_markdown())
    else:
        print("0 vulnerabilities")
    if len(sys.argv) == 3 and 'list' == sys.argv[2]:
        sys.exit(0)
    else:
        vuln()

def modify_vuln():
    """Modify a vulnerability"""
    print("\n")
    vulns_file =  f"{cfg.get_active_path()}/report/{cfg.vulnsCsv}"
    try:
        vulns_file_data = pd.read_csv(vulns_file)
    except (FileNotFoundError, PermissionError, IOError, OSError):
        out.color_notice('No vulnerabilities logged to modify.')
        vuln()
    headings = list(vulns_file_data.columns.values)
    out.color_list(vulns_file_data.to_markdown())
    vuln_id = int(input("\nPick an entry to modify or '99' to go back to the menu:  "))
    if 99 == vuln_id:
        vuln()
    print("\n" + str(headings))
    field_id = str(input("Type a column name to modify or '99' to go back to the menu:  "))
    if '99' == field_id:
        vuln()
    if field_id not in headings:
        print("INVALID HEADING")
        vuln()
    if 'CVSS' == field_id:
        new_value = float(input("What is the new value?  "))
    else:
        new_value = str(input('What is the new value?  '))
    vulns_file_data.at[vuln_id, field_id] = new_value
    print(vulns_file_data)
    this_msg = (
        f"Modified vulnerability {field_id} "
        f"to: {new_value} for {str(vulns_file_data.at[vuln_id, 'Name'])}"
    )
    out.color_notice(this_msg)
    work.sitrep_auto(this_msg)
    with open(vulns_file, 'w', newline='') as vulns_file_writer: # pylint: disable=unspecified-encoding
        vulns_file_data.to_csv(vulns_file_writer, index=False)
        vulns_file_writer.close()
    time.sleep(2)
    vuln()

def remove_vuln():
    """Remove a stored vulnerability"""

    print("\n")
    vulns_file =  f"{cfg.get_active_path()}/report/{cfg.vulnsCsv}"
    try:
        vulns_file_data = pd.read_csv(vulns_file)
    except (FileNotFoundError, PermissionError, IOError, OSError):
        out.color_notice('No vulnerabilities logged to modify.')
        vuln()
    out.color_list(vulns_file_data.to_markdown())
    vuln_id = int(input("\nPick an entry to modify or '99' to go back to the menu:  "))
    if 99 == vuln_id:
        vuln()
    elif 0 <= vuln_id <= len(vulns_file_data):
        vulns_file_data.drop([vulns_file_data.index[vuln_id]], axis="index", inplace=True)

    this_msg = (f"Removed vulnerability ID {vuln_id}")
    out.color_notice(this_msg)
    work.sitrep_auto(this_msg)
    with open(vulns_file, 'w', newline='') as vulns_file_writer: # pylint: disable=unspecified-encoding
        vulns_file_data.to_csv(vulns_file_writer, index=False)
        vulns_file_writer.close()
    time.sleep(2)
    vuln()

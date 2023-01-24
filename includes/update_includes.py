#!/usr/bin/python3
"""
Automate the process of maintaining a current list of MITRE ATT&CK
"T" IDs, Tactics, and Techniques.
"""

import os
import sys
import configparser
import fnmatch
import hashlib
import csv
import re
import shutil
import ijson
import requests
import blessings
term = blessings.Terminal(kind='xterm-256color')

def out_header(msg):
    """ Format the header """
    print(f"\n{term.bold}{term.bright_black}{term.on_bright_white}{msg}{term.normal}\n")

def out_subheading(msg):
    """ Format subheadings """
    print(f"{term.on_bright_blue}{msg}{term.normal}")

def out_menu_item_bold(msg):
    """ Format menu items that need bold """
    print(f"  {term.bold_bright_green}{msg}{term.normal}")

def out_menu_item(msg):
    """ Format menu items """
    print(f"  {term.bright_green}{msg}{term.normal}")

def out_list(msg):
    """ Format list """
    print(f"{term.bright_yellow}{msg}{term.normal}")

def out_debug(msg):
    """ Format debug output """
    print(
        f"{term.on_yellow}{term.black}[d]{term.normal}  {term.yellow}{msg}{term.normal}"
    )

def out_table_header(msg):
    """ Format table header """
    print(f"{term.on_blue_underline_bold}{term.bright_white}{msg}{term.normal}")

def out_verify(field, msg):
    """ Format line verifying content """
    print(
        f'{term.bright_white_bold_on_blue} {field} '
        f'{term.normal}  {term.yellow}{msg}{term.normal}'
    )

def out_pass(field, msg):
    """ Format a good pass line output """
    print(
        f'{term.white_bold_on_bright_green} '
        f'{field} {term.normal}  '
        f'{term.bright_green}{msg}{term.normal}'
    )

def out_fail(field, msg):
    """ Format a bad failed line output """
    print(
        f'{term.bright_white_bold_on_bright_red} '
        f'{field} {term.normal}  '
        f'{term.bright_red}{msg}{term.normal}'
    )

def out_notice(msg):
    """ Format a simple notice message """
    print(f"{term.yellow}{msg}{term.normal}")

def helper():
    """ Usage information. """
    print("Update the local MITRE ATT&CK framwork files from MITRE CTI GitHub\n")
    print("Usage: update-includes.py")
    sys.exit(0)

def attack_remove_deprecated(stix_objects):
    """ Drop deprecated items. """
    # Taken from:
    #https://github.com/mitre/cti/blob/master/USAGE.md#getting-techniques-or-sub-techniques
    # Remove any revoked or deprecated objects from queries made to the data source.
    # Note we use .get() because the property may not be present in the JSON data.
    # The default is False if the property is not set.
    return list(
        filter(
            lambda x: x.get(
                "x_mitre_deprecated", False
            ) is False and x.get(
                "revoked", False
            ) is False,
            stix_objects
        )
    )

def parse_attack_json(json_filename):
    """ Convert JSON content into a simplified format. """
    out_subheading(f'[    Parsing {json_filename}    ]')
    attack_csv = []
    out_notice(f'Parsing {json_filename}')
    with open(json_filename, "rb") as json_handle:
        objects = ijson.items(json_handle, 'objects.item')
        records = (
            o for o in objects if o['type'] == 'attack-pattern'
        )
        for record in records:
            # Skip the two means of deprecating a technique.
            if 'x_mitre_is_subtechnique' in record.keys():
                if record['x_mitre_is_subtechnique'] is True:
                    continue
            if 'revoked' in record.keys():
                if record['revoked'] is True:
                    continue
            tactic_id       = record['external_references'][0]['external_id']
            tactic    = record['kill_chain_phases'][0]['phase_name']
            technique = record['name']
            #out_debug(f"tactic_id: {tactic_id}\ttactic: {tactic}\ttechnique: {technique}")
            attack_csv.append([tactic_id, tactic, technique])
    autorpt_filename = 'autorpt-' + (json_filename).replace('.json', '.csv')
    out_notice(f'AutoRpt CSV Filename: {autorpt_filename}')
    out_notice(f'Attack CSV Rows: {len(attack_csv)}')
    with open(autorpt_filename, 'w', newline='', encoding='utf8') as csv_file:
        csv_writer = csv.writer(
            csv_file,
            delimiter=',',
            #quotechar='',
            quoting=csv.QUOTE_MINIMAL
        )
        # Write CSV header.
        row = ['TID', 'TACTIC', 'TECHNIQUE']
        csv_writer.writerow(row)
        # Write rows values.
        for row in attack_csv:
            csv_writer.writerow(row)

def auto_verify_attack_csv():
    """ A spot test to verify the content and query for each attack csv file. """
    tactic_id = ''
    tactic = ''
    technique = ''
    out_header("    Verifying AutoRpt Attack CSV Files    ")
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    csv_files = []

    for name in files:
        if name.endswith(".csv") and re.match(r'autorpt-.*-attack.csv', str(name)):
            csv_files.append(name)

    if 0 == (len(csv_files)):
        out_notice('No files found')
        sys.exit(10)

    out_notice(f'Number of csv_files: {len(csv_files)}')
    i = 0
    for this_csv in csv_files:
        if "enterprise" in this_csv:
            out_notice(f"{i})\t{this_csv}")

            # Get Enterprise framework
            picker = i
            file = csv_files[picker]

            try:
                if re.search(r"^autorpt-enterprise-attack.csv$", str(file)):
                    with open(file, newline='', encoding='utf8') as csvfile:
                        spamreader = csv.reader(csvfile, delimiter=',')
                        for row in spamreader:
                            tactic_id = row[0]
                            tactic = row[1]
                            technique = row[2]
                            if tactic_id == 'T1190':
                                out_pass(
                                    'Verification PASS ',
                                    f"ID: {tactic_id} Tactic: {tactic} Technique: {technique}"
                                )
                else:
                    out_notice(
                        'Unable to find T1190 in autorpt-enterprise-attack.csv!  '
                        'It may have been deprecated or the update failed.'
                    )
            except (PermissionError, IOError, FileNotFoundError):
                out_fail(
                    'Verification Failed ',
                    f"Tactic: {tactic} Technique: {technique}"
                )
        i = i + 1

def download_mitre_attack_json_files():
    """ Download the ATT&CK files in JSON format. """
    out_header('[    Downloading Latest JSON Files from the MITRE ATT&CK GitHub    ]')
    for url in allUrls:
        local_filename = os.path.basename(url)
        framework = local_filename.replace('-attack.json', '')
        out_notice(f'Local Filename: {local_filename}\tframework: {framework}')

        # Get the latest JSON file from GitHub
        try:
            request_response = requests.get(url, timeout=90)
        except (PermissionError, IOError, FileNotFoundError):
            msg = 'Unable to download {url}'
            out_notice(msg)
            sys.exit(1)

        # Calculate sha256sum for the downloaded file
        # and store the digest in the latest config value
        config['Latest'][framework] = hashlib.sha256(request_response.content).hexdigest()

        # If latest sum is different than current parse latest to update current
        if config['Current'][framework] != config['Latest'][framework]:
            with open (local_filename, 'wb') as json_to_disk:
                # Write the json file to disk for parsing
                try:
                    json_to_disk.write(request_response.content)
                except (PermissionError, IOError, FileNotFoundError):
                    msg = 'Unable to write to {localFileName}'
                    out_notice(msg)
                    sys.exit(2)

                config['Current'][framework] = config['Latest'][framework]
                try:
                    with open(updateConfigFile, 'w', encoding='utf8') as config_file_writer: # pylint: disable=unspecified-encoding
                        config.write(config_file_writer)
                except (PermissionError, IOError):
                    out_fail(
                        'Save Config',
                        "Failed to save the updated values to the user config.toml file."
                    )
                    sys.exit(3)
            parse_attack_json(local_filename)
        else:
            out_pass('Download', f'{framework} is already up-to-date.')

def remove_mitre_attack_json_files():
    """ Remove files. """
    out_header('[    Removing JSON Files    ]')
    for name in os.listdir('.'):
        if fnmatch.fnmatch(name, '*-attack.json'):
            out_notice(f'Removing: {name}')
            os.remove(name)

def download_eisvogel_template(this_template):
    """ Download the latest Eisvogel template. """
    url_filename = os.path.basename(this_template)
    if "LICENSE" in url_filename:
        local_filename = 'eisvogel.LICENSE'
        base_name = local_filename
    else:
        local_filename = url_filename.replace('.tex', '.latex')
        base_name = url_filename.replace('.tex', '')
    target_filename = (
        f"{os.path.expanduser('~/.local/share/pandoc/templates/')}"
        f"{local_filename}"
    )
    out_header(f"[    Downloading Latest {base_name} from Wandmalfarbe's GitHub    ]")

    # HTTP GET Request.
    try:
        request_response = requests.get(this_template, timeout=90)
    except (PermissionError, IOError, FileNotFoundError):
        out_notice(f'Unable to download {this_template}')
        sys.exit(1)

    # Calculate sha256sum for the downloaded file
    # and store the digest in the latest config value
    print("[i] Generating the hash for the latest file...")
    config['Latest'][base_name] = hashlib.sha256(request_response.content).hexdigest()

    # If latest sum is different than current parse latest to update current
    if (
        #not config['Current'][base_name] or
        not config.has_option('Current', base_name) or
        config['Current'][base_name] != config['Latest'][base_name]
    ):
        print("[i] Changes exist.  Writing the latest template to disk.")
        with open (local_filename, 'wb') as to_disk:
            try:
                to_disk.write(request_response.content)
            except (PermissionError, IOError, FileNotFoundError):
                out_notice(f'Unable to write to {local_filename}')
                sys.exit(2)

            config['Current'][base_name] = config['Latest'][base_name]
            try:
                with open(updateConfigFile, 'w', encoding='utf8') as config_file_writer:
                    config.write(config_file_writer)
            except (PermissionError, IOError):
                out_fail(
                    'Save Config',
                    "Failed to save the updated values to the user config.toml file."
                )
                sys.exit(3)
        out_pass('Copying file', f"{target_filename}")
        try:
            shutil.copy(local_filename, target_filename)
        except (PermissionError, IOError, FileNotFoundError):
            out_fail("Unable to write", target_filename)
            sys.exit(3)
    else:
        out_pass('Download', f'{local_filename} is already up-to-date.')


if __name__ == "__main__":
    # Get the script home starting directory
    autorpt_runfrom = os.path.dirname(os.path.realpath(__file__))
    GITHUB_BASE_URL = 'https://raw.githubusercontent.com/'
    EISVOGEL_BASE = f'{GITHUB_BASE_URL}Wandmalfarbe/pandoc-latex-template/master/'
    github_eisvogel = f'{EISVOGEL_BASE}eisvogel.tex'
    github_eisvogel_license = f'{EISVOGEL_BASE}LICENSE'
    github_mitre = f'{GITHUB_BASE_URL}mitre/cti/master'
    url_enterprise = f'{github_mitre}/enterprise-attack/enterprise-attack.json'
    url_mobile = f'{github_mitre}/mobile-attack/mobile-attack.json'
    url_ics = f'{github_mitre}/ics-attack/ics-attack.json'
    allUrls = [url_enterprise, url_mobile, url_ics]
    updateConfigFile = f'{autorpt_runfrom}/update.toml'
    config = configparser.ConfigParser()
    config.read(updateConfigFile)

    # Download the latest Eisvogel template.
    download_eisvogel_template(github_eisvogel)
    download_eisvogel_template(github_eisvogel_license)

    # Download the latest MITRE CTI GitHub JSON files
    download_mitre_attack_json_files()
    # Validate the new CSV files
    auto_verify_attack_csv()
    # Remove local JSON files.  Too big.
    remove_mitre_attack_json_files()

#!/usr/bin/python3

import os
import sys
import configparser
import fnmatch
import hashlib
import json
import pandas as pd
import re
import requests
#import shutil
#import urllib.request
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
        f'{term.black_bold_on_bright_green} '
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

def attack_get_techniques(thesrc, include="techniques"):
    """ Filter MITRE ATT&CK. """
    # Taken from:
    #https://github.com/mitre/cti/blob/master/USAGE.md#getting-techniques-or-sub-techniques
    """Filter Techniques or Sub-Techniques from ATT&CK Enterprise Domain.
    include argument has three options: "techniques", "subtechniques", or "both"
    depending on the intended behavior."""
    if include == "techniques":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', False)
        ])
    elif include == "subtechniques":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', True)
        ])
    elif include == "both":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern')
        ])
    else:
        raise RuntimeError("Unknown option %s!" % include)

    return query_results

def attack_remove_deprecated(stix_objects):
    """ Drop deprecated items. """
    # Taken from:
    #https://github.com/mitre/cti/blob/master/USAGE.md#getting-techniques-or-sub-techniques
    """Remove any revoked or deprecated objects from queries made to the data source"""
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

def parse_attack_json():
    """ Convert the files into a simplified format. """
    out_header('[    Parse JSON Files from MITRE ATT&CK    ]')
    # Get the list of downloaded JSON files
    allFiles = []
    frameworkNames = []
    attackJson = []
    for root, dirs, files in os.walk(autorpt_runfrom):
        for name in files:
            if re.search("json", name):
                allFiles.append(name)
                frameworkNames.append(name.replace('-attack.json', ''))

    if len(allFiles) == 0:
        out_notice('Current files are latest.')
        sys.exit(50)

    # Process each JSON file
    for file in allFiles:
        out_notice(f'Parsing {file}')
        if not os.path.isfile(file):
            out_notice(f'Cannot find file {file}')
            sys.exit(2)
        with open(file) as f:
            try:
                attackJson = json.load(f)
            except:
                out_notice(f'Unable to read file {file}')
        autorptFilename = 'autorpt-' + (file).replace('.json', '.csv')
        df = pd.DataFrame({})
        tId = ''
        # ICS does not have x_mitre_is_subtechnique
        if not file.find("ics") != -1:
            for item in attackJson['objects']:
                if 'x_mitre_is_subtechnique' in item:
                    if not item["x_mitre_is_subtechnique"]:
                        for ref in  item['external_references']:
                            if 'external_id' in ref and re.match(
                                'T[\d+]{4}',
                                str(ref['external_id'])
                            ) is not None:
                                tId = str(ref['external_id'])
                        for phase in item['kill_chain_phases']:
                            if phase != 'mitre-attack':
                                newRow = {
                                    'TID': tId,
                                    'TACTIC': str(phase['phase_name']),
                                    'TECHNIQUE': str(item['name'])
                                }
                                df = df.append(newRow, ignore_index = True)
        else:
            for item in attackJson['objects']:
                if 'type' in item:
                    if 'kill_chain_phases' in item and 'external_references' in item:
                        for ref in  item['external_references']:
                            if 'external_id' in ref and re.match(
                                'T[\d+]{4}',
                                str(ref['external_id'])
                            ) is not None:
                                tId = str(ref['external_id'])
                        for phase in item['kill_chain_phases']:
                            if phase != 'kill_chain_name':
                                newRow = {
                                    'TID': tId,
                                    'TACTIC': str(phase['phase_name']),
                                    'TECHNIQUE': str(item['name'])
                                }
                                df = df.append(newRow, ignore_index = True)
                else:
                    out_debug('Type not in item')
        df.sort_values(['TACTIC','TECHNIQUE'], inplace=True)
        out_notice(f"Creating {autorptFilename}")
        try:
            # Write the new CSV file
            with open(autorptFilename, 'w', newline='') as f:
                df.to_csv(f, index=False)
            # Set the latest sha256sum as current
            for url in allUrls:
                framework = os.path.basename(url).replace('-attack.json', '')
                config['Current'][framework] = config['Latest'][framework]
            # Save the new update file
            with open(updateConfigFile, 'w') as configFile:
                config.write(configFile)
        except:
            out_notice(f'Unable to write to {autorptFilename}')
    return None

def auto_verify_attack_csv():
    """ A spot test to verify the content and query for each attack csv file. """
    tactic = ''
    technique = ''
    out_header("    Verifying AutoRpt Attack CSV Files    ")
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    csvFiles = []
    for name in files:
        if name.endswith(".csv") and re.match(r'autorpt-.*-attack.csv', str(name)):
            csvFiles.append(name)
    if 0 == (len(csvFiles)):
        out_notice('No files found')
        sys.exit(10)
    # Get Enterprise framework
    picker = 3
    file = csvFiles[picker]

    try:
        if re.search(r"^autorpt-enterprise-attack.csv$", str(file)):
            matrix = re.match(r"^autorpt-(\W+)-attack.csv$", str(file))
            df = pd.read_csv(file, index_col=False, engine="python")

            tactics = df.TACTIC.unique()
            picker = 8 # initial access
            tactic = tactics[picker]

            techniques = df.query(f'TACTIC == "{tactic}"')[['TECHNIQUE']]
            picker = 1 # Exploit Public-Facing Application
            technique = techniques.iloc[picker, 0]

            out_pass(
                'Verification PASS ',
                f"Tactic: {tactic} Technique: {technique}"
            )
        else:
            out_notice('Unable to find autorpt-enterprise-attack.csv!')
    except:
        out_fail(
            'Verification Failed ',
            f"Tactic: {tactic} Technique: {technique}"
        )
    return tactic, technique

def verify_attack_csv():
    """ A spot test to verify the content and query for each attack csv file. """
    tactic = ''
    technique = ''
    out_header("[    Verifying AutoRpt Attack CSV Files    ]")
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    csvFiles = []
    for name in files:
        if name.endswith(".csv") and re.match(r'autorpt-.*-attack.csv', str(name)):
            csvFiles.append(name)
    if 0 == (len(csvFiles)):
        out_notice('No files found')
        sys.exit(10)
    i = 0
    out_notice('Which MITRE ATT&CK Framework applies?   Press 99 for main menu.')
    for file in csvFiles:
        out_menu_item(f'{i}. {file[8:-11]}')
        i = i + 1
    picker = int(input('>  '))
    if 99 == picker:
        main_menu()
    elif picker > (len(csvFiles)):
        out_notice('Selection out of range')
        main_menu()
    else:
        file = csvFiles[picker]

    if re.search(r"^autorpt-enterprise-attack.csv$", str(file)):
        matrix = re.match(r"^autorpt-(\W+)-attack.csv$", str(file))
        df = pd.read_csv(file, index_col=False, engine="python")
        tactics = df.TACTIC.unique()
        i = 0
        out_notice('What is the Tactic?  Or 99 to return to the main menu.')
        for tactic in tactics:
            out_menu_item(f'{i}. {tactic}')
            i = i + 1
        picker = int(input('>  '))
        if 99 == picker:
            main_menu()
        elif picker > len(tactics):
            out_notice('Selection out of range.')
            main_menu()
        else:
            tactic = tactics[picker]
            out_pass('PASS', f'Selected {picker} for {tactic}')

        techniques = df.query(f'TACTIC == "{tactic}"')[['TECHNIQUE']]
        #out_debug(
        # 'Test case:',
        # techniques.iloc[0,0] + '. Selected 1 of ' + str(len(techniques)) + ' techniques'
        # )
        out_notice('Pick a Technique?')
        i = 0
        for t in techniques.iterrows():
            out_menu_item(str(i) + '. ' + str(techniques.iloc[i,0]))
            i = i + 1
        picker = int(input('>  '))
        if picker > len(techniques):
            out_notice('Selection out of range')
            main_menu()
        else:
            technique = techniques.iloc[picker, 0]
            out_pass(
                'For Return ', 'Tactic: ' + tactic + ' Technique: ' + technique
            )
    else:
        out_notice('Only testing Enterprise at this time!')
    return tactic, technique

def download_mitre_attack_json_files():
    """ Download the ATT&CK files in JSON format. """
    out_header('[    Downloading Latest JSON Files From MITRE ATT&CK GitHub    ]')
    for url in allUrls:
        localFilename = os.path.basename(url)
        framework = localFilename.replace('-attack.json', '')
        out_notice(f'Local Filename: {localFilename}\tframework: {framework}')

        # Get the latest JSON file from GitHub
        try:
            r = requests.get(url, timeout=90)
        except:
            msg = 'Unable to download {url}'
            out_notice(msg)
            sys.exit(1)

        # Calculate sha256sum for the downloaded file
        # and store the digest in the latest config value
        config['Latest'][framework] = hashlib.sha256(r.content).hexdigest()

        # If latest sum is different than current parse latest to update current
        if config['Current'][framework] != config['Latest'][framework]:
            with open (localFilename, 'wb') as jsonToDisk:
                # Write the json file to disk for parsing
                try:
                    jsonToDisk.write(r.content)
                except:
                    msg = 'Unable to write to {localFileName}'
                    out_notice(msg)
                    sys.exit(1)
    return None

def remove_mitre_attack_json_files():
    """ Remove files. """
    out_header('[    Removing JSON Files    ]')
    for name in os.listdir('.'):
        if fnmatch.fnmatch(name, '*-attack.json'):
            out_notice(f'Removing: {name}')
            os.remove(name)

def main_menu():
    """ The Main menu. """
    out_header('    MITRE ATT&CK    ')
    out_menu_item('0. Auto run.  Download latest JSON master files and parse.  Does 1, 2, and 3.')
    out_menu_item('1. Only update local master JSON master files from MITRE GitHub')
    out_menu_item('2. Only generate updated tactics and techniques files')
    out_menu_item('3. Verify local files included with AutoRpt')
    out_menu_item_bold('4. Back to main menu')
    out_menu_item_bold('5. Quit')
    picker = int(input('>  '))
    if 1 == picker:
        download_mitre_attack_json_files()
        main_menu()
    if 2 == picker:
        parse_attack_json()
        main_menu()
    if 3 == picker:
        verify_attack_csv()
        main_menu()
    if 4 == picker:
        main_menu()
    if 5 == picker:
        sys.exit(0)

if __name__ == "__main__":
    # Get the script home starting directory
    autorpt_runfrom = os.path.dirname(os.path.realpath(__file__))
    MITRE_GITHUB = 'https://raw.githubusercontent.com/mitre/cti/master'
    urlEnterprise = f'{MITRE_GITHUB}/enterprise-attack/enterprise-attack.json'
    urlMobile = f'{MITRE_GITHUB}/mobile-attack/mobile-attack.json'
    urlIcs = f'{MITRE_GITHUB}/ics-attack/ics-attack.json'
    #urlPreAttack = f'{MITRE_GITHUB}pre-attack/pre-attack.json'
    allUrls = [urlEnterprise, urlMobile, urlIcs]
    updateConfigFile = f'{autorpt_runfrom}/update.toml'
    config = configparser.ConfigParser()
    config.read(updateConfigFile)

    # Download the latest MITRE CTI GitHub JSON files
    download_mitre_attack_json_files()
    # If the files are new, create new CSV files for AutoRpt
    parse_attack_json()
    # Validate the new CSV files
    auto_verify_attack_csv()
    # Remove local JSON files.  Too big.
    remove_mitre_attack_json_files()
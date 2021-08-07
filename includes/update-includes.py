#!/usr/bin/python3

import blessings
import json
import os
import pandas as pd
import re
import requests
import shutil
import sys
import urllib.request
term = blessings.Terminal(kind='xterm-256color')

def colorHeader(msg):
    print(f"\n{term.bold}{term.bright_black}{term.on_bright_white}{msg}{term.normal}\n")

def colorSubHeading(msg):
    print(f"{term.on_bright_blue}{msg}{term.normal}")

def colorMenuItemBold(msg):
    print(f"  {term.bold_bright_green}{msg}{term.normal}")

def colorMenuItem(msg):
    print(f"  {term.bright_green}{msg}{term.normal}")

def colorList(msg):
    print(f"{term.bright_yellow}{msg}{term.normal}")

def colorDebug(msg):
    print(f"{term.on_yellow}{term.black}[d]{term.normal}  {term.yellow}{msg}{term.normal}")

def colorTableHeader(msg):
    print(f"{term.on_blue_underline_bold}{term.bright_white}{msg}{term.normal}")

def colorVerification(field, msg):
    print(f'{term.bright_white_bold_on_blue} {field} {term.normal}  {term.yellow}{msg}{term.normal}')

def colorVerificationPass(field, msg):
    print(f'{term.black_bold_on_bright_green} {field} {term.normal}  {term.bright_green}{msg}{term.normal}')

def colorVerificationFail(field, msg):
    print(f'{term.bright_white_bold_on_bright_red} {field} {term.normal}  {term.bright_red}{msg}{term.normal}')

def colorNotice(msg):
    print(f"{term.yellow}{msg}{term.normal}")

def helper():
    print("[i] AutoRpt Proof Of Concept Functionality\n")
    print("Usage: poc.py parameter")
    print("Where parameter is one of: ")
    print("     startup or -s or --startup")
    print("     vuln or -v or --vuln")
    print("     sitrep or -r or --sitrep")
    print("     ports or -p or --ports")
    print("     finalize or -f or -f")
    sys.exit(1)

def attackGetTechniques(thesrc, include="techniques"):
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

def attackRemoveRevokedDeprecated(stix_objects):
    # Taken from: 
    #https://github.com/mitre/cti/blob/master/USAGE.md#getting-techniques-or-sub-techniques
    """Remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )

def parseAttackJson():
    colorHeader('    Parse JSON Files from MITRE ATT&CK    ')
    fileEnterprise = 'enterprise-attack.json'
    fileMobile = 'mobile-attack.json'
    fileIcs = 'ics-attack.json'
    filePreAttack = 'pre-attack.json'
    allFiles = [fileEnterprise, fileMobile, fileIcs, filePreAttack]
    for file in allFiles:
        colorSubHeading(f'Parsing {file}')
        if not os.path.isfile(file):
            colorNotice(f'Cannot find file {file}')
            sys.exit(2)
        with open(file) as f:
            try:
                attackJson = json.load(f)
            except:
                colorNotice(f'Unable to read file {file}')
        autorptFilename = 'autorpt-' + (file).replace('.json', '.csv')
        colorNotice(autorptFilename)
        df = pd.DataFrame({})
        tId = ''
        # ICS does not have x_mitre_is_subtechnique
        if not file.find("ics") != -1:
            for item in attackJson['objects']:
                if 'x_mitre_is_subtechnique' in item:
                    if not item["x_mitre_is_subtechnique"]:
                        for ref in  item['external_references']:
                            if 'external_id' in ref and re.match('T[\d+]{4}', str(ref['external_id'])) is not None:
                                tId = str(ref['external_id'])
                        for phase in item['kill_chain_phases']:
                            if phase != 'mitre-attack':
                                newRow = {'TID': tId, 'TACTIC': str(phase['phase_name']), 'TECHNIQUE': str(item['name'])}
                                df = df.append(newRow, ignore_index = True)
        else:
            for item in attackJson['objects']:
                if 'type' in item:
                    if 'kill_chain_phases' in item and 'external_references' in item:
                        for ref in  item['external_references']:
                            if 'external_id' in ref and re.match('T[\d+]{4}', str(ref['external_id'])) is not None:
                                tId = str(ref['external_id'])
                        for phase in item['kill_chain_phases']:
                            if phase != 'kill_chain_name':
                                newRow = {'TID': tId, 'TACTIC': str(phase['phase_name']), 'TECHNIQUE': str(item['name'])}
                                df = df.append(newRow, ignore_index = True)
                else:
                    colorDebug('Type not in item')
        
        df.sort_values(['TACTIC','TECHNIQUE'], inplace=True)
        try:
            with open(autorptFilename, 'w', newline='') as f:
                df.to_csv(f, index=False)
        except:
            colorNotice(f'Unable to write to {autorptFilename}')
    return None

def verifyAttackCsv():
    # A spot test to verify the content and query for each attack csv file.
    tactic = ''
    technique = ''
    colorHeader("    Verifying AutoRpt Attack CSV Files    ")
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    csvFiles = []
    for name in files:
        if name.endswith(".csv") and re.match(r'autorpt-.*-attack.csv', str(name)):
            csvFiles.append(name)
    if 0 == (len(csvFiles)):
        colorNotice('No files found')
        sys.exit(10)
    i = 0
    colorNotice('Which MITRE ATT&CK Framework applies?   Press 99 for main menu.')
    for file in csvFiles:
        colorMenuItem(f'{i}. {file[8:-11]}')
        i = i + 1
    picker = int(input('>  '))
    if 99 == picker:
        mainMenu()
    elif picker > (len(csvFiles)):
        colorNotice('Selection out of range')
        mainMenu()
    else:
        file = csvFiles[picker]
    
    if re.search(r"^autorpt-enterprise-attack.csv$", str(file)):
        matrix = re.match(r"^autorpt-(\W+)-attack.csv$", str(file))
        df = pd.read_csv(file, index_col=False, engine="python")
        tactics = df.TACTIC.unique()
        i = 0
        colorNotice('What is the Tactic?  Or 99 to return to the main menu.')
        for tactic in tactics:
            colorMenuItem(f'{i}. {tactic}')
            i = i + 1
        picker = int(input('>  '))
        if 99 == picker:
            mainMenu()
        elif picker > len(tactics):
            colorNotice('Selection out of range.')
            mainMenu()
        else:
            tactic = tactics[picker]
            colorVerificationPass('PASS', f'Selected {picker} for {tactic}')
        
        techniques = df.query(f'TACTIC == "{tactic}"')[['TECHNIQUE']]
        #colorDebug('Test case:', techniques.iloc[0,0] + '. Selected 1 of ' + str(len(techniques)) + ' techniques')
        colorNotice('Pick a Technique?')
        i = 0
        for t in techniques.iterrows():
            colorMenuItem(str(i) + '. ' + str(techniques.iloc[i,0]))
            i = i + 1
        picker = int(input('>  '))
        if picker > len(techniques):
            colorNotice('Selection out of range')
            mainMenu()
        else:
            technique = techniques.iloc[picker, 0]
            colorVerificationPass('For Return ', 'Tactic: ' + tactic + ' Technique: ' + technique)
    else:
        colorNotice('Only testing Enterprise at this time!')
    return tactic, technique

def downloadMitreAttackJsonFiles():
    colorHeader('    Downloading Latest JSON Files From MITRE ATT&CK GitHub    ')
    for url in allUrls:
        localFilename = os.path.basename(url)
        colorSubHeading(f'Local Filename: {localFilename}')
        with open (localFilename, 'wb') as jsonToDisk:
            try:
                r = requests.get(url)
            except:
                msg = 'Unable to download {url}'
                colorNotice(msg)
                sys.exit(1)
            try:
                jsonToDisk.write(r.content)
            except:
                msg = 'Unable to write to {localFileName}'
                colorNotice(msg)
                sys.exit(1)
    parseAttackJson()
    return None
    
def mainMenu():
    colorHeader('    MITRE ATT&CK    ')
    colorMenuItem('1. Update local master JSON master files from MITRE GitHub')
    colorMenuItem('2. Generate updated tactics and techniques files')
    colorMenuItem('3. Verify local files included with AutoRpt')
    colorMenuItemBold('4. Back to main menu')
    colorMenuItemBold('5. Quit')
    picker = int(input('>  '))
    if 1 == picker:
        downloadMitreAttackJsonFiles()
        mainMenu()
    if 2 == picker:
        parseAttackJson()
        mainMenu()
    if 3 == picker:
        verifyAttackCsv()
        mainMenu()
    if 4 == picker:
        mainMenu()
    if 5 == picker:
        sys.exit(0)

if __name__ == "__main__":
    # Get the script home starting directory
    autorpt_runfrom = os.path.dirname(os.path.realpath(__file__))
    urlEnterprise = 'https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json'
    urlMobile = 'https://github.com/mitre/cti/raw/master/mobile-attack/mobile-attack.json'
    urlIcs = 'https://github.com/mitre/cti/raw/master/ics-attack/ics-attack.json'
    urlPreAttack = 'https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json'
    allUrls = [urlEnterprise, urlMobile, urlIcs, urlPreAttack]
    
    mainMenu()
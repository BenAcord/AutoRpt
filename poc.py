#!/usr/bin/python3
#
#  poc.py - proof of concept testing for AutoRpt new features
#
import blessings
#from blessings import Terminal
from colorama import init
init()
import colorama
from colorama import Fore, Back, Style
import csv
from cvss import CVSS3
import datetime
import getopt
import glob
#from glob import glob
import json
import os
import pandas as pd
from pathlib import Path
import re
import requests
import shutil
from stix2 import Filter, MemoryStore, FileSystemSource
import string
import subprocess
import sys
from tabulate import tabulate
import time
import yaml
import xlsxwriter
# The following are only needed in PoC for testing
from random import *
import math
from functools import partial

# Global variables
autorpt_runfrom = None
exam_name = None
email = None
student_id = None
style_name = None
term = blessings.Terminal(kind='xterm-256color')
vulnsCsv = 'report/vulns.csv'
sitrepLog = 'report/sitrep.log'
#autorptConfigFile = '/config.yml'
#configFile = 

def banner():
    print(f'{term.bright_white_bold_on_red}Dev Dev Dev Dev Dev Dev Dev Dev Dev Dev{term.normal}')
    print(f'{term.bright_white_on_red}  ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄   ▄▄▄·▄▄▄▄▄ {term.normal}')
    print(f'{term.bright_white_on_red} ▐█ ▀█ █▪██▌•██  ▪     ▀▄ █·▐█ ▄█•██   {term.normal}')
    print(f'{term.bright_white_on_red} ▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄ ▐▀▀▄  ██▀· ▐█.▪ {term.normal}')
    print(f'{term.bright_white_on_red} ▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█•█▌▐█▪·• ▐█▌· {term.normal}')
    print(f'{term.bright_white_on_red}  ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀  ▀.▀    ▀▀▀  {term.normal}')
    print(f'{term.bright_white_on_red}                                       {term.normal}')
    print(f'{term.bright_white_bold_on_red}Dev Dev Dev Dev Dev Dev Dev Dev Dev Dev{term.normal}\n\n')
    
def colorTest():
    field = 'Field Header'
    msg = 'string value message'
    # other kind of test: partial(blessings.Terminal, kind='xterm-256color')
    TestTerminal = partial(blessings.Terminal, kind='xterm-256color') 
    t = TestTerminal()
    #  Test last:  t.clear
    colorHeader('    TESTING COLOR PALLET  :::  Blessings  ')
    print(f'Bold: {t.bold}{field} - {msg}{t.normal}')
    print(f'Underline: {t.underline}{field} - {msg}{t.normal}')
    print(f'Blink: {t.blink}{field} - {msg}{t.normal}')
    print(f'Dim: {t.dim}{field} - {msg}{t.normal}')
    print(f'Reverse: {t.reverse}{field} - {msg}{t.normal}')
    print(f'Italic: {t.italic}{field} - {msg}{t.normal}')
    print('\n')
    print(f'Black:[{t.on_black}{field}{t.normal}] MSG:[{t.black}{msg}{t.normal}] Bright Msg:[{t.bright_black}{msg}{t.normal}]')
    print(f'Blue:[{t.on_blue}{field}{t.normal}] MSG:[{t.blue}{msg}{t.normal}] Bright Msg:[{t.bright_blue}{msg}{t.normal}]')
    print(f'Magenta:[{t.on_magenta}{field}{t.normal}] MSG:[{t.magenta}{msg}{t.normal}] Bright Msg:[{t.bright_magenta}{msg}{t.normal}]')
    print(f'Cyan:[{t.on_cyan}{field}{t.normal}] MSG:[{t.cyan}{msg}{t.normal}] Bright Msg:[{t.bright_cyan}{msg}{t.normal}]')
    print(f'Green:[{t.on_green}{field}{t.normal}] MSG:[{t.green}{msg}{t.normal}] Bright Msg:[{t.bright_green}{msg}{t.normal}]')
    print(f'Yellow:[{t.on_yellow}{field}{t.normal}] MSG:[{t.yellow}{msg}{t.normal}] Bright Msg:[{t.bright_yellow}{msg}{t.normal}]')
    print(f'Red:[{t.on_red}{field}{t.normal}] MSG:[{t.red}{msg}{t.normal}] Bright Msg:[{t.bright_red}{msg}{t.normal}]')
    print(f'White:[{t.on_white}{field}{t.normal}] MSG:[{t.white}{msg}{t.normal}] Bright Msg:[{t.bright_white}{msg}{t.normal}]')
    
    colorHeader('    TESTING COLOR PALLET  :::  Colorama  ')
    colorama.init(autoreset=True)
    print('BLACK: ' + Back.BLACK + field + Style.RESET_ALL + ' - ' + Fore.BLACK + msg + Style.BRIGHT + ' - ' + Fore.BLACK + msg)
    print('BLUE: ' + Back.BLUE + field + Style.RESET_ALL + ' - ' + Fore.BLUE + msg + Style.BRIGHT + ' - ' + Fore.BLUE + msg)
    print('MAGENTA: ' + Back.MAGENTA + field + Style.RESET_ALL + ' - ' + Fore.MAGENTA + msg + Style.BRIGHT + ' - ' + Fore.MAGENTA + msg)
    print('CYAN: ' + Back.CYAN + field + Style.RESET_ALL + ' - ' + Fore.CYAN + msg + Style.BRIGHT + ' - ' + Fore.CYAN + msg)
    print('GREEN: ' + Back.GREEN + field + Style.RESET_ALL + ' - ' + Fore.GREEN + msg + Style.BRIGHT + ' - ' + Fore.GREEN + msg)
    print('YELLOW: ' + Back.YELLOW + field + Style.RESET_ALL + ' - ' + Fore.YELLOW + msg + Style.BRIGHT + ' - ' + Fore.YELLOW + msg)
    print('RED: ' + Back.RED + field + Style.RESET_ALL + ' - ' + Fore.RED + msg + Style.BRIGHT + ' - ' + Fore.RED + msg)
    print('WHITE: ' + Back.WHITE + field + Style.RESET_ALL + ' - ' + Fore.WHITE + msg + Style.BRIGHT + ' - ' + Fore.WHITE + msg)
    
    
    if '.*' == str(input('Press Enter key to return to the main menu.')):
        mainMenu()
    else:
        mainMenu()

def clearScreen():
    _ = subprocess.call('clear' if os.name == 'posix' else 'cls')

def colorHeader(msg):
    print(f"\n{term.bold}{term.bright_black}{term.on_bright_white}{msg}{term.normal}\n")

def colorSubHeading(msg):
    print(f"{term.on_bright_blue}{msg}{term.normal}")

def colorMenuItem(msg):
    print(f"  {term.bold_bright_green}{msg}{term.normal}")

def colorList(msg):
    print(f"{term.bright_yellow}{msg}{term.normal}")

def colorDebug(msg):
    print(f"{term.on_yellow}{term.black}[d]{term.normal}  {term.yellow}{msg}{term.normal}")

def colorTableHeader(msg):
    print(f"{term.on_blue_underline_bold}{term.bright_white}{msg}{term.normal}")

def colorVerification(field, msg):
    print(f'{term.bright_white_bold_on_blue} {field} {term.normal}  {term.yellow}{msg}{term.normal}')

def colorVerificationPass(field, msg):
    print(f'{term.bright_white_bold_on_bright_green} {field} {term.normal}  {term.bright_green}{msg}{term.normal}')

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

def startup(exam_name, email, student_id, style_name):
    print("[i] startup has no PoC functionality defined.")
    # sitrep update must be the last thing in startup()
    msg = 'Startup for {exam_name} with email {email} and ID {studenti_id} using style {style_name}'
    sitrepAuto(msg)
    sys.exit(2)

def finalize(exam_name, email, student_id, style_name):
    print("[i] finalize has no PoC functionality defined.")
    # sitrep update must be the last thing in startup()
    msg = 'Startup for {exam_name} with email {email} and ID {studenti_id} using style {style_name}'
    sitrepAuto(msg)
    sys.exit(3)

def getCvss3Score():
    colorHeader("    CVSS 3 Scoring    ")
    print("Do you know the Overall CVSS v3 Score? [Y|N]")
    picker = str(input(">  ")).upper()
    if "Y" == picker:
        print("What is the score?")
        cvssScore = float(input(">  "))
        if cvssScore <= 3.9:
            cvssSeverity = 'Low'
        elif cvssScore >= 4.0 and cvssScore <= 6.9:
            cvssSeverity = 'Medium'
        elif cvssScore >= 7.0 and cvssScore <= 8.9:
            cvssSeverity = 'High'
        elif cvssScore >= 9.0 and cvssScore <= 10.0:
            cvssSeverity = 'Critical'
        else:
            colorNotice('The score must be between 0.1 and 10.0.')
            getCvss3Score
        print("If known, paste the CVSS Vector string here or hit Enter to skip\n(eg. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N ")
        cvssVector = str(input('>  ')).upper()
        if 'NONE' == cvssVector or '' == cvssVector:
            cvssVector = ''
        else:
            cvssVector = "CVSS:3.0/" + cvssVector
        returnStr = [cvssSeverity, str(cvssScore), cvssVector]
    else:
        colorSubHeading('Base Score Metrics')
        colorSubHeading('Exploit')
        cvssAVs = {'Network': 'AV:N', 
                    'Adjacent Network': 'AV:A', 
                    'Local': 'AV:L', 
                    'Physical': 'AV:P'}
        aV = cvssAVs[getCvssMetricValue(cvssAVs, "Attack Vector")]
        cvssACs = {'Low': 'AC:L', 'High': 'AC:H'}
        aC = cvssACs[getCvssMetricValue(cvssACs, "Attack Complexity")]
        cvssPRs = {'None': 'PR:N', 'Low': 'PR:L', 'High': 'PR:H'}
        pR = cvssPRs[getCvssMetricValue(cvssPRs, "Privileges Required")]
        cvssUIs = {'None': 'UI:N', 'Required': 'UI:R'}
        uI = cvssUIs[getCvssMetricValue(cvssUIs, "User Interaction")]
        cvssSs = {'Unchanged': 'S:U', 'Changed': 'S:C'}
        s = cvssSs[getCvssMetricValue(cvssSs, "Scope")]
        
        colorSubHeading('Impact')
        cvssCs = {'None': 'C:N', 'Low': 'C:L', 'High': 'C:H'}
        c = cvssCs[getCvssMetricValue(cvssCs, "Confidentiality Impact")]
        cvssIs = {'None': 'I:N', 'Low': 'I:L', 'High': 'I:H'}
        i = cvssIs[getCvssMetricValue(cvssIs, "Integrity Impact")]
        cvssAs = {'None': 'A:N', 'Low': 'A:L', 'High': 'A:H'}
        a = cvssAs[getCvssMetricValue(cvssAs, "Availability Impact")]
        
        colorSubHeading('Temporal Score Metrics')
        cvssEs = {'Not Defined': 'E:X', 
                    'Unproven that exploit exists': 'E:U', 
                    'Proof of concept code': 'E:P', 
                    'Functional exploit exists': 'E:F', 
                    'High': 'E:H'}
        e = cvssEs[getCvssMetricValue(cvssEs, "Exploit Code Maturity")]
        cvssRLs = {'Not Defined': 'RL:X', 
                    'Official fix': 'RL:O', 
                    'Temporary fix': 'RL:T', 
                    'Workaround': 'RL:W', 
                    'Unavailable': 'RL:U'}
        rL = cvssRLs[getCvssMetricValue(cvssRLs, "Remediation Level")]
        cvssRCs = {'Not Defined': 'RC:X', 
                    'Unknown': 'RC:U', 
                    'Reasonable': 'RC:R', 
                    'Confirmed': 'RC:C'}
        rC = cvssRCs[getCvssMetricValue(cvssRCs, "Report Confidence")]
        
        colorSubHeading('Environmental Score Metrics')
        colorSubHeading('Exploit')
        cvssMAVs = {'Not Defined': 'MAV:X', 
                    'Network': 'MAV:N', 
                    'Adjacent Network': 'MAV:A', 
                    'Local': 'MAV:L', 
                    'Physical': 'MAV:P'}
        mAV = cvssMAVs[getCvssMetricValue(cvssMAVs, "Environmental Attack Vector")]
        cvssMACs = {'Not Defined': 'MAC:X', 'Low': 'MAC:L', 'High': 'MAC:H'}
        mAC = cvssMACs[getCvssMetricValue(cvssMACs, "Environmental Attack Complexity")]
        cvssMPRs = {'Not Defined': 'MPR:X', 'None': 'MPR:N', 'Low': 'MPR:L', 'High': 'MPR:H'}
        mPR = cvssMPRs[getCvssMetricValue(cvssMPRs, "Environmental Privileges Required")]
        cvssMUIs = {'Not Defined': 'MUI:X', 'None': 'MUI:N', 'Required': 'MUI:R'}
        mUI = cvssMUIs[getCvssMetricValue(cvssMUIs, "Environmental User Interaction")]
        cvssMSs = {'Not Defined': 'MS:X', 'Unchanged': 'MS:U', 'Changed': 'MS:C'}
        mS = cvssMSs[getCvssMetricValue(cvssMSs, "Environmental Scope")]

        colorSubHeading('Impact')
        cvssMCs = {'Not Defined': 'MC:X', 'None': 'MC:N', 'Low': 'MC:L', 'High': 'MC:H'}
        mC = cvssMCs[getCvssMetricValue(cvssMCs, "Environmental Confidentiality Impact")]
        cvssMIs = {'Not Defined': 'MI:X', 'None': 'MI:N', 'Low': 'MI:L', 'High': 'MI:H'}
        mI = cvssMIs[getCvssMetricValue(cvssMIs, "Environmental Integrity Impact")]
        cvssMAs = {'Not Defined': 'MA:X', 'None': 'MA:N', 'Low': 'MA:L', 'High': 'MA:H'}
        mA = cvssMAs[getCvssMetricValue(cvssMAs, "Environmental Availability Impact")]
        colorSubHeading('Impact Subscore Modifiers')
        cvssCRs = {'Not Defined': 'CR:X', 'Low': 'CR:L', 'Medium': 'CR:M', 'High': 'CR:H'}
        cR = cvssCRs[getCvssMetricValue(cvssCRs, "Environmental Confidentiality Requirement")]
        cvssIRs = {'Not Defined': 'IR:X', 'Low': 'IR:L', 'Medium': 'IR:M', 'High': 'IR:H'}
        iR = cvssIRs[getCvssMetricValue(cvssIRs, "Environmental Integrity Requirement")]
        cvssARs = {'Not Defined': 'AR:X', 'Low': 'AR:L', 'Medium': 'AR:M', 'High': 'AR:H'}
        aR = cvssARs[getCvssMetricValue(cvssARs, "Environmental Availability Requirement")]

        cvssVector = 'CVSS:3.0/'
        cvssVector += aV + '/' + aC + '/' + pR + '/' + uI + '/' + s + '/'
        cvssVector += c + '/' + i + '/' + a + '/'
        cvssVector += e + '/' + rL + '/' + rC + '/'
        cvssVector += mAV + '/' + mAC + '/' + mPR + '/' + mUI + '/' + mS + '/'
        cvssVector += mC + '/' + mI + '/' + mA + '/'
        cvssVector += cR + '/' + iR + '/' + aR
        c = CVSS3(cvssVector)
        returnStr = [str(c.severities()[2]), str(c.scores()[2]), cvssVector]
    #colorDebug("Returning: " + str(returnStr))
    return returnStr

def getCvssMetricValue(cvssDict, metricName):
    print("What is the " + metricName + "?")
    for (i, opt) in enumerate(list(cvssDict)):
        print("\t" + str(i) + ") " + opt)
    return list(cvssDict)[int(input(" >  "))]

def attackLoad():
    # Mapping matrices, tactics and techniques
    # Techniques map into tactics by use of their kill_chain_phases property. 
    # Where the kill_chain_name is mitre-attack, mitre-mobile-attack, or mitre-ics-attack 
    # (for enterprise, mobile, and ics domains respectively), the phase_name corresponds 
    # to the x_mitre_shortname property of an x-mitre-tactic object. Matrices define their 
    # tactics in order using the tactic_refs embedded relationships.    
    #
    # Tactics = x_mitre_shortname or x_mitre_tactic w/ ID TAxxxx
    # Techniques is attack_pattern Txxxx
    #     but so are subtechniques Txxxx.yyy which makes this noisy
    # The tactic_refs array of the matrix contains an ordered list of 
    # x-mitre-tactic STIX IDs corresponding to the tactics of the matrix
    attackEnterpriseJsonSrc = MemoryStore().load_from_file('/home/kali/Downloads/enterprise-attack.json')
    src = FileSystemSource('/opt/cti/enterprise-attack')
    # This is ugly
    # Not ideal to use Stix & local, fat download of mitre att&ck cti github (~204M)
    # or to make calls to the online json (19M)
    colorHeader('    TECHNIQUES    (test with reconnaissance)    ')
    techniques = attackGetTechniques(src, "subtechniques")
    techniques = attackRemoveRevokedDeprecated(techniques)
    #  kill_chain_phases=[KillChainPhase(kill_chain_name='mitre-attack', phase_name='execution')]
    for t in techniques:
        j = json.loads(str(t))
        killChain = j["kill_chain_phases"] #).replace('[', '').replace(']', '')
        tactic = ''
        technique = ''
        for k in killChain:
            tactic = str(k["phase_name"])
        technique = str(j["name"])
        colorList('Tactic Name: ' + tactic + '\tTechnique Name: ' + technique)
        colorList(' J: ' + str(j))
        sys.exit(255)
    sys.exit(255)

def getMitreAttack():
    tactic = ''
    technique = ''
    colorHeader("    MITRE ATT&CK    ")
    path_includes = autorpt_runfrom + '/includes'
    csvFiles = glob.glob(path_includes + '/autorpt-*-attack.csv')
    colorDebug(path_includes + '  - Files: ' + str(csvFiles))
    i = 0
    colorNotice('Which MITRE ATT&CK Framework applies?\nPress 99 for main menu.')
    for file in csvFiles:
        colorMenuItem(f'{i}. {file[30:-11]}')
        i = i + 1
    picker = int(input('>  '))
    if 99 == picker:
        mainMenu()
    elif picker > (len(csvFiles)):
        colorNotice('Selection out of range')
        mainMenu()
    else:
        file = csvFiles[picker]
    
    matrix = re.match(r"^autorpt-(\W+)-attack.csv$", str(file))
    df = pd.read_csv(file, index_col=False, engine="python")
    tactics = df.TACTIC.unique()
    i = 0
    colorNotice('What is the Tactic?\nOr 99 to return to the main menu.')
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
    
    return [tactic, technique]

def vuln():
    colorHeader('[    Vulnerabilities    ]')
    colorMenuItem("1. Add a new vulnerability")
    colorMenuItem("2. List all vulnerabilities")
    colorMenuItem("3. Modify an existing vulnerability")
    colorMenuItem("4. Remove a vulnerability\n")
    colorMenuItem('5. Main Menu')
    colorMenuItem("6. quit")
    vuln_selection = int(input("> "))
    if 1 == vuln_selection:
        vulnAdd()
    elif 2 == vuln_selection:
        vulnList()
    elif 3 == vuln_selection:
        vulnModify()
    elif 4 == vuln_selection:
        vulnRemove()
    elif 5 == vuln_selection:
        mainMenu()
    elif 6 == vuln_selection:
        sys.exit(0)

def vulnAdd():
    colorHeader("    Add Vulnerability    ")
    colorNotice("What is the name for this vulnerability?\n(eg. Remote code injection in Vendor_Product_Component)")
    vulnName = str(input('>  '))
    colorNotice("Describe the business impact: ")
    vulnImpact = str(input('>  '))
    colorNotice("Do you have a comment for where you left off? ")
    vulnComment = str(input('>  '))
    rawCvss = getCvss3Score()
    cvssSeverity = rawCvss[0]
    cvssScore = rawCvss[1]
    cvssVector = rawCvss[2]
    colorDebug('Getting Mitre ATT&CK values')
    mitreAttack = getMitreAttack()
    colorVerification('mitreAttack', str(mitreAttack))
    vulnMitreTactic = mitreAttack[0]
    vulnMitreTechnique = mitreAttack[1]
    colorNotice("\n-----------------------------\n  Verify the data entered.\n-----------------------------")
    colorVerification('[Name]                  ',vulnName)
    colorVerification("[CVSS Overall Score]    ", str(cvssScore))
    colorVerification("[CVSS Severity]         ", cvssSeverity)
    colorVerification("[Business Impact]       ", vulnImpact)
    colorVerification("[Comment]               ", vulnComment)
    colorVerification('[MITRE ATT&CK Tactic]   ', vulnMitreTactic)
    colorVerification('[MITRE ATT&CK Technique]', vulnMitreTechnique)
    checkPoint = str(input("\nAre these values correct? [Y|N]  > ")).upper()
    if checkPoint == "Y":
        row = f'{vulnName},{vulnImpact},{vulnComment},{cvssScore},{cvssSeverity},{cvssVector},{vulnMitreTactic},{vulnMitreTechnique}'
        vulnCsvNewRow(row)
    else:
        print("[!] Reseting values")
        vulnName = ''
        vulnImpact = ''
        vulnCvss = ''
        vulnMitreTactic = ''
        vulnMitreTechnique = ''
        vulnComment = ''
        vulnAdd()
    vuln()

def vulnCsvNewRow(row):
    if not os.path.isfile(vulnsCsv):
        headings = 'Name,Impact,Comment'
        headings += ',CvssScore,CvssSeverity,CvssVector'
        headings += ',MitreTactic,MitreTechnique'
        with open(vulnsCsv, 'a', encoding='utf-8') as f:
            f.write(headings + "\n")
            f.write(row + "\n")
            f.close()
    else:
        with open(vulnsCsv, 'a', encoding='utf-8') as f:
            f.write(row + "\n")
            f.close()
    msg = f'Added new vulnerability: {str(row)}'
    sitrepAuto(msg)

def vulnList():
    colorHeader("    List of Current Vulnerabilities    ")
    if os.path.exists(vulnsCsv):
        df = pd.read_csv('report/vulns.csv', index_col=False, engine="python")
        colorList(tabulate(df[['Name', 'Impact', 'CvssSeverity', 'CvssScore', 'Comment']], headers=df.columns))
    else:
        print("0 vulnerabilities")
    if len(sys.argv) == 3 and 'list' == sys.argv[2]:
        sys.exit(0)    
    else:
        vuln()

def vulnModify():
    print("\n")
    vm = pd.read_csv(vulnsCsv)
    rowCount = len(vm.index)
    headings = list(vm.columns.values)
    # Need a better method of displaying rows.
    # Or just let pandas truncate for selection and display long-form details.
    colorList(tabulate(vm[['Name', 'Impact', 'CvssSeverity', 'CvssScore', 'Comment']], headers=vm.columns))
    vulnId = int(input("\nPick an entry to modify or '99' to go back to the menu:  "))
    if 99 == vulnId:
        vuln()
    print("\n" + str(headings))
    fieldId = str(input("Type a column name to modify or '99' to go back to the menu:  "))
    if '99' == fieldId:
        vuln()
    if fieldId not in headings:
        print("INVALID HEADING")
        vuln()
    if 'CVSS' == fieldId:
        newValue = float(input("What is the new value?  "))
    else:
        newValue = str(input(f'What is the new value?  '))
    vm.at[vulnId, fieldId] = newValue
    print(vm)
    msg = f"Modified vulnerability {fieldId} to: {newValue} for {str(vm.at[vulnId, 'Name'])}"
    colorNotice(msg)
    sitrepAuto(msg)
    with open(vulnsCsv, 'w', newline='') as f:
        vm.to_csv(f, index=False)
        f.close()
    colorDebug('Modified rows written to csv file.')
    time.sleep(3)
    vuln()

def vulnRemove():
    # Replace with modification of vulnModify
    i = 0
    print("\n")
    r = csv.reader(open(vulnsCsv))
    rows = list(r)
    for row in rows:
        print(str(i) + ") " + str(row))
        i += 1
    vulnId = int(input("\nPick an entry to remove or '99' to go back to the menu:  "))
    if 99 == vulnId:
        vuln()    
    # Bug: Get vuln name and log it with sitrep
    msg = "Remove vulnerability: " + str(rows[vulnId])
    sitrepAuto(msg)
    del rows[vulnId]
    with open(vulnsCsv, 'w', newline='') as f:
        writer = csv.writer(f, delimiter=',')
        writer.writerows(rows)
        f.close()
    vuln()

def vulnTestLoad():
    if os.path.isfile(vulnsCsv):
        vuln()
    else:
        row = []
        for i in range(4):
            for a in string.ascii_lowercase[:4]:
                vulnName = str(i) + a
                cvssScore = float(math.floor(uniform(0,10) * 10 ** 2) / 10 ** 2)
                vulnImpact = vulnName + "-" + str(cvssScore)
                vulnComment = "Something-" + vulnName
                a = ['Low', 'Medium', 'High', 'Critical']
                cvssSeverity = a[randint(0,3)]
                cvssVector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L/E:U/RL:U/RC:C/CR:L/IR:H/AR:L/MAV:N/MAC:L/MPR:L/MUI:N/MS:U/MC:L/MI:H/MA:L'
                vulnMitreTactic = "Tactic-TBD" + str(cvssScore)
                vulnMitreTechnique = "Technique-TBD" + str(cvssScore)
                row += [ {'Name': vulnName, 'Impact': vulnImpact, 'Comment': vulnComment,
                         'CvssScore': cvssScore, 'CvssSeverity': cvssSeverity, 'CvssVector': cvssVector,
                         'MitreTactic': vulnMitreTactic, 'MitreTechnique': vulnMitreTechnique} ]
        vulnCsvNewRow(row)
        print("Completed loading test dataset to vuln.csv file.")

def find(filename, path):
  for root, dirs, files in os.walk(path):
    if filename in files:
      yield os.path.join(root, filename)

def ports():
    portsFile = 'report/ports.xlsx'
    # autorecon specific: scans/_full_*_nmap.txt
    with open('targets.txt', 'r', encoding='utf-8', newline='') as t:
        targets = t.readlines()
        for target in targets:
            target = target.strip()
            nmapFile = './results/' + target + '/scans/_full_tcp_nmap.txt'
            if os.path.isfile(nmapFile):
                with open(nmapFile, 'r', encoding='utf-8', newline='') as n:
                    nmapContents = n.readlines()
                    n.close()
                df = pd.DataFrame({})
                ip = ''
                port = '' 
                state = ''
                service = '' 
                version = ''
                for line in nmapContents:
                    if re.match(r"^Nmap scan report for ", line):
                        ip = line.strip().replace('Nmap scan report for ', '')
                    elif re.match(r"^\d+.*$", line):
                        fields = line.strip().split()
                        # 0:port, 1:state, 2:service, 3:reason(skip), 4:version(glob)
                        port = fields[0]
                        state = fields[1]
                        service = fields[2]
                        #version = ' '.join(fields[4:])
                        version = re.sub(r'\(.*\)', '', ' '.join(fields[4:]))  # if broken flip last option to version
                        newRow = {'IPADDRESS': ip,
                                'PORT': port, 
                                'STATE': state, 
                                'SERVICE': service, 
                                'VERSION': version}
                        df = df.append(newRow, ignore_index = True)
                colorHeader(f'    {target} - Port Count: {str(len(df.index))}    ')
                colorList(tabulate(df[['IPADDRESS', 'PORT', 'SERVICE', 'STATE', 'VERSION']], headers=df.columns))
                if os.path.isdir('report'):
                    # Bug: Replace with CSV
                    with pd.ExcelWriter('report/ports.xlsx') as writer:
                        try:
                            df.to_excel(writer, sheet_name=target, index=False)
                        except:
                            print("[e] Unable to write to xlsx file.")
            else:
                print('[e] file does not exist: ' + nmapFile)
    
    
    # Show result file details
    sys.exit(255)

def sitrepAuto(msg):
    d = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    if os.path.isfile('report/sitrep.log'):
        with open('report/sitrep.log', 'a', encoding='utf-8', newline='') as f:
            f.write(f'{d} - {msg}\n')
            f.close()
    else:
        with open('report/sitrep.log', 'w', encoding='utf-8', newline='') as f:
            f.write(f'{d} - {msg}\n')
            f.close()

def sitrepList():
    if os.path.isfile(sitrepLog):
        clearScreen()
        colorHeader("    SITREP Log Entries    ")
        with open(sitrepLog) as f: 
            s = f.readlines()
            f.close()
        for l in s:
            fields = l.strip().split(" - ")
            print(f'{term.bold_blue_on_yellow} {fields[0]} {term.normal} - {term.yellow}{fields[1]}{term.normal}')
    else:
        print(f'{term.white}Sitrep file is empty.{term.normal}\n\n')

def sitrepNew():
    msg = str(input('What is your current status? '))
    sitrepAuto(msg)
    sitrepMenu()

def sitrepMenu():
    # A stream of status journal.
    colorHeader('[    SITREP  (Situation Report)    ]')
    colorMenuItem('1. List all sitrep entries')
    colorMenuItem('2. Add new sitrep log entry\n')
    colorMenuItem('3. Main Menu')
    colorMenuItem('4. Quit')
    sitrepAction = int(input('>  '))
    if 4 == sitrepAction:
        sys.exit(0)
    elif 3 == sitrepAction:
        mainMenu()
    elif 1 == sitrepAction:
        sitrepList()        
    elif 2 == sitrepAction:
        sitrepNew()
    sitrepMenu()

def mainMenu():
    clearScreen()
    banner()
    colorHeader('[    Main Menu    ]')
    colorMenuItem('1. Startup')
    colorMenuItem('2. Vulnerabilities')
    colorMenuItem('3. SitRep Log')
    colorMenuItem('4. Finalize')
    colorMenuItem('5. Quit')
    colorMenuItem('6. PoC Color Test')
    colorMenuItem('7. MITRE ATT&CK')
    picker = int(input('>  '))

    if 1 == picker:
        picker = str(input('are you in the directory you want to create working report subdirectories?  [Y/N]  '))
    elif 2 == picker:
        vuln()
    elif 3 == picker:
        sitrepMenu()
    elif 4 == picker:
        finalize()
    elif 5 == picker:
        sys.exit(0)
    elif 6 == picker:
        colorTest()
    elif 7 == picker:
        attackLoad()

def getConfiData():
    exam_name = None
    email = None
    student_id = None
    style_name = None
    if os.path.exists(autorpt_runfrom + '/config.yml'):
        config_file = open(autorpt_runfrom + '/config.yml', 'r')
        config_data = yaml.safe_load(config_file)
    else:
        config_data = None
    msg = "Debug config file values and yaml import"
    #colorDebug(msg)
    msg = "-------------------------------------------------------------"
    for x in config_data:
        msg = x + ' - [' + str(config_data[x]) + ']'
    
    msg = "\n\nDebug Keys\n-------------------------------------------------------------"
    msg = 'config_data keys: ' + str(config_data.keys())
    msg = "\n\nDebug Values\n-------------------------------------------------------------"
    msg = 'config_data values: ' + str(config_data.values())
    msg = "-------------------------------------------------------------"
    #sys.exit(255)
    msg = "End Debug"

    # Verify configuration data entries
    if config_data is not None:
        if 'exam' in config_data.keys():
            exam_name = config_data['exam']
            if not os.path.isdir(autorpt_runfrom + '/templates/' + exam_name):
                print('[!] config file exam value is not supported.')
                sys.exit(11)
        if 'email' in config_data.keys():
            email = config_data['email']
        if 'studentid' in config_data.keys():
            student_id = str(config_data['studentid'])
        if 'style' in config_data.keys():
            style_name = config_data['style']
    
    msg = "==================================================\nDEBUG"
    msg = 'exam type: ' + str(type(exam_name)) + ' Value: ' + exam_name
    msg = 'email type: ' + str(type(email)) + ' Value: ' + email
    msg = 'student_id type: ' + str(type(student_id)) + ' Value: ' + student_id
    msg = 'style_name type: ' + str(type(style_name)) + ' Value: ' + style_name
    msg = "END DEBUG\n=================================================="


def params(argv, exam_name, email, student_id, style_name):
    # DEBUG >>>>
    #msg = 'Number of arguments:' + str(len(sys.argv)) + ' arguments.'
    #print(f'{term.on_blue}{msg}{term.normal}')
    #msg = 'Argument List: ' + str(sys.argv)
    #colorDebug(msg)
    # DEBUG <<<<
    action = sys.argv[1]
    if action == '-h' or action == '--help' or action == 'help':
        helper()
    elif action == '-s' or action == 'startup' or action == '--startup':
        startup(exam_name, email, student_id, style_name)
    elif action == '-f' or action == 'finalize' or action == '--finalize':
        finalize(exam_name, email, student_id, style_name)
    elif action == '-v' or action == 'vuln' or action == '--vuln':
        # Debug test load a CSV - vulnTestLoad()
        if len(sys.argv) == 3 and 'list' == sys.argv[2]:
            vulnList()
        else:
            vuln()
    elif action == '-i' or action == 'sitrep' or action == '--sitrep':
        if len(sys.argv) == 3 and 'list' == sys.argv[2]:
            sitrepList()
        else:
            sitrepMenu()
    elif action == '-p' or action == 'ports' or action == '--ports':
        ports()
    elif action == '-a' or action == 'attack' or action == '--attack':
        getCvss3Score()
    else:
        print ('Action is "', action)
        helper()

# DisplayablePath from: 
# https://stackoverflow.com/questions/9727673/list-directory-tree-structure-in-python
class DisplayablePath(object):
    display_filename_prefix_middle = '├──'
    display_filename_prefix_last = '└──'
    display_parent_prefix_middle = '    '
    display_parent_prefix_last = '│   '

    def __init__(self, path, parent_path, is_last):
        self.path = Path(str(path))
        self.parent = parent_path
        self.is_last = is_last
        if self.parent:
            self.depth = self.parent.depth + 1
        else:
            self.depth = 0

    @property
    def displayname(self):
        if self.path.is_dir():
            return self.path.name + '/'
        return self.path.name

    @classmethod
    def make_tree(cls, root, parent=None, is_last=False, criteria=None):
        root = Path(str(root))
        criteria = criteria or cls._default_criteria

        displayable_root = cls(root, parent, is_last)
        yield displayable_root

        children = sorted(list(path
                               for path in root.iterdir()
                               if criteria(path)),
                          key=lambda s: str(s).lower())
        count = 1
        for path in children:
            is_last = count == len(children)
            if path.is_dir():
                yield from cls.make_tree(path,
                                         parent=displayable_root,
                                         is_last=is_last,
                                         criteria=criteria)
            else:
                yield cls(path, displayable_root, is_last)
            count += 1

    @classmethod
    def _default_criteria(cls, path):
        return True

    @property
    def displayname(self):
        if self.path.is_dir():
            return self.path.name + '/'
        return self.path.name

    def displayable(self):
        if self.parent is None:
            return self.displayname

        _filename_prefix = (self.display_filename_prefix_last
                            if self.is_last
                            else self.display_filename_prefix_middle)

        parts = ['{!s} {!s}'.format(_filename_prefix,
                                    self.displayname)]

        parent = self.parent
        while parent and parent.parent is not None:
            parts.append(self.display_parent_prefix_middle
                         if parent.is_last
                         else self.display_parent_prefix_last)
            parent = parent.parent

        return ''.join(reversed(parts))

if __name__ == "__main__":
    # Get the script home starting directory
    autorpt_runfrom = os.path.dirname(os.path.realpath(__file__))

    if len(sys.argv) <= 1:
        mainMenu()
    else:
        params(sys.argv[1:], exam_name, email, student_id, style_name)
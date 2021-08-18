#!/usr/bin/python3
"""
---
autorpt.py - Penetration testing report automatic generator
             Sets up a clean directory for note taking during 
             a pentest, an exam, or training then compiles the final report.
---------------------------------------------------------------------------------------------
"""

import blessings
import configparser
import csv
from cvss import CVSS3
import datetime
import getopt
from glob import glob
import json
import os
import openpyxl
import pandas as pd
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import yaml

def helper():
    colorNotice("USAGE:")
    colorNotice("autorpt.py [ help | startup | vuln | ports | sitrep \{message\}| finalize | settings ]\n")
    colorNotice("WHERE:")
    colorNotice('  help:      Display this listing of usage and examples.')
    colorNotice('  startup:   Create a clean working directory for a new engagement.')
    colorNotice('  vuln:      Record a confirmed vulnerability with CVSS scoring and MITRE ATT&CK attributes.')
    colorNotice('  ports:     (AutoRecon specific) Quick display of all open ports per target.')
    colorNotice('  sitrep:    Record a status update of your current progress or display the menu.')
    colorNotice('  finalize:  Compile markdown files into a desired output file format.')
    colorNotice('  settings:  Configuration settings.')

    colorNotice("\nEXAMPLES:")
    colorNotice("When you are ready to start an exam or training:")
    colorNotice("    autorpt.py startup")
    colorNotice("Log a verified vulnerability:")
    colorNotice("    autorpt.py vuln")
    colorNotice("Display vulnerability list:")
    colorNotice("    autorpt.py vuln list")
    colorNotice("Log your current status:")
    colorNotice("    autorpt.py sitrep pwned buffer overflow")
    colorNotice("...Or")
    colorNotice("    autorpt.py sitrep Stuck trying to exploit system X:8001/login.php via SQLi.  May be a rabbit trail.")
    colorNotice("...Or use the menu system:")
    colorNotice("    autorpt.py sitrep")
    colorNotice("Display the sitrep log:")
    colorNotice("    autorpt.py sitrep list")
    colorNotice("After AutoRecon completes, display the ports:")
    colorNotice("    autorpt.py ports")
    colorNotice("Compile the markdown into a polished report document")
    colorNotice("    autorpt.py finalize")
    sys.exit(1)

def banner():
    print(f'{term.bright_red}{term.normal}')
    print(f'{term.bright_red}  ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄   ▄▄▄·▄▄▄▄▄ {term.normal}')
    print(f'{term.bright_red} ▐█ ▀█ █▪██▌•██  ▪     ▀▄ █·▐█ ▄█•██   {term.normal}')
    print(f'{term.bright_red} ▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄ ▐▀▀▄  ██▀· ▐█.▪ {term.normal}')
    print(f'{term.bright_red} ▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█•█▌▐█▪·• ▐█▌· {term.normal}')
    print(f'{term.bright_red}  ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀  ▀.▀    ▀▀▀  {term.normal}')
    #print(f'{term.bright_red}                                       {term.normal}')
    print(f'{term.bright_red}             Tag your work{term.normal}\n')
    
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
        print("If known, paste the CVSS Vector string here or hit Enter to skip (eg. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N ")
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
    return returnStr

def getCvssMetricValue(cvssDict, metricName):
    print("What is the " + metricName + "?")
    for (i, opt) in enumerate(list(cvssDict)):
        print("\t" + str(i) + ") " + opt)
    return list(cvssDict)[int(input(" >  "))]

def getMitreAttack():
    tactic = ''
    technique = ''
    colorHeader("    MITRE ATT&CK    ")
    path_includes = autorpt_runfrom + '/includes'
    csvFiles = glob(path_includes + '/autorpt-*-attack.csv')
    
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

    # Get the tactic
    i = 0
    picker = 0
    tactics = df.TACTIC.unique()
    colorNotice('What is the Tactic?\nOr 99 to return to the ATT&CK menu.')
    for tactic in tactics:
        colorMenuItem(f'{i}. {tactic}')
        i = i + 1
    picker = int(input('>  '))
    if 99 == picker:
        getMitreAttack()
    elif picker > len(tactics):
        colorNotice('Selection out of range.')
        mainMenu()
    else:
        tactic = tactics[picker]
    
    # Get the technique
    i = 0
    picker = 0
    techniques = df.query(f'TACTIC == "{tactic}"')[['TECHNIQUE']]
    colorNotice('Pick a Technique?')
    for index, row in techniques.iterrows():
        colorMenuItem(f"{str(i)}.  row: {str(row.TECHNIQUE)} vs iloc: {techniques.iloc[i,0]}")
        i = i + 1
    picker = int(input('>  '))
    technique = techniques.iloc[picker, 0]

    # Bug: Upon repeat will not set the correct value for either value.
    # Returns the first selection for both tactic and technique.
    #colorDebug(f"Final values from getMitreAttack() are Tactic {tactic} & Technique: {technique}")
    #colorNotice(f'Is this correct?   Tactic {tactic} & Technique: {technique}')
    #colorMenuItem('1. Yes')
    #colorMenuItem('2. No')
    #picker = int(input('>  '))
    #if 2 == picker:
    #    getMitreAttack()
    
    return [tactic, technique]

def dictToMenu(dictionary):
    i = 0
    for item in dictionary.split(','):
        colorMenuItem(str(i) + ".  " + item)
        i += 1
    colorMenuItem('99 for main menu')
    return i

def configSectionToMenu(section):
    i = 0
    items = []
    for item in section:
        colorMenuItem(str(i) + ".  " + section[item])
        items.append(section[item])
        i += 1
    colorMenuItem('99 for main menu')
    return items

def addTarget():
    # Update targets.txt with a new IP address
    # Get target IP address
    colorNotice('Do you know the target IP address?  Or enter "N" to skip.')
    targetIp = str(input('>  ')).replace(" ", "").lower()
    colorDebug('Adding a new target is a future feature.')

def startup():
    colorHeader('[    Startup    ]')

    colorNotice('Startup will first create a directory structure for the engagement.')
    colorNotice('(eg. training/hackthebox/waldo)\n')

    # Get the engagement type: training, ctf, exam, bugbounty, pentest
    colorNotice('Select the type of engagement:')
    dictLen = int(dictToMenu(appConfig['Settings']['types']))
    picker = int(input('>  '))
    if 99 == picker:
        mainMenu()
    elif picker >= dictLen:
        mainMenu()
    else:
        engagementType = appConfig['Settings']['types'].split(',')[picker]

    # Set default path for templates. Only exams are unique.
    templates_path = f'{autorpt_runfrom}/templates/training/'
    if 'training' == engagementType:
        # Get the platform
        colorNotice('Enter the platform or company name (or 10 to add a custom platform):')
        providers = configSectionToMenu(appConfig['Training'])
        picker = int(input('>  '))
        if picker == 99:
            mainMenu()
        elif picker == 10:
            colorNotice('Enter the name of the custom platform')
            platform = str(input('>  '))
        else:
            platform = providers[picker]
        # Future: No means to custom add a platform
        # Get the box name
        colorNotice('What is the box name?')
        colorNotice('(eg. waldo, kenobi, etc.')
        engagementName = str(input('>  ')).replace(" ", "").lower()
        # Get target IP address
        colorNotice('Do you know the target IP address?  Or enter "N" to skip.')
        targetIp = str(input('>  ')).replace(" ", "").lower()
    elif 'bugbounty' == engagementType:
        # Get the platform
        colorNotice('Enter the platform or company name:')
        providers = configSectionToMenu(appConfig['Bug Bounty'])
        platform = providers[int(input('>  '))]
        # No means to custom add a platform
        # Get the program name
        colorNotice('What is the program name?')
        colorNotice('(eg. Tesla, Domain.com, etc.')
        rep = {"'": "", '"': "", '`': ''}
        engagementName = str(input('>  ')).replace(rep).lower()
    elif 'ctf' == engagementType:
        # Get the engagement name
        colorNotice('What is the name of this CTF event?')
        platform = str(input('>  ')).lower()
        platform = platform.replace("'", "")
        platform = platform.replace('"', "")
        platform = platform.replace('`', '')
        platform = platform.replace(" ", "")
        # Get the engagement name
        colorNotice('What is the team name?')
        engagementName = str(input('>  ')).lower()
        engagementName = engagementName.replace("'", "")
        engagementName = engagementName.replace('"', "")
        engagementName = engagementName.replace('`', '')
        engagementName = engagementName.replace(' ', '')
    elif 'exam' == engagementType:
        # pick the exam
        colorNotice('Select the exam')
        i = 0
        exams = []
        for item in appConfig['Exams']:
            examName = appConfig['Exams'][item].split(',')[1]
            colorMenuItem(str(i) + ".  " + examName)
            exams.append(item)
            i += 1
        colorMenuItem('99 for main menu')
        picker = int(input('>  '))
        if 99 == picker:
            mainMenu()
        platform = appConfig['Exams'][exams[picker]].split(',')[0]
        engagementName = exams[picker]
        # No means to custom add a platform
        templates_path = f'{autorpt_runfrom}/templates/{engagementName}/'
    elif 'pentest' == engagementType:
        # Least tested option
        # Company performing the test
        colorNotice('What is the penetration testing company name?')
        providers = configSectionToMenu(appConfig['Bug Bounty'])
        platform = str(input('>  '))
        # Client name
        colorNotice('What is the client name?')
        engagementName = str(input('>  ')).replace('\s+', '').lower()
    else:
        mainMenu()
    
    # Set timestamp for this engagement for uniqueness
    timestamp = datetime.datetime.now().strftime('%Y%m%d')
    
    # Compile the engagement string and directory path to create
    thisEngagement = f'{engagementName}'
    thisEngagement += f'-{timestamp}'

    thisDir = appConfig['Paths']['pathwork']
    thisDir += f'/{engagementType}'
    thisDir += f'/{platform}'
    thisDir += f'/{engagementName}'
    thisDir += f'-{timestamp}'

    # Copy the template to the engagement directory
    try:
        shutil.copytree(templates_path, f'{thisDir}/')
    except OSError as exc: # python >2.5
        colorVerificationFail("[!]", "Copytree templates failed.  Trying copy.")
        try:
            shutil.copy(templates_path, f'{thisDir}/')
        except OSError as exc:
            colorVerificationFail("[!]", "Copy templates failed. Done.")
            sys.exit(5)
    
    if "training" == engagementType:
        os.rename(f'{thisDir}/report/1-renameme.md', f'{thisDir}/report/1-{engagementName}.md')
        if len(targetIp) >= 7:
            with open(f'{thisDir}/targets.txt', 'w') as t:
                t.write(targetIp + '\n')
    
    # Update sessions file
    # Set active
    session['Current']['active'] = thisEngagement
    # Set new details record
    msg = f'{thisDir},'
    msg += f'{engagementType},'
    msg += f'{appConfig["Settings"]["studentid"]},'
    msg += f'{appConfig["Settings"]["your_name"]},'
    msg += f'{appConfig["Settings"]["email"]},'
    msg += f'{appConfig["Settings"]["style"]},'
    msg += f'{engagementName}'
    session['Engagements'][thisEngagement] = msg
    saveEnagements()

    # Journal entry in sitrep
    msg = f'Startup initiated new working directory for {engagementName}: {thisDir}'
    sitrepAuto(msg)

    # Display directory tree
    colorNotice("Templates successfully copied to report directory.  Here's the new structure:\n")
    paths = DisplayablePath.make_tree(Path(thisDir))
    for path in paths:
        print(path.displayable())
    time.sleep(3)
    #mainMenu()

def finalize():
    activeAll = getActiveAll()
    engagementType = activeAll.split(',')[1]
    email = appConfig['Settings']['email']
    author = appConfig['Settings']['your_name']
    student_id = appConfig['Settings']['studentid']
    rptFormat = appConfig['Settings']['preferred_output_format']
    toArchive = 'No'
    rpt_base = f"{activeAll.split(',')[0]}/report/"
    rpt_date = datetime.datetime.now().strftime('%Y-%m-%d')
    style_name = appConfig['Settings']['style']
    targetName = activeAll.split(',')[6]
    # ensure the latest ports file exists
    portsFile = f"{rpt_base}{portsSpreadsheet}"
    if not os.path.exists(portsFile):
        ports()
    # Read in the ports spreadsheet
    ports_table = pd.read_excel(portsFile, sheet_name='All Ports').to_markdown()
    # FUTURE FEATURE IS TO AUTOMATICALLY ADD THE VULNS TABLE'
    portsFile = f"{rpt_base}{vulnsCsv}"
    if os.path.isfile(portsFile):
        fields = ['CvssSeverity','IpAddress','Port','Name','Remediation']
        vulns_table = pd.read_csv(portsFile, 
                                  usecols=fields, 
                                  sep=",", 
                                  engine="python").to_markdown()
        vulns_all = pd.read_csv(portsFile, sep=",", engine="python")
    else:
        vulns_table = 'No vulnerabilities were discovered.'

    # Student info only applies for exams and perhaps specific exams (eg OffSec)
    if 'training' == engagementType:
        rpt_name = "training_" + targetName + "_Report"
    else:
        rpt_name = f"{targetName.upper()}_" + student_id + "_Exam_Report"

        if student_id == '':
            colorNotice("\nWhat is your student ID, if required?\n(eg. OS-12345, N/A)")
            student_id = str(input('>  '))
        else:
            colorNotice("Student ID pulled from config file as " + student_id)
    
    if email == '':
        colorNotice("What is your full email address?")
        email = str(input('>  '))
    else:
        colorNotice("Email address pulled from config file as " + email)

    if author == '':
        colorNotice("What is your name?")
        author = str(input('>  '))
    else:
        colorNotice("Author pulled from config file as " + author)
    
    # Rename as rptMarkdownFile
    rpt_filename = rpt_base + rpt_name + ".md"
    
    # Set output file format
    if rptFormat == '':
        i = 0
        print("From these options, Pick an output format:")
        for ext in supported_filetypes.split(','):
            colorMenuItem(f"{str(i)} ) {ext}")
            i += 1
        picked = int(input('>  '))
        rptFormat = supported_filetypes[picked].lower()

    if rptFormat in ["commonmark_x", "jira", "gfm"]:
        rpt_extension = 'md'
    else:
        rpt_extension = rptFormat
    # Is archive needed?
    if '7z' in rpt_extension:
        toArchive = 'yes'
        rpt_extension = rpt_extension.split("+")[0]
        rptFullPath = rpt_base + rpt_name + "." + rpt_extension
    else:
        rptFullPath = rpt_base + rpt_name + "." + rpt_extension
    
    msg = f'Creating final report.  toArchive? {toArchive}  Ext: {str(rpt_extension)}  File: {rptFullPath}'
    sitrepAuto(msg)
    
    # The merged, unified markdown file is not a primary source.
    # Remove of it already exists. Previous failed attempt.
    if os.path.exists(rpt_filename):
        try:
            os.remove(rpt_filename)
        except:
            colorVerificationFail("Error", "removing existing report file: " + rpt_filename)
            sys.exit(6)

    # Merge markdown sections into a single mardown for pandoc later
    md_file_list = glob(rpt_base + '[0-9]*.md')
    md_file_list = sorted(md_file_list)
    for file in md_file_list:
        with open(file, 'r+') as f:
            file_contents = f.read()
            file_contents = re.sub('BOILERPLATE_AUTHOR', author, file_contents)
            file_contents = re.sub('BOILERPLATE_EMAIL', email, file_contents)
            file_contents = re.sub('BOILERPLATE_DATE', rpt_date, file_contents)
            file_contents = re.sub('BOILERPLATE_PORTS', ports_table, file_contents)
            file_contents = re.sub('BOILERPLATE_VULNS', vulns_table, file_contents)
            if "training" == engagementType:
                file_contents = re.sub('BOILERPLATE_TARGET', targetName, file_contents)
                file_contents = re.sub('BOILERPLATE_HOSTNAME', targetName, file_contents)
                file_contents = re.sub('BOILERPLATE_OSID', '', file_contents)
            else:
                file_contents = re.sub('BOILERPLATE_OSID', student_id, file_contents)
                
            # Some markdown for pasted images are incompatable with Pandoc 
            # and results in no images reaching the final report.
            # Rewrite all pasted screenshots from this "![[Pasted_image_A.png]]" 
            # to this format "![Pasted_image_A.png](Pasted_image_A.png)"
            file_contents = re.sub(r'\!\[\[Pasted_image_(\w+).png\]\]', 
                                   r'![Pasted_image_\1.png](Pasted_image_\1.png)', 
                                   file_contents)
            # Write modifed contents with boilerplate value replacements
            with open(rpt_filename, 'a') as result:
                result.write(file_contents + '\n')

    if style_name == '':
        style_name = getPandocStyle()
    else:
        colorNotice("Code block style pulled from config file as " + style_name)
    
    colorVerification("[i]", f"Generating report {rptFullPath}")
    # Hack.  Use OS install of pandoc.
    # Need to figure out Pythonic pandoc module use.
    cmd = 'pandoc ' + rpt_filename
    cmd += ' --output=' + rptFullPath
    cmd += ' --from markdown+yaml_metadata_block+raw_html'
    cmd += ' --table-of-contents' 
    cmd += ' --toc-depth' + ' 6'
    cmd += ' --top-level-division=chapter'
    cmd += ' --wrap=auto'
    cmd += ' --highlight-style ' + style_name
    if rpt_extension in appConfig['Settings']['no_template']:
        cmd += ' --template' + ' eisvogel'
    
    colorDebug(f"cmd:\n{cmd}")

    try:
        p = subprocess.run([cmd], shell=True, universal_newlines=True, capture_output=True)
    except:
        colorVerificationFail("[!]", "Failed to generate PDF using pandoc.")
        sys.exit(10)
    
    if 'yes' == toArchive:
        archive_file = rpt_base + rpt_name + ".7z"
        colorVerification("[i]", "Generating 7z archive " + archive_file)
        cmd = '/usr/bin/7z a ' + archive_file + ' ' + rptFullPath
        try:
            p = subprocess.run([cmd], shell=True, universal_newlines=True, capture_output=True)
        except:
            colorVerificationFail("[!]", "Failed to generate 7z archive")
            sys.exit(15)

def getActivePath():
    active = session['Current']['active']
    if 'None' == active:
        colorNotice('No active engagement exists.  Use startup to create a new engagement.')
        sys.exit(30)
    else:
        return f"{session['Engagements'][active].split(',')[0]}"

def getActiveAll():
    active = session['Current']['active']
    if 'None' == active:
        colorNotice('No active engagement exists.  Use startup to create a new engagement.')
        sys.exit(30)
    else:
        return f"{session['Engagements'][active]}"

def getPandocStyle():
    colorNotice("\nFrom the following list, pick a syntax highlight style for code blocks?")
    colorNotice("   Recommendation: lighter styles are easier to read and use less ink if printed.")
    colorNotice("   Dark styles include: espresso, zenburn, and breezedark.")
    colorNotice("   Light styles include: pygments, tango, kate, monochrome, haddock")
    i = 0
    style_list = {}
    p = str(subprocess.run(["pandoc", "--list-highlight-styles"], 
                            check=True, 
                            universal_newlines=True, 
                            capture_output=True).stdout)
    output = p.splitlines(False)
    for s in output:
        colorList('\t' + str(i) + ". " + s)
        style_list[i] = s
        i += 1
    style_id = int(input('>  '))
    if style_id > i or style_id < 0:
        colorNotice('Invalid selection')
        getPandocStyle()
    return style_list[style_id]

def getNmapFile(target):
    # A listing of known good nmap output files.
    # In order: AutoRecon, nmapAutomator, and Reconnoitre
    nmapFiles = [f"_full_tcp_nmap.txt",
                 f"_quick_tcp_nmap.txt",
                 f"Full_{target}.nmap",
                 f"{target}.quick.nmap",
                 f"{target}.nmap"]
    
    for name in nmapFiles:
        for root, dirs, files in os.walk(getActivePath()):
            if name in files:
                nmapFile = os.path.join(root, name)
                return nmapFile

def ports():
    portsFile = f"{getActivePath()}/report/{portsSpreadsheet}"
    if os.path.isfile(portsFile):
        os.remove(portsFile)
    # Look for nmap output files associated with each target IP address
    with open(f"{getActivePath()}/targets.txt", 'r', encoding='utf-8', newline='') as t:
        allPorts = pd.DataFrame({})
        targets = t.readlines()
        for target in targets:
            target = target.strip()
            nmapFile = getNmapFile(target)
            if nmapFile == None:
                print('[!] Unable to find any nmap files.')
                break

            df = pd.DataFrame({})
            ip = ''
            port = '' 
            state = ''
            service = '' 
            version = ''
            with open(nmapFile, 'r', encoding='utf-8', newline='') as n:
                nmapContents = n.readlines()
                n.close()
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
                    version = re.sub(r'\(.*\)', '', ' '.join(fields[4:]))

                    if service == 'unrecognized':
                        continue
                    
                    newRow = {'IPADDRESS': ip,
                            'PORT': port, 
                            'STATE': state, 
                            'SERVICE': service, 
                            'VERSION': version}
                    df = df.append(newRow, ignore_index = True)
                    allPorts = allPorts.append(newRow, ignore_index = True)
            # Create worksheet per target
            colorVerification(target, f'Port Count: {str(len(df.index))}')
            #colorList(df.to_markdown())

            with pd.ExcelWriter(portsFile, engine='openpyxl') as writer:
                if os.path.exists(portsFile):
                    book = openpyxl.load_workbook(portsFile)
                else:
                    book = openpyxl.Workbook()
                
                writer.book = book
                sheetActive = book.active
                if 'Sheet' in book.sheetnames:
                    del book['Sheet']

                try:
                    df.to_excel(writer, sheet_name=target, index=False)
                    writer.save()
                    writer.close()
                except:
                    colorVerificationFail("[e]", "Unable to write to xlsx file.")
        colorList(allPorts.to_markdown())

        with pd.ExcelWriter(portsFile, engine='openpyxl') as writer:
            if os.path.exists(portsFile):
                book = openpyxl.load_workbook(portsFile)
            else:
                book = openpyxl.Workbook()
            
            writer.book = book
            sheetActive = book.active
            if 'Sheet' in book.sheetnames:
                del book['Sheet']

            try:
                allPorts.to_excel(writer, sheet_name='All Ports', index=False)
                writer.save()
                writer.close()
            except:
                colorVerificationFail("[e]", "Unable to write to xlsx file.")
    return allPorts

def sitrepAuto(msg):
    d = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    sitrepFile = f"{getActivePath()}/report/{sitrepLog}"
    #colorDebug(f"sitrepFile: {sitrepFile}")
    if os.path.exists(sitrepFile):
        with open(sitrepFile, 'a', encoding='utf-8', newline='') as f:
            f.write(f'{d} - {msg}\n')
            f.close()
    else:
        with open(sitrepFile, 'w', encoding='utf-8', newline='') as f:
            f.write(f'{d} - {msg}\n')
            f.close()
    colorNotice('sitrep logged')

def sitrepList():
    sitrepFile = f"{getActivePath()}/report/{sitrepLog}"
    if os.path.isfile(sitrepFile):
        colorHeader("    SITREP Log Entries    ")
        with open(sitrepFile) as f: 
            s = f.readlines()
            f.close()
        for l in s:
            fields = l.strip().split(" - ")
            colorVerification(fields[0], fields[1])
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
    else:
        vuln()

def vulnAdd():
    colorHeader("    Add Vulnerability    ")
    i = 0
    targetFile = f"{getActivePath()}/{targetsFile}"
    if os.path.isfile(targetFile):
        colorNotice("For which target?\nOr '99' to go back to the menu.")
        with open(targetFile) as f: 
            targets = f.readlines()
            f.close()
        for target in targets:
            target = target.strip()
            print(f'{i}.  {term.yellow}{target}{term.normal}')
            i = i + 1
        targetId = int(input(">  "))
        if 99 == targetId:
            vuln()
        else:
            target = targets[targetId].strip()
    else:
        print(f'{term.white}targets file is empty.{term.normal}\n\n')
    
    colorNotice("What is the port number [0-65535]?")
    port = int(input('>  '))
    if port < 1 or port > 65535:
        colorNotice("Number is outside the range of acceptable port numbers: 0 - 65535.")
        vuln()
    
    colorNotice("What is the name for this vulnerability?\n(eg. Remote code injection in Vendor_Product_Component)")
    vulnName = str(input('>  '))
    
    colorNotice("Describe the business impact: ")
    vulnImpact = str(input('>  '))
    
    colorNotice("What is the remediation?")
    remediation = str(input('>  '))
    
    colorNotice("Do you have a comment for where you left off? ")
    vulnComment = str(input('>  '))
    if len(vulnComment) > 0:
        sitrepAuto(vulnComment)
    
    rawCvss = getCvss3Score()
    cvssSeverity = rawCvss[0]
    cvssScore = rawCvss[1]
    cvssVector = rawCvss[2]
    mitreAttack = getMitreAttack()
    colorDebug(f"getMitreAttack returned: {str(mitreAttack)}")
    vulnMitreTactic = mitreAttack[0]
    vulnMitreTechnique = mitreAttack[1]
    
    colorNotice("\n-----------------------------\n  Verify the data entered.\n-----------------------------")
    colorVerification('[Target]                ',target)
    colorVerification('[Port]                  ',port)
    colorVerification('[Name]                  ',vulnName)
    colorVerification("[CVSS Overall Score]    ", str(cvssScore))
    colorVerification("[CVSS Severity]         ", cvssSeverity)
    colorVerification("[Business Impact]       ", vulnImpact)
    colorVerification("[Remediation    ]       ", remediation)
    colorVerification("[Comment]               ", vulnComment)
    colorVerification('[MITRE ATT&CK Tactic]   ', vulnMitreTactic)
    colorVerification('[MITRE ATT&CK Technique]', vulnMitreTechnique)
    
    checkPoint = str(input("\nAre these values correct? [Y|N]  > ")).upper()
    if checkPoint == "Y":
        row = f'{target},{port},{vulnName},{vulnImpact},{remediation},{vulnComment},{cvssScore},{cvssSeverity},{cvssVector},{vulnMitreTactic},{vulnMitreTechnique}'
        vulnCsvNewRow(row)
    else:
        print("[!] Reseting values")
        vulnName = ''
        vulnImpact = ''
        remediation = ''
        vulnCvss = ''
        vulnMitreTactic = ''
        vulnMitreTechnique = ''
        vulnComment = ''
        vulnAdd()
    vuln()

def vulnCsvNewRow(row):
    vulnsFile =  f"{getActivePath()}/report/{vulnsCsv}"
    if not os.path.isfile(vulnsFile):
        headings = 'IpAddress,Port,'
        headings += 'Name,Impact,Remediation,Comment'
        headings += ',CvssScore,CvssSeverity,CvssVector'
        headings += ',MitreTactic,MitreTechnique'
        with open(vulnsFile, 'a', encoding='utf-8') as f:
            f.write(headings + "\n")
            f.write(row + "\n")
            f.close()
    else:
        with open(vulnsFile, 'a', encoding='utf-8') as f:
            f.write(row + "\n")
            f.close()
    msg = f'Added new vulnerability: {str(row)}'
    sitrepAuto(msg)

def vulnList():
    colorHeader("    List of Current Vulnerabilities    ")
    vulnsFile =  f"{getActivePath()}/report/{vulnsCsv}"
    if os.path.exists(vulnsFile):
        df = pd.read_csv(vulnsFile, sep=",", engine="python") # , index_col=False
        colorList(df.to_markdown())
    else:
        print("0 vulnerabilities")
    if len(sys.argv) == 3 and 'list' == sys.argv[2]:
        sys.exit(0)    
    else:
        vuln()

def vulnModify():
    print("\n")
    vulnsFile =  f"{getActivePath()}/report/{vulnsCsv}"
    try:
        vm = pd.read_csv(vulnsFile)
    except:
        colorNotice('No vulnerabilities logged to modify.')
        vuln()
    rowCount = len(vm.index)
    headings = list(vm.columns.values)
    colorList(vm.to_markdown())
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
    with open(vulnsFile, 'w', newline='') as f:
        vm.to_csv(f, index=False)
        f.close()
    time.sleep(3)
    vuln()

def vulnRemove():
    # Replace with modification of vulnModify
    i = 0
    print("\n")
    vulnsFile =  f"{getActivePath()}/report/{vulnsCsv}"
    try:
        r = csv.reader(open(vulnsFile))
    except:
        colorNotice('No vulnerabilities logged to remove.')
        vuln()
    rows = list(r)
    for row in rows:
        colorList(str(i) + ") " + str(row))
        i += 1
    vulnId = int(input("\nPick an entry to remove or '99' to go back to the menu:  "))
    if 99 == vulnId:
        vuln()    
    # Bug: Get vuln name and log it with sitrep
    msg = "Remove vulnerability: " + str(rows[vulnId])
    sitrepAuto(msg)
    del rows[vulnId]
    with open(vulnsFile, 'w', newline='') as f:
        writer = csv.writer(f, delimiter=',')
        writer.writerows(rows)
        f.close()
    vuln()

def listEngagements():
    for e in session['Engagements']:
        colorVerification(e, session['Engagements'][e].split(',')[0])
    settingsMenu()

def settingsMenu():
    colorHeader('[    Settings    ]')
    colorMenuItem('1. Application-level settings')
    colorMenuItem('2. Engagement settings')
    colorMenuItem('3. Back to main menu')
    colorMenuItem('4. Quit')
    picker = int(input('>  '))
    
    if 1 == picker:
        # Application-level settings
        picker = 0
        colorSubHeading('Current Settings')
        colorMenuItem(f"1) Engagements will be stored in {str(appConfig['Paths']['pathwork'])}")
        colorMenuItem(f"2) Your name: {str(appConfig['Settings']['your_name'])}")
        colorMenuItem(f"3) Your student ID: {str(appConfig['Settings']['studentid'])}")
        colorMenuItem(f"4) Your email address: {str(appConfig['Settings']['email'])}")
        colorMenuItem(f"5) Preferred report format: {str(appConfig['Settings']['preferred_output_format'])}")
        colorMenuItem(f"6) Code block style: {str(appConfig['Settings']['style'])}")
        colorMenuItem(f"7) Settings menu")
        colorMenuItem(f"8) Main menu")
        colorMenuItem(f"\nPick a number to modify its setting")
        picker = int(input('>  '))

        if 8 <= picker:
            # return to main menu
            mainMenu()
        elif 1 == picker:
            # Set new engagements working directory
            colorNotice('What is the path to store future engagement subdirectories?')
            picker = str(input('>  '))
            if not os.path.isdir(picker):
                colorVerificationFail('[!]', f'{picker} is not a valid directory.  Creating...')
                try:
                    # If umask is not set, incorrect permissions will be assigned on mkdir
                    os.umask(0)
                    os.mkdir(picker, 0o770)
                except:
                    colorVerificationFail('[e]', f'Unable to create directory: {picker} ')
                    sys.exit(20)
            appConfig['Paths']['pathwork'] = picker
            saveConfig(appConfig)
        elif 2 == picker:
            # Set author name
            colorMenuItem('What is your full name as the report author?')
            picker = str(input('>  '))
            appConfig['Settings']['your_name'] = picker
            saveConfig(appConfig)
        elif 3 == picker:
            # Set student ID
            colorMenuItem('What is your student ID?')
            picker = str(input('>  '))
            appConfig['Settings']['studentid'] = picker
            saveConfig(appConfig)
        elif 4 == picker:
            # Set email address
            colorMenuItem('What is your email address?')
            picker = str(input('>  '))
            if (re.match(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', picker)):
                appConfig['Settings']['email'] = picker
                saveConfig(appConfig)
            else:
                colorNotice('Not an email formatted string.  Try again.')
                settingsMenu()
        elif 5 == picker:
            # Set preferred report format
            colorMenuItem(f"What is your preferred report format?  {appConfig['Settings']['preferred_output_format']}")
            i = 0
            for filetype in supported_filetypes.split(','):
                colorMenuItem(f'{i}) {filetype}')
                i += 1
            picker = int(input('>  '))
            if picker <= i:
                colorDebug(f"Setting > preferred report format: {supported_filetypes.split(',')[picker]}")
                appConfig['Settings']['preferred_output_format'] = supported_filetypes.split(',')[picker]
                saveConfig(appConfig)
            else:
                colorNotice('Invalid option.')
                settingsMenu()
        elif 6 == picker:
            # Set code block style
            appConfig['Settings']['style'] = getPandocStyle()
            saveConfig(appConfig)
        elif 7 == picker:
            # return to settings menu
            settingsMenu()
        else:
            # Unknown selection, return to settings menu
            settingsMenu()
    elif 2 == picker:
        # Engagement settings
        colorSubHeading('[    Engagement Settings    ]')
        colorNotice(f"Active engagement: {session['Current']['active']}")
        colorNotice(f"Total engagement: {str(len(session['Engagements']))}\n")
        colorMenuItem('1. Set a new active engagement')
        colorMenuItem('2. List all engagements')
        colorMenuItem('3. Back to main menu')
        colorMenuItem('4. Quit')
        picker = int(input('>  '))
        if picker == 3:
            mainMenu()
        elif picker == 4:
            sys.exit(0)
        elif picker > 4:
            settingsMenu()
        elif picker == 1:
            i = 0
            engagements = {}
            colorNotice('Pick a new active engagement')
            for e in session['Engagements']:
                colorMenuItem(f"{i}) {e} {session['Engagements'][e].split(',')[0]}")
                engagements[i] = e
                i += 1
            picker = int(input('>  '))
            if picker > i:
                settingsMenu()
            else:
                session['Current']['active'] = engagements[picker]
                saveEnagements()
                settingsMenu()
        elif picker == 2:
            listEngagements()
        sys.exit(255)

        colorNotice('Pick an engagement to make it active:')
        i = 0
        for s in session['Engagements']:
            colorMenuItem(f"{i}) {s} - {session['Engagements'][s].split(',')[0]}")
            i += 1
        picker = int(input('>  '))
        if picker <= i:
            colorNotice('set active, save')
            saveEnagements()
        else:
            colorVerificationFail('[!]', 'Invalid selection.')
            settingsMenu()
    elif 4 == picker:
        # quit
        sys.exit(23)
    else:
        # return to main menu
        mainMenu()
    settingsMenu()

def mainMenu():
    clearScreen()
    banner()
    colorHeader('[    Main Menu    ]')
    colorMenuItem('1. Startup')
    colorMenuItem('2. Vulnerabilities')
    colorMenuItem('3. Ports')
    colorMenuItem('4. SitRep Log')
    colorMenuItem('5. Finalize')
    colorMenuItem('6. Settings')
    colorMenuItem('7. Quit')
    picker = int(input('>  '))

    if 1 == picker:
        startup()
    elif 2 == picker:
        vuln()
    elif 3 == picker:
        ports()
    elif 4 == picker:
        sitrepMenu()
    elif 5 == picker:
        finalize()
    elif 6 == picker:
        settingsMenu()
    elif 7 == picker:
        sys.exit(0)
    else:
        mainMenu()

def params(argv):
    # Set routing action based on argument.  Otherwise, display help.
    action = sys.argv[1]
    if action == '-h' or action == '--help' or action == 'help':
        helper()
    elif action == '-s' or action == 'startup' or action == '--startup':
        startup()
    elif action == '-f' or action == 'finalize' or action == '--finalize':
        finalize()
    elif action == '-v' or action == 'vuln' or action == '--vuln':
        if len(sys.argv) == 3 and 'list' == sys.argv[2]:
            vulnList()
        else:
            vuln()
    elif action == '-i' or action == 'sitrep' or action == '--sitrep':
        if len(sys.argv) == 3 and 'list' == sys.argv[2]:
            sitrepList()
        elif len(sys.argv) > 3:
            msg = ' '.join(sys.argv[2:])
            sitrepAuto(msg)
        else:
            sitrepMenu()
    elif action == '-p' or action == 'ports' or action == '--ports':
        ports()
    else:
        mainMenu()

def loadAppConfig(pathConfig, appConfigFile):
    # Application-level settings configuration file
    # Exit without configuration file
    if not os.path.isdir(pathConfig):
        try:
            # If umask is not set, incorrect permissions will be assigned on mkdir
            os.umask(0)
            os.mkdir(pathConfig, 0o770)
        except:
            colorVerificationFail('[e]', f'Unable to create directory for AutoRpt settings: {pathConfig} ')
            sys.exit(20)

    if not os.path.isfile(appConfigFile):
        try:
            # copy configuration file from GitHub clone
            shutil.copy(appConfigFile, pathConfig)
        except:
            colorVerificationFail('[e]', f'Unable to copy configuration file from the GitHub clone: {appConfigFile}')
            sys.exit(20)
    
    config = configparser.ConfigParser()
    config.read(appConfigFile)
    return config

def loadSessionConfig(appSessionFile):
    if os.path.isfile(appSessionFile):
        config = configparser.ConfigParser()
        config.read(appSessionFile)
        return config
    else:
        colorNotice('The session file does not exist. It will be created on first use of startup.')

def saveConfig(appConfig):
    with open(appConfigFile, 'w') as configFile:
        appConfig.write(configFile)

def saveEnagements():
    with open(sessionFile, 'w') as configFile:
        session.write(configFile)

def debugConfig():
    colorVerification('autorpt_runfrom', autorpt_runfrom)
    colorVerification('main appConfig', appConfig.sections())
    for key in appConfig['Paths']:
        colorVerification('App working path for engagenments', appConfig['Paths'][key])
    colorVerification('main session', session.sections())
    colorVerification('Active Engagement', session['Current']['Active'])
    colorVerification('Active Engagement Details for name', activeSessionDetails)
    for key in session['Engagements']:
        colorVerification(f'Engagement: {key}', session['Engagements'][key].split(','))
    print('\n')
    colorVerification('supported filetypes', supported_filetypes)
    colorVerification('no templates', extentionsWithoutTemplate)
    colorVerification('target file', targetsFile)
    colorVerification('port XLSX', portsSpreadsheet)
    colorVerification('vuln CSV', vulnsCsv)
    colorVerification('sitrep Log', sitrepLog)

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
    # Define a terminal for color sugar
    term = blessings.Terminal(kind='xterm-256color')
    # Display pretty ASCII art
    banner()
    # Get the script home starting directory (eg. /opt/AutoRpt)
    autorpt_runfrom = os.path.dirname(os.path.realpath(__file__))
    # Directory for additional, supporting content.
    # Currently only the Mitre ATT&CK Framwork.
    pathIncludes: autorpt_runfrom + '/includes'
    # Path to store configuration settings and sessions
    pathConfig = os.path.expanduser("~/.config/AutoRpt")
    # Configuration settings
    appConfigFile = pathConfig + '/config.yml'
    # Load configuration settings
    appConfig = loadAppConfig(pathConfig, pathConfig + '/config.yml')
    # Engagement sessions
    sessionFile = pathConfig + '/' + appConfig['Files']['sessionFile']
    session = loadSessionConfig(sessionFile)
    # Details for the active engagement
    try:
        activeSessionDetails = session['Engagements'][session['Current']['active']].split(',')
    except:
        activeSessionDetails = ''
    # Should be supportedFiletypes
    supported_filetypes = appConfig['Settings']['output_formats']
    # Exclude filetypes that break report creation with pandoc
    # File with list of target IP addresses
    targetsFile = appConfig['Files']['targetFile']
    # Spreadsheet of all ports per IP address in targets file
    portsSpreadsheet = appConfig['Files']['portFile']
    # Validated list of vulnerabilities
    vulnsCsv =  appConfig['Files']['vulnFile']
    # Situation report
    sitrepLog =  appConfig['Files']['sitrepFile']
    
    # Take action based on parameters
    if len(sys.argv) <= 1:
        mainMenu()
    else:
        params(sys.argv[1:])
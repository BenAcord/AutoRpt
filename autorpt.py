#!/usr/bin/python3
"""
---
autorpt.py - Penetration testing report automatic generator
             Sets up a clean directory for note taking during 
             an exam or training then compiles the final report.
---------------------------------------------------------------------------------------------
"""

import blessings
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
from tabulate import tabulate
import time
import yaml

# Global variables
autorpt_runfrom = None
exam_name = None
email = None
student_id = None
style_name = None
supported_filetypes = ["PDF", "PDF+7z", "DOCX", "ODT", "JIRA", "COMMONMARK_X", "GFM"]
extentionsWithoutTemplate = ["DOCX"]
term = blessings.Terminal(kind='xterm-256color')
#portsFile = 'report/ports.xlsx'
portsSpreadsheet = 'report/ports.xlsx'
vulnsCsv = 'report/vulns.csv'
sitrepLog = 'report/sitrep.log'

def helper():
    colorNotice("USAGE:")
    colorNotice("autorpt.py [ help | startup | vuln | ports | sitrep \{message\}| finalize ]\n")
    colorNotice("WHERE:")
    colorNotice('  help:      Display this listing of usage and examples.')
    colorNotice('  startup:   Create a clean working directory for a new engagement.')
    colorNotice('  vuln:      Record a confirmed vulnerability with CVSS scoring and MITRE ATT&CK attributes.')
    colorNotice('  ports:     (AutoRecon specific) Quick display of all open ports per target.')
    colorNotice('  sitrep:    Record a status update of your current progress or display the menu.')
    colorNotice('  finalize:  Compile markdown files into a desired output file format.')

    colorNotice("\nEXAMPLES:")
    colorNotice("When you are ready to start an exam or training:")
    colorNotice("    autorpt.py startup")
    colorNotice("Log a verified vulnerability:")
    colorNotice("    autorpt.py vuln")
    colorNotice("Display vulnerability list:")
    colorNotice("    autorpt.py vuln list")
    colorNotice("Log your current status:")
    colorNotice("    autorpt.py sitrep pwned buffer overflow")
    colorNotice("Or")
    colorNotice("    autorpt.py sitrep Stuck trying to exploit system X:8001/login.php via SQLi.  May be a rabbit trail.")
    colorNotice("Or use the menu system:")
    colorNotice("    autorpt.py sitrep")
    colorNotice("Display the sitrep log:")
    colorNotice("    autorpt.py sitrep list")
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
    #colorDebug("Returning: " + str(returnStr))
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
    #colorDebug(path_includes + '  - Files: ' + str(csvFiles))
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

def startup(exam_name, email, student_id, style_name):
    # Startup pulls from script home
    autorpt_runfrom = os.path.dirname(os.path.realpath(__file__))
    
    if exam_name is None:
        templates_path_base = autorpt_runfrom + "/templates/"
        print("Available exam templates:")
        i = 0
        exam_list = {}
        for root, dirs, files in os.walk(templates_path_base):
            dirs.sort()
            for exam in dirs:
                if "report" != exam:
                    exam_list[i] = exam
                    print('\t' + str(i) + ".  " + exam)
                    i += 1

        try:
            exam_id = int(input("[+] Pick a number for the exam are you taking: "))
            exam_name = exam_list[exam_id]
        except:
            print("[!] Invalid number selected.")
            sys.exit(4)
        
        del exam_list
    else:
        print("[i] Exam name pulled from config file as " + exam_name)
    
    if "training" == exam_name:
        training_name = str(input("[+] What is the name of your target? (single word, no spaces) "))
        templates_path = autorpt_runfrom + '/templates/' + exam_name + '/'
        exam_path = './' + training_name + '/'
        rpt_path = training_name + '/'
    else:
        print("\n[i] Copying templates directory for the selected exam.")
        templates_path = autorpt_runfrom + '/templates/' + exam_name + '/'
        exam_path = './' + exam_name + '/'
        rpt_path = exam_name + '/'

    try:
        shutil.copytree(templates_path, rpt_path)
    except OSError as exc: # python >2.5
        print("[!] Copytree templates failed.  Trying copy.")
        try:
            shutil.copy(templates_path, rpt_path)
        except OSError as exc:
            print("[!] Copy templates failed. Done.")
            sys.exit(5)
    
    if "training" == exam_name:
        os.rename(rpt_path + "report/renameme.md", rpt_path + "report/" + training_name + ".md")
    
    print("[i] Templates successfully copied to report directory.  Here's the new structure:\n")
    
    # Display a directory tree for the exam
    paths = DisplayablePath.make_tree(Path(exam_path))
    for path in paths:
        print(path.displayable())

def finalize(exam_name, email, student_id, style_name):
    toArchive = 'No'
    rpt_base = './report/'
    rpt_date = datetime.datetime.now().strftime('%Y-%m-%d')
    
    # Student info only applies for exams and perhaps specific exams (eg OffSec)
    if 'oscp' == exam_name:    
        rpt_name = "OSCP_" + student_id + "_Exam_Report"
    else:
        rpt_name = "training_" + os.getcwd().split('/')[-1] + "_Report"
    
    if student_id is None:
        student_id = input("\n[+] What is your student ID, if required (eg. OS-12345, N/A)? ")
    else:
        print("[i] Student ID pulled from config file as " + student_id)
    
    if email is None:
        email = input("[+] What is your full email address? ")
    else:
        print("[i] Email address pulled from config file as " + email)

    # Rename as rptMarkdownFile
    rpt_filename = rpt_base + rpt_name + ".md"
    
    print("From these options: ")
    for (i, ext) in enumerate(supported_filetypes):
        print("\t" + str(i) + ") " + ext)
    picked = int(input("Pick an output format "))
    rptFormat = supported_filetypes[picked].lower()
    if rptFormat in ["commonmark_x", "jira", "gfm"]:
        rpt_extension = 'md'
    else:
        rpt_extension = rptFormat
    
    if '7z' in rpt_extension:
        toArchive = 'yes'
        rpt_extension = rpt_extension.split("+")[0]
        rptFullPath = rpt_base + rpt_name + "." + rpt_extension  # Rename as rptFullPathTargetFile
        print('toArchive? ' + toArchive + '\tExt: ' + str(rpt_extension) + '\tFile: ' + rptFullPath)
    else:
        rptFullPath = rpt_base + rpt_name + "." + rpt_extension  # Rename as rptFullPathTargetFile
        print('toArchive? ' + toArchive + '\tExt: ' + str(rpt_extension) + '\tFile: ' + rptFullPath)
    # Remove merged rpt md file if it already exists. Previous failed attempt.
    if os.path.exists(rpt_filename):
        try:
            os.remove(rpt_filename)
        except:
            print("[!] Error removing existing report file: " + rpt_filename)
            sys.exit(6)

    # Merge markdown sections into a single mardown for pandoc later
    md_file_list = glob(rpt_base + '[0-9]*.md')
    md_file_list = sorted(md_file_list)
    for file in md_file_list:
        colorDebug(f'Parsing {file} for boilerplate content replacing with Email: {email} RptDate: {rpt_date} StudentID: {student_id}')
        with open(file, 'r+') as f:
            file_contents = f.read()
            file_contents = re.sub('BOILERPLATE_EMAIL', email, file_contents)
            file_contents = re.sub('BOILERPLATE_DATE', rpt_date, file_contents)
            if "training" == exam_name:
                file_contents = re.sub('BOILERPLATE_HOSTNAME', 'targetName', file_contents)
                file_contents = re.sub('BOILERPLATE_OSID', '', file_contents)
            else:
                file_contents = re.sub('BOILERPLATE_OSID', student_id, file_contents)
                
            # Future Functionality: Some markdown for pasted images are incompatable with Pandoc 
            # and results in no images reaching the final report.
            # Rewrite all pasted screenshots "![[Pasted_image_A.png]]" 
            # in the format "![Pasted_image_A.png](Pasted_image_A.png)"
            file_contents = re.sub(r'\!\[\[Pasted_image_(\w+).png\]\]', 
                                   r'![Pasted_image_\1.png](Pasted_image_\1.png)', 
                                   file_contents)

            with open(rpt_filename, 'a') as result:
                result.write(file_contents + '\n')

    if style_name is None:
        print("\n[i] From the following list, what syntax highlight style should be used for code in the report?")
        print("   Recommendation: lighter styles are easier to read and use less ink if printed.")
        print("   Dark styles include: espresso, zenburn, and breezedark.")
        print("   Light styles include: pygments, tango, kate, monochrome, haddock")
        # Store pandoc code syntax highlight styles in a dictionary list
        i = 0
        style_list = {}
        p = str(subprocess.run(["pandoc", "--list-highlight-styles"], check=True, universal_newlines=True, capture_output=True).stdout)
        output = p.splitlines(False)
        for s in output:
            print('\t' + str(i) + ". " + s)
            style_list[i] = s
            i += 1
        style_id = int(input("[+] Pick a number for the style: "))
        style_name = style_list[style_id]
        print("[i] Style set to " + style_name)
    else:
        print("[i] Style pulled from config file as " + style_name)

    
    print("[i] Generating report " + rptFullPath)
    # Hack.  Use OS install of pandoc.
    # Need to figure out Pythonic pandoc module use.
    cmd = 'pandoc ' + rpt_filename
    cmd += ' --output=' + rptFullPath
    cmd += ' --from markdown+yaml_metadata_block+raw_html'
    cmd += ' --table-of-contents' 
    cmd += ' --toc-depth' + ' 6' 
    cmd += ' --number-sections'
    cmd += ' --top-level-division=chapter'
    cmd += ' --wrap=auto '
    cmd += ' --highlight-style ' + style_name
    cmd += ' -f ' + rptFormat
    if not rpt_extension in extentionsWithoutTemplate:
        # certain output formats break if a template is used
        print("[d] No template for extension " + rpt_extension + " not in list of exclusions: " + str(extentionsWithoutTemplate))
    else:
        cmd += ' --template' + ' eisvogel'
    
    print("[d] Pandoc command: " + cmd)

    try:
        p = subprocess.run([cmd], shell=True, universal_newlines=True, capture_output=True)
    except:
        print("[!] Failed to generate PDF using pandoc.")
        sys.exit(10)
    
    if 'yes' == toArchive:
        archive_file = rpt_base + rpt_name + ".7z"
        print("[i] Generating 7z archive " + archive_file)
        cmd = '/usr/bin/7z a ' + archive_file + ' ' + rptFullPath
        try:
            p = subprocess.run([cmd], shell=True, universal_newlines=True, capture_output=True)
        except:
            print("[!] Failed to generate 7z archive")
            sys.exit(15)

def ports():
    if os.path.isfile(portsSpreadsheet):
        os.remove(portsSpreadsheet)
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
                
                with pd.ExcelWriter(portsSpreadsheet, engine='openpyxl') as writer:
                    if os.path.exists(portsSpreadsheet):
                        book = openpyxl.load_workbook(portsSpreadsheet)
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
            else:
                print('[e] file does not exist: ' + nmapFile)
    return None

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
        #clearScreen()
        colorHeader("    SITREP Log Entries    ")
        with open(sitrepLog) as f: 
            s = f.readlines()
            f.close()
        for l in s:
            fields = l.strip().split(" - ")
            print(f'{term.bold_white_on_blue} {fields[0]} {term.normal} - {term.yellow}{fields[1]}{term.normal}')
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

def vulnAdd():
    colorHeader("    Add Vulnerability    ")
    colorNotice("What is the name for this vulnerability?\n(eg. Remote code injection in Vendor_Product_Component)")
    vulnName = str(input('>  '))
    colorNotice("Describe the business impact: ")
    vulnImpact = str(input('>  '))
    colorNotice("Do you have a comment for where you left off? ")
    vulnComment = str(input('>  '))
    if len(vulnComment) > 0:
        sitrepAuto(vulnComment)
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

def mainMenu():
    clearScreen()
    banner()
    colorHeader('[    Main Menu    ]')
    colorMenuItem('1. Startup')
    colorMenuItem('2. Vulnerabilities')
    colorMenuItem('3. SitRep Log')
    colorMenuItem('4. Finalize')
    colorMenuItem('5. Quit')
    picker = int(input('>  '))

    if 1 == picker:
        picker = str(input('are you in the directory you want to create working report subdirectories?  [Y/N]  '))
        colorVerificationFail('Warning!', 'No logic for validating Y or N.')
        startup()
    elif 2 == picker:
        vuln()
    elif 3 == picker:
        sitrepMenu()
    elif 4 == picker:
        finalize()
    elif 5 == picker:
        sys.exit(0)

def params(argv, exam_name, email, student_id, style_name):
    # Set routing action based on argument.  Otherwise, display help.
    action = sys.argv[1]
    if action == '-h' or action == '--help' or action == 'help':
        helper()
    elif action == '-s' or action == 'startup' or action == '--startup':
        startup(exam_name, email, student_id, style_name)
    elif action == '-f' or action == 'finalize' or action == '--finalize':
        finalize(exam_name, email, student_id, style_name)
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
    banner()

    # Get the script home starting directory
    autorpt_runfrom = os.path.dirname(os.path.realpath(__file__))
    
    if len(sys.argv) <= 1:
        mainMenu()
    else:
        params(sys.argv[1:], exam_name, email, student_id, style_name)
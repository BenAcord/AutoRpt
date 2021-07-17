#!/usr/bin/python3
#
#  poc.py - proof of concept testing for AutoRpt new features
#
from colorama import Fore, Style
import csv
import datetime
import getopt
from glob import glob
import json
import os
import pandas as pd
from pathlib import Path
import re
import shutil
import string
import subprocess
import sys
import time
import yaml
import xlsxwriter

# Global variables
autorpt_runfrom = None
exam_name = None
email = None
student_id = None
style_name = None


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
    sys.exit(2)

def finalize(exam_name, email, student_id, style_name):
    print("[i] finalize has no PoC functionality defined.")
    sys.exit(3)

def vuln():
    print("\nVULNERABILITIES\n")
    print("1. Add a new vulnerability")
    print("2. List all vulnerabilities")
    print("3. Modify an existing vulnerability")
    print("4. Remove a vulnerability")
    print("5. quit")
    vuln_selection = int(input("------------------------------\n[+] Pick a number: "))
    if vuln_selection == 1:
        vuln_add()
    elif vuln_selection == 2:
        vuln_list()
    elif vuln_selection == 3:
        vuln_modify()
    elif vuln_selection == 4:
        vuln_remove()
    elif vuln_selection == 5:
        sys.exit(0)

def vuln_add():
    print("TBD")
    vulnName = str(input("[+] What is the name for this vulnerability? (eg. Remote code injection in Vendor_Product_Component)  "))
    vulnImpact = str(input("[+] Describe the business impact: "))
    vulnCvss = float(input("[+] CVSS overall score: (eg. 8.1) "))
    #---
    # Future: Decide on how best to incorporate Mitre Python dependecies (update this dependencies)
    #         Worse case is to grab the 18mb enterprise_attack.json and parse on the fly.  Bad hack.
    #         There's also mobile_attack and ics_attack to incorporate as well.
    #         Use a Python list comprehension for column output in menu structure.
    #
    #         Potential menu prompts:
    #         Attack?  [enterprise, mobile, ics]
    #         Tactic?  [...]     #  Arranged in 4 columns wide with menu IDs
    #         Technique? [...]   #  Arranged in 4 columns wide listing with menu IDs
    #---
    # For now, free text Mitre ATT&CK input
    vulnMitreTactic = str(input("[+] What is the Mitre ATT&CK tactic?  (eg. Needs a menu from data source)  "))
    vulnMitreTechnique = str(input("[+] What is the Mitre ATT&CK technique?  (eg. Needs a menu from data source)  "))
    vulnComment = str(input("[+] Do you have a comment for where you left off? (eg. may be a rabbit trail or verified, etc."))
    print("\n-----------------------------\n  Verify the data entered.\n-----------------------------")
    print("Name: " + vulnName + "    CVSS Overall Score: " + str(vulnCvss))
    print("Business Impact: " + vulnImpact)
    print(vulnMitreTactic + " - " + vulnMitreTechnique)
    checkPoint = str(input("\n----------------------------------\n  Are these values correct? [Y|N]\n----------------------------------\n"))
    if checkPoint == "Y" or checkPoint == 'y':
        print("write vuln to CSV")
        #row = [ [vulnName, vulnCvss, vulnImpact, vulnMitreTactic, vulnMitreTechnique, vulnComment] ]
        row = [ {'Name': vulnName, 'CVSS': vulnCvss, 
                        'Impact': vulnImpact, 'MitreTactic': vulnMitreTactic, 
                        'MitreTechnique': vulnMitreTechnique, 
                        'Comment': vulnComment} ]
        vuln_csv_newrow(row)
    else:
        print("[!] Reseting values")
        vulnName = ''
        vulnImpact = ''
        vulnCvss = ''
        vulnMitreTactic = ''
        vulnMitreTechnique = ''
        vulnComment = ''
        vuln_add()
    vuln()

def vuln_csv_newrow(row):
    with open('report/vulns.csv', 'w', encoding='utf-8') as f:
            df1 = pd.DataFrame(row)
            df1.to_csv(f, index=False)
            f.close()
    msg = "Added new vulnerability: " + str(row)
    sitrep_auto(msg)

def vuln_test_load():
    if os.path.isfile('report/vulns.csv'):
        vuln()
    else:
        row = []
        for i in range(4):
            for a in string.ascii_lowercase[:4]:
                vulnName = str(i) + a
                vulnCvss = float(8.5)
                vulnImpact = vulnName + "-" + str(vulnCvss)
                vulnMitreTactic = "Tactic-TBD" + str(vulnCvss)
                vulnMitreTechnique = "Technique-TBD" + str(vulnCvss)
                vulnComment = "Something-" + vulnName
                row += [ {'Name': vulnName, 'CVSS': vulnCvss, 
                        'Impact': vulnImpact, 'MitreTactic': vulnMitreTactic, 
                        'MitreTechnique': vulnMitreTechnique, 
                        'Comment': vulnComment} ]
        with open('report/vulns.csv', 'w', encoding='utf-8') as f:
            df1 = pd.DataFrame(row)
            df1.to_csv(f, index=False)
            f.close()
        print("Completed loading test dataset to vuln.csv file.")

def vuln_list():
    print("\nLIST OF CURRENT VULNERABILITIES\n---------------------------------\n")
    with open("report/vulns.csv", "r") as csvfile:
        csvreader = csv.DictReader(csvfile)
        i = 0
        for row in csvreader:
            print(f'{str(i)})\t{row["Name"]}\t{row["Impact"]}\t{row["CVSS"]}\t{row["Comment"]}')
            #print(f'{str(i)})\t{row["Name"]}')
            i += 1
    vuln()

def vuln_modify():
    print("\n")
    vm = pd.read_csv("report/vulns.csv")
    rowCount = len(vm.index)
    print("Pandas row count: " + str(rowCount))
    headings = list(vm.columns.values)
    print(vm)

    vulnId = int(input("\n[+] Pick an entry to modify or '99' to go back to the menu:  "))
    if 99 == vulnId:
        vuln()
    
    print("\n" + str(headings))
    fieldId = str(input("[+] Type a column name to modify or 'm' to go back to the menu:  "))
    if 'm' == fieldId:
        vuln()
    if fieldId not in headings:
        print("INVALID HEADING")
        vuln()
    #oldValue = vm.at[vulnId, fieldId]
    if 'CVSS' == fieldId:
        newValue = float(input("[+] What is the new value?  "))
    else:
        newValue = str(input(f'[+] What is the new value?  '))
    print(f'[i] Column "{fieldId}" index {str(vulnId)} set to new value of: ' + str(newValue))
    vm.at[vulnId, fieldId] = newValue
    print(vm)
    msg = "Modified vulnerability at {str(vulnId)} {fieldId} to: " + newValue
    sitrep_auto(msg)
    with open('report/vulns.csv', 'w', newline='') as f:
        vm.to_csv(f, index=False)
        f.close()

    """
    line = rows[vulnId]
    print('[i] Original line values: ' + str(line))
    for i in range(6):
        rows[vulnId][i] = input("Old value: " + rows[vulnId][i] + "  New value: ")
    with open('report/vulns.csv', 'w', newline='') as f:
        writer = csv.writer(f, delimiter=',')
        writer.writerows(rows)
        f.close()
    """
    print('[i] Modified rows written to csv file.')
    time.sleep(3)
    vuln()

def vuln_remove():
    #  Most of this is duplicate code from Modifiy
    i = 0
    print("\n")
    r = csv.reader(open('report/vulns.csv'))
    rows = list(r)
    for row in rows:
        print(str(i) + ") " + str(row))
        i += 1

    vulnId = int(input("\n[+] Pick an entry to remove or '99' to go back to the menu:  "))
    if 99 == vulnId:
        vuln()    
    print("[i] You selected row " + str(vulnId))
    msg = "Remove vulnerability: " + rows[vulnId]
    sitrep_auto(msg)
    del rows[vulnId]
    with open('report/vulns.csv', 'w', newline='') as f:
        writer = csv.writer(f, delimiter=',')
        writer.writerows(rows)
        f.close()
    print('[i] Modified rows written to csv file.')
    time.sleep(3)
    vuln()

def find(filename, path):
  for root, dirs, files in os.walk(path):
    if filename in files:
      yield os.path.join(root, filename)

def ports():
    print('[i] Extracting all ports for each target into a single report CSV file.')
    portsFile = 'report/ports.xlsx'
    # For each target in targets.txt get the full path for _full_*_nmap.txt (autorecon specific)
    with open('targets.txt', 'r', encoding='utf-8', newline='') as t:
        targets = t.readlines()
        for target in targets:
            target = target.strip()
            nmapFile = './results/' + target + '/scans/_full_tcp_nmap.txt'
            print('[TARGET] ' + target)

            if os.path.isfile(nmapFile):
                with open(nmapFile, 'r', encoding='utf-8', newline='') as n:
                    nmapContents = n.readlines()
                    n.close()
                df = pd.DataFrame({})
                port = [] 
                state = []
                service = [] 
                version = []
                for line in nmapContents:
                    if re.match(r"^\d+.*$", line):
                        fields = line.strip().split()
                        # 0:port, 1:state, 2:service, 3:reason(skip), 4:version(glob)
                        port = fields[0]
                        state = fields[1]
                        service = fields[2]
                        version = ' '.join(fields[4:])
                        newRow = {'PORT': fields[0], 
                                  'STATE': fields[1], 
                                  'SERVICE': fields[2], 
                                  'VERSION': ' '.join(fields[4:])}
                        df = df.append(newRow, ignore_index = True)
                print("\tPort Count: " + str(len(df.index)) + "\n")
                with pd.ExcelWriter('report/ports.xlsx') as writer:
                    try:
                        df.to_excel(writer, sheet_name=target, index=False)
                    except:
                        print("[e] Unable to write to xlsx file.")
            else:
                print('[e] file does not exist: ' + nmapFile)
    
    
    # Show result file details
    sys.exit(255)


def sitrep_auto(msg):
    d = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    row = [ {'TIMESTAMP': d, 'SITREP': msg} ]
    # BUG: Header column names added for each new row.
    if os.path.isfile('report/sitrep.csv'):
        with open('report/sitrep.csv', 'a', encoding='utf-8', newline='') as f:
                sr = pd.DataFrame(row)
                sr.to_csv(f, index=False, header=False)
                f.close()
    else:
        with open('report/sitrep.csv', 'w', encoding='utf-8', newline='') as f:
                sr = pd.DataFrame(row)
                sr.to_csv(f, index=False, header=False)
                f.close()

def sitrep():
    # A stream of conscientiousness journal
    sitrepFile = 'report/sitrep.csv'
    print("\n[  SITREP  ]\n")
    print('  (s) Show all sitrep entries\n  (l) Log new sitrep\n  (q) quit\n')
    sitrepAction = str(input('What do you want to do?  '))
    if 'q' == sitrepAction:
        sys.exit(0)
    elif 's' == sitrepAction:
        if os.path.isfile(sitrepFile):
            sitrepLog = pd.DataFrame(pd.read_csv("report/sitrep.csv", names=['TIMESTAMP', 'COMMENT']))
            print("\n")
            print(sitrepLog)
            print("\n\n")
            time.sleep(3)
        else:
            print('[e] Sitrep file is empty.\n\n')
            time.sleep(2)
    elif 'l' == sitrepAction:
        d = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
        msg = str(input('[+] What is your current status? '))
        # sanitize here
        row = [ {'TIMESTAMP': d, 'SITREP': msg} ]
        # BUG: Header column names added for each new row.
        if os.path.isfile('report/sitrep.csv'):
            with open('report/sitrep.csv', 'a', encoding='utf-8', newline='') as f:
                    sr = pd.DataFrame(row)
                    sr.to_csv(f, index=False, header=False)
                    f.close()
        else:
            with open('report/sitrep.csv', 'w', encoding='utf-8', newline='') as f:
                    sr = pd.DataFrame(row)
                    sr.to_csv(f, index=False, header=False)
                    f.close()
    sitrep()

def params(argv, exam_name, email, student_id, style_name):
    # DEBUG
    print ('Number of arguments:', len(sys.argv), 'arguments.')
    print ('Argument List:', str(sys.argv))
    
    # Set routing action based on argument.  Otherwise, display help.
    action = sys.argv[1]
    #if len(sys.argv) == 2:
    #    action = sys.argv[1]
    #else:
    #    helper()
    # Action routes to function
    if action == '-h' or action == '--help' or action == 'help':
        helper()
    elif action == '-s' or action == 'startup' or action == '--startup':
        startup(exam_name, email, student_id, style_name)
    elif action == '-f' or action == 'finalize' or action == '--finalize':
        finalize(exam_name, email, student_id, style_name)
    elif action == '-v' or action == 'vuln' or action == '--vuln':
        vuln_test_load()
        vuln()
    elif action == '-r' or action == 'sitrep' or action == '--sitrep':
        msg = ' '.join(sys.argv[2:])
        print('Param glob debug: ' + msg)
        sitrep_auto(msg)
    elif action == '-r' or action == 'sitrep' or action == '--sitrep':
        sitrep()
    elif action == '-p' or action == 'ports' or action == '--ports':
        ports()
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

print(" ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄   ▄▄▄·▄▄▄▄▄")
print("▐█ ▀█ █▪██▌•██  ▪     ▀▄ █·▐█ ▄█•██  ")
print("▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄ ▐▀▀▄  ██▀· ▐█.▪")
print("▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█•█▌▐█▪·• ▐█▌·")
print(" ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀  ▀.▀    ▀▀▀ ")
print("              Tag your work\n\n")

# Global variables
autorpt_runfrom = None
exam_name = None
email = None
student_id = None
style_name = None

if __name__ == "__main__":
    # Get the script home starting directory
    autorpt_runfrom = os.path.dirname(os.path.realpath(__file__))

    if os.path.exists(autorpt_runfrom + '/config.yml'):
        config_file = open(autorpt_runfrom + '/config.yml', 'r')
        config_data = yaml.safe_load(config_file)
    else:
        config_data = None
    print("Debug config file values and yaml import")
    print("-------------------------------------------------------------")
    for x in config_data:
        print(x + ' - [' + str(config_data[x]) + ']')
    
    print("\n\nDebug Keys\n-------------------------------------------------------------")
    print('config_data keys: ' + str(config_data.keys()))
    print("\n\nDebug Values\n-------------------------------------------------------------")
    print('config_data values: ' + str(config_data.values()))
    print("-------------------------------------------------------------")
    #sys.exit(255)
    print("End Debug")

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
    
    print("==================================================\nDEBUG")
    print('exam type: ' + str(type(exam_name)) + ' Value: ' + exam_name)
    print('email type: ' + str(type(email)) + ' Value: ' + email)
    print('student_id type: ' + str(type(student_id)) + ' Value: ' + student_id)
    print('style_name type: ' + str(type(style_name)) + ' Value: ' + style_name)
    print("END DEBUG\n==================================================")

    # Parse parameters and route to functions
    params(sys.argv[1:], exam_name, email, student_id, style_name)
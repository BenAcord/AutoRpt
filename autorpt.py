#!/usr/bin/python3

"""
---
autorpt.py - Penetration testing report automatic generator
             Sets up a clean directory for taking an exam or training.

If you use Obsidian, which I highly recommend, open the report subdirectory as a new vault.
During the exam update markdown files report/1-5*.md.
Once the dust settles and the VPN drops the overarching report sections 0- and 6- can be written.

Dependencies
$ sudo apt-get install -y p7zip pandoc

--- Future Features
  1.  config - pre-answer most if not all prompts
  2.  Lab finalize prompt or config setting that compiles all md files in all subdirectories.
        This is for the Offensive Security course labs or PortSwigger's Web Security Academy.
        Compile all notes for a lab into a single PDF report.
---------------------------------------------------------------------------------------------
"""

import datetime
import getopt
from glob import glob
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import yaml

# Global variables
autorpt_runfrom = None
exam_name = None
email = None
student_id = None
style_name = None


def helper():
    print("[!] Use at your own risk.\n")

    print("AutoRpt is an exam preparation aid accomplishing two main reporting tasks:")
    print("1. (startup) Prior to starting an exam, it creates a base exam directory")
    print("   structure and populates it with a markdown report template.")
    print("   It is a good idea to run this well in advance of the exam start.\n")
    print("   An option exists for training against a single system (eg. Hack the Box, Try Hack Me, VulnHub, etc.).\n")
    print("2. (finalize) During the exam and after the VPN drops, autorpt generates")
    print("   a final PDF and 7z.\n")

    print("Usage: autorpt.py [ help | startup | vuln | sitrep | finalize ]\n")
    print("Examples:\n")
    print("  When you are ready to start an exam: autorpt.py startup")
    print("  Log a verified vulnerability: autorpt.py vuln")
    print("  Log your current status: autorpt.py sitrep pwned buffer overflow")
    print("\n  After the report is written: autorpt.py finalize")
    sys.exit(1)

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
        print("\n[i] Training should be a one-off, maybe(?).  Drop a single md into this directory")
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
    # Generate report PDF and 7z archive
    if student_id is None:
        student_id = input("\n[+] What is your student ID, if required (eg. OS-12345, N/A)? ")
    else:
        print("[i] Student ID pulled from config file as " + student_id)
    
    if email is None:
        email = input("[+] What is your full email address? ")
    else:
        print("[i] Email address pulled from config file as " + email)
    
    # List markdown files for merging into single report file
    rpt_base = './report/'

    # variables for reporting
    rpt_date = datetime.datetime.now().strftime('%Y-%m-%d')
    rpt_name = "OSCP_" + student_id + "_Exam_Report"
    rpt_filename = rpt_base + rpt_name + ".md"
    rpt_pdf = rpt_base + rpt_name + ".pdf"
    
    # Remove merged rpt md file if it already exists. Previous failed attempt.
    if os.path.exists(rpt_filename):
        try:
            os.remove(rpt_filename)
        except:
            print("[!] Error removing existing report file: " + rpt_filename)
            sys.exit(6)

    # Merge markdown sections into a single mardown for pandoc later
    # DEBUG: print("\n[i] Merging markdown file sections into a single report file: " + rpt_filename)
    md_file_list = glob(rpt_base + '[0-6]*.md')
    md_file_list = sorted(md_file_list)
    for file in md_file_list:
        # DEBUG: print("[i] Processing file: " + str(file))
        with open(file, 'r+') as f:
            file_contents = f.read()
            file_contents = re.sub('BOILERPLATE_EMAIL', email, file_contents)
            file_contents = re.sub('BOILERPLATE_OSID', student_id, file_contents)
            file_contents = re.sub('BOILERPLATE_DATE', rpt_date, file_contents)
            # Future Functionality: 
            # Rewrite all pasted screenshots "![[Pasted_image_A.png]]" 
            # in the format "![Pasted_image_A.png](Pasted_image_A.png)"
            with open(rpt_filename, 'a') as result:
                result.write(file_contents + '\n')

    # Get the code syntax style if not set in config file
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

    print("[i] Generating PDF report " + rpt_pdf)
    # Hack.  Use OS install of pandoc.
    # Need to figure out Pythonic pandoc module use.
    cmd = 'pandoc ' + rpt_filename
    cmd += ' --output=' + rpt_pdf
    cmd += ' --from markdown+yaml_metadata_block+raw_html'
    cmd += ' --template' + ' eisvogel'
    cmd += ' --table-of-contents' 
    cmd += ' --toc-depth' + ' 6' 
    cmd += ' --number-sections'
    cmd += ' --top-level-division=chapter'
    cmd += ' --wrap=auto '
    cmd += ' --highlight-style ' + style_name

    try:
        p = subprocess.run([cmd], shell=True, universal_newlines=True, capture_output=True)
    except:
        print("[!] Failed to generate PDF using pandoc.")
        sys.exit(10)
    
    # 7zip the PDF
    archive_file = rpt_base + rpt_name + ".7z"
    print("[i] Generating 7z archive " + archive_file)
    cmd = '/usr/bin/7z a ' + archive_file + ' ' + rpt_pdf
    try:
        p = subprocess.run([cmd], shell=True, universal_newlines=True, capture_output=True)
    except:
        print("[!] Failed to generate 7z archive")
        sys.exit(15)


def params(argv, exam_name, email, student_id, style_name):
    # DEBUG
    print ('Number of arguments:', len(sys.argv), 'arguments.')
    print ('Argument List:', str(sys.argv))
    
    # Set routing action based on argument.  Otherwise, display help.
    if len(sys.argv) == 2:
        action = sys.argv[1]
    else:
        helper()
    # Action routes to function
    if action == '-h' or action == '--help' or action == 'help':
        helper()
    elif action == 's' or action == 'startup' or action == '--startup':
        startup(exam_name, email, student_id, style_name)
    elif action == 'f' or action == 'finalize' or action == '--finalize':
        finalize(exam_name, email, student_id, style_name)
    elif action == 'v' or action == 'vuln' or action == '--vuln':
        print('autorpt vuln menu\n1.Add new vulnerability\n2. Modify existing vulnerability\n3. Remove existing vulnerability\n\nPlease make a selection: ')
        sys.exit(255)
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
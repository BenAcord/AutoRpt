#!/usr/bin/python3
"""
autorpt_work.py
Workflow processes and tasking.
"""

import datetime
from glob import glob
import os
import shutil
import sys
import re
import autorpt_cfg as cfg
import autorpt as core
import autorpt_pretty as out

def iterate_closing_file(active_engagement_path, active_lab_files):
    """ Increment the file number for closing.md """

    # Locate the highest numbered lab file.
    holder = 1
    for this_file_name in active_lab_files:
        #i_num = int(this_file_name.split('-')[0])
        i_num = get_file_id(this_file_name)
        if i_num > holder:
            holder = i_num
    holder = holder + 1

    active_closing_file = glob(f'{active_engagement_path}/report/*-closing.md')[0]
    closing_inum_original = get_file_id(active_closing_file)
    # Increment the closing file iterator if it is less than or equal to the new lab file iterator.
    closing_inum_new =  closing_inum_original + 1

    if closing_inum_new <= holder:
        closing_inum_new = holder + 1
    source_file = f"{active_engagement_path}/report/{closing_inum_original}-closing.md"
    dest_file = f"{active_engagement_path}/report/{closing_inum_new}-closing.md"
    move_file(source_file, dest_file)
    return holder

def move_file(source_file, dest_file):
    """ Move a source file to a new destination filename. """
    try:
        shutil.move(source_file, dest_file)
    except (FileNotFoundError, PermissionError, IOError, OSError):
        out.color_fail("File Move", "Unable to move the file [{source_file}] to [{dest_file}].")
        sys.exit(20)

def copy_file(source_file, dest_file):
    """ Move a source file to a new destination filename. """
    # Copy in the new template file as a new lab interated file.
    try:
        shutil.copyfile(source_file, dest_file)
    except (FileNotFoundError, PermissionError, IOError, OSError):
        this_msg = "Unable to copy the source template to the active report destination."
        out.color_fail("Add Template", this_msg)
        sys.exit(21)

def get_file_id(this_file_name):
    """ For a provided filename, return its file ID prefix. """
    return int(re.search(r'/(\d+)-.*.md', this_file_name).group(1))

def add_template():
    """Function to copy a new template to the active engagement"""

    # holder is the baseline ID iterator for a filename.  0 is always execsummary.
    #holder = 1
    active_engagement_path = cfg.get_active_path()
    active_lab_files = glob(f'{active_engagement_path}/report/[1-9]*.md')
    # Remove the closing file from the list of files.
    active_lab_files = [f for f in active_lab_files if 'closing' not in f]

    holder = iterate_closing_file(active_engagement_path, active_lab_files)
    new_lab_file_name = str(holder) + "-template.md"

    # Get the lab file iterator, ignoring 0 and the highest value (ie. execsummary and closing).
    source_path = cfg.session[cfg.session['Current']['active']]['source_path']
    source_file = f"{source_path}/report/z-template.md"
    dest_file = f"{active_engagement_path}/report/{new_lab_file_name}"
    print(f'Copying template to file number {str(holder)}')
    copy_file(source_file, dest_file)

    # Log action
    sitrep_auto('Added new template to the active engagement.')

def add_target(ip_address):
    """Function to add a new target IP address and template file."""
    # Not all training requires an IP address.

    active_engagement_path = cfg.get_active_path()
    # Manually get a new IP address for the targets file and copy in a new template.
    if ip_address == '':
        # Prompt for target IP address
        out.color_notice('Do you know the target IP address or hostname?  Or enter "N" to skip.')
        ip_address = str(input('>  ')).replace(" ", "").lower()
        if ip_address == 'n':
            out.color_fail('No IP Address or hostname provided', "An IP Address is required.")
            sys.exit(22)
    # Check if the value already exists in the file.
    with open(
        f'{active_engagement_path}/{cfg.targets_file}',
        "r",
        encoding="utf8"
    ) as targets_file_reader:
        targets_file_contents = targets_file_reader.read()
    if ip_address in targets_file_contents:
        out.color_fail(
            'Duplicate Target',
            'This value already exists in the targets file.  '
            'Will not create its template file as it may already exist.  '
            'If you want a fresh template file without adding an entry to the targets.md file '
            'use the addtemplate functionality.'
        )
    else:
        # Update targets with a new IP address
        print(
            f'Injecting {ip_address} into target file '
            f'{active_engagement_path}/{cfg.targets_file}.'
        )
        with open(f'{active_engagement_path}/{cfg.targets_file}', 'a') as target_file_writer: # pylint: disable=unspecified-encoding
            target_file_writer.write(f'{ip_address}\n')

        # holder is the baseline ID iterator for a filename.  0 is always execsummary.
        #holder = 1
        active_engagement_path = cfg.get_active_path()
        active_lab_files = glob(f'{active_engagement_path}/report/[1-9]*.md')
        # Remove the closing file from the list of files.
        active_lab_files = [f for f in active_lab_files if 'closing' not in f]
        # Rotate the closing file to the next iterative number.
        holder = iterate_closing_file(active_engagement_path, active_lab_files)
        new_lab_file_name = f"{str(holder)}-{ip_address}.md"

        source_path = cfg.session[cfg.session['Current']['active']]['source_path']
        source_file = f"{source_path}/report/z-template.md"
        dest_file = f"{active_engagement_path}/report/{new_lab_file_name}"
        print(f'Copying template to file number {str(holder)}')
        copy_file(source_file, dest_file)

        # Log action
        sitrep_auto(f'Added new target: {ip_address}')

def sitrep_auto(this_msg):
    """Automatically, without prompting, write the this_msg to the sitrep file."""
    this_dataframe = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    sitrep_file = f"{cfg.get_active_path()}/report/{cfg.sitrepLog}"
    if os.path.exists(sitrep_file):
        with open(sitrep_file, 'a', encoding='utf-8', newline='') as sitrep_file_writer:
            sitrep_file_writer.write(f'{this_dataframe} - {this_msg}\n')
            sitrep_file_writer.close()
    else:
        with open(sitrep_file, 'w', encoding='utf-8', newline='') as sitrep_file_writer:
            sitrep_file_writer.write(f'{this_dataframe} - {this_msg}\n')
            sitrep_file_writer.close()
    # Update the engagement status
    active = cfg.session['Current']['active']
    cfg.session[active]['status'] = 'In-process'
    cfg.save_enagements()

def sitrep_list():
    """Display the contents of the sitrep file"""
    sitrep_file = f"{cfg.session[cfg.session['Current']['active']]['path']}"
    sitrep_file += f"/report/{cfg.sitrepLog}"
    if os.path.isfile(sitrep_file):
        out.color_header("SITREP Log Entries")
        with open(sitrep_file) as sitrep_file_writer: # pylint: disable=unspecified-encoding
            sitrep_content = sitrep_file_writer.readlines()
            sitrep_file_writer.close()
        for sitrep_line in sitrep_content:
            fields = sitrep_line.strip().split(" - ")
            out.color_verify(fields[0], fields[1])
    else:
        print(f'{out.term.white}Sitrep file is empty.{out.term.normal}\n\n')

def sitrep_new():
    """Manually prompt for the sitrep message."""
    sitrep_auto(str(input('What is your current status? ')))
    sitrep_menu()

def sitrep_menu():
    """A stream of status journal."""
    out.color_header('SITREP  (Situation Report)')
    out.color_menu_item('1. List all sitrep entries')
    out.color_menu_item('2. Add new sitrep log entry\n')
    out.color_menu_item('3. Main Menu')
    out.color_menu_item('4. Quit')
    sitrep_action = int(input('>  '))
    if 4 == sitrep_action:
        sys.exit(0)
    elif 3 == sitrep_action:
        core.main_menu()
    elif 1 == sitrep_action:
        sitrep_list()
    elif 2 == sitrep_action:
        sitrep_new()
    sitrep_menu()

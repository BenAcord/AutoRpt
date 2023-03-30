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
import pandas as pd
import autorpt.cfg as cfg # pylint: disable=import-error,consider-using-from-import
import autorpt.main as main # pylint: disable=import-error,consider-using-from-import
from autorpt.pretty import term, color_header, color_subheading, color_verify # pylint: disable=import-error
from autorpt.pretty import color_menu_item, color_fail, color_notice # pylint: disable=import-error


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
    # Increment the closing file iterator if it is less than or equal to
    # the new lab file iterator.
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
        color_fail(
            "File Move", "Unable to move the file [{source_file}] to [{dest_file}]."
        )
        sys.exit(20)

def copy_file(source_file, dest_file):
    """ Move a source file to a new destination filename. """
    # Copy in the new template file as a new lab interated file.
    try:
        shutil.copyfile(source_file, dest_file)
    except (FileNotFoundError, PermissionError, IOError, OSError):
        color_fail(
            "Add Template",
            "Unable to copy the source template to the active report destination."
        )
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
    source_path = cfg.SESSION[
        cfg.SESSION['Current']['active']]['source_path'
    ]
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
        color_notice(
            'Do you know the target IP address or hostname?  Or enter "N" to skip.'
        )
        ip_address = str(input('>  ')).replace(" ", "").lower()
        if ip_address == 'n':
            color_fail(
                'No IP Address or hostname provided', "An IP Address is required."
            )
            sys.exit(22)
    # Check if the value already exists in the file.
    with open(
        f'{active_engagement_path}/{cfg.TARGETS_FILE}',
        "r",
        encoding="utf8"
    ) as targets_file_reader:
        targets_file_contents = targets_file_reader.read()
    if ip_address in targets_file_contents:
        color_fail(
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
            f'{active_engagement_path}/{cfg.TARGETS_FILE}.'
        )
        with open(
            f'{active_engagement_path}/{cfg.TARGETS_FILE}',
            'a',
            encoding='utf8'
        ) as target_file_writer: # pylint: disable=unspecified-encoding
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

        source_path = cfg.SESSION[
            cfg.SESSION['Current']['active']]['source_path'
        ]
        source_file = f"{source_path}/report/z-template.md"
        dest_file = f"{active_engagement_path}/report/{new_lab_file_name}"
        print(f'Copying template to file number {str(holder)}')
        copy_file(source_file, dest_file)

        # Log action
        sitrep_auto(f'Added new target: {ip_address}')

def sitrep_auto(this_msg):
    """Automatically, without prompting, write the message to the sitrep file."""
    this_dataframe = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    sitrep_file = f"{cfg.get_active_path()}/report/{cfg.SITREP_LOG}"
    if os.path.exists(sitrep_file):
        with open(sitrep_file, 'a', encoding='utf-8', newline='') as sitrep_file_writer:
            sitrep_file_writer.write(f'{this_dataframe} - {this_msg}\n')
            sitrep_file_writer.close()
    else:
        with open(sitrep_file, 'w', encoding='utf-8', newline='') as sitrep_file_writer:
            sitrep_file_writer.write(f'{this_dataframe} - {this_msg}\n')
            sitrep_file_writer.close()
    # Update the engagement status
    active = cfg.SESSION['Current']['active']
    cfg.SESSION[active]['status'] = 'In-process'
    cfg.save_engagements(cfg.SESSION)

def sitrep_list():
    """Display the contents of the sitrep file"""
    sitrep_file = (
        f"{cfg.SESSION[cfg.SESSION['Current']['active']]['path']}"
    )
    sitrep_file += f"/report/{cfg.SITREP_LOG}"
    if os.path.isfile(sitrep_file):
        color_header("SITREP Log Entries")
        with open(sitrep_file) as sitrep_file_writer: # pylint: disable=unspecified-encoding
            sitrep_content = sitrep_file_writer.readlines()
            sitrep_file_writer.close()
        for sitrep_line in sitrep_content:
            fields = sitrep_line.strip().split(" - ")
            color_verify(fields[0], fields[1])
    else:
        print(
            f'{term.white}'
            f'Sitrep file is empty.{term.normal}\n\n'
        )

def sitrep_new():
    """Manually prompt for the sitrep message."""
    sitrep_auto(str(input('What is your current status? ')))
    sitrep_menu()

def sitrep_menu():
    """A stream of status journal."""
    color_header('SITREP  (Situation Report)')
    color_menu_item('1. List all sitrep entries')
    color_menu_item('2. Add new sitrep log entry\n')
    color_menu_item('3. Main Menu')
    color_menu_item('4. Quit')
    sitrep_action = int(input('>  '))
    if 4 == sitrep_action:
        sys.exit(0)
    elif 3 == sitrep_action:
        main.main_menu()
    elif 1 == sitrep_action:
        sitrep_list()
    elif 2 == sitrep_action:
        sitrep_new()
    sitrep_menu()

def whathaveidone():
    """Summary analysis of session engagements."""

    status_type_df = pd.DataFrame({})
    status_platform_df = pd.DataFrame({})
    status = []
    types = []
    platforms = []

    for key in cfg.SESSION.sections():
        if key not in ['DEFAULT', 'Current']:
            status.append(cfg.SESSION[key]['status'])
            types.append(cfg.SESSION[key]['type'])
            platforms.append(cfg.SESSION[key]['platform'])

    new_row = {'STATUS': status, 'TYPE': types, 'COUNT': platforms}
    status_type_df = pd.DataFrame(new_row)

    new_row = {'STATUS': status, 'COUNT': types, 'PLATFORM': platforms}
    status_platform_df = pd.DataFrame(new_row)

    color_header("Activity Summary")
    color_notice(
        pd.pivot_table(status_type_df,
            index=['TYPE'],
            columns=['STATUS'],
            aggfunc='count',
            values=['COUNT'],
            fill_value=0,
            margins=True,
            dropna=True
        )
    )

    color_notice(
        f'\n{term.bold}Total number of enagements: '
        f'{status_type_df.shape[0]}{term.normal}\n'
    )

    color_subheading("\nCount of engagements by Platform")
    color_notice(
        pd.pivot_table(status_platform_df,
            index=['PLATFORM'],
            columns=['STATUS'],
            aggfunc='count',
            values=['COUNT'],
            fill_value=0,
            margins=True,
            dropna=True
        )
    )

    if status_type_df.shape[0] >= 100:
        color_notice(
            f"\nDo you want to see a summary of all {status_type_df.shape[0]} entries?  [ Y | N ]"
        )
        picker = input('>  ')
        if picker not in [ "Y", "y", "Yes", ]:
            sys.exit(0)

    color_subheading("\nDetails")
    session_details = {}
    for key in cfg.SESSION.sections():
        if key not in ['DEFAULT', 'Current']:
            session_details[key] = cfg.SESSION[key]['status']


    sorted_by_status = dict(sorted(session_details.items(), key=lambda item: item[1]))

    for this_key, this_value in sorted_by_status.items():
        if "Finalized" == this_value:
            print(
                f'{term.red}'
                f'{this_value:15} '
                f'{this_key}{term.normal}'
            )
        elif "Started" == this_value:
            print(
                f'{term.bright_green}'
                f'{this_value:15}\t'
                f'{this_key}{term.normal}'
            )
        else:
            print(
                f"{term.bright_yellow}"
                f'{this_value:15}\t'
                f'{this_key}{term.normal}'
            )

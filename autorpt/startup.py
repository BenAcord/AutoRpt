#!/usr/bin/python3
"""
Create a new engagement work environment.
"""

import datetime
import os
import re
import shutil
import sys
import time
import autorpt.cfg as cfg # pylint: disable=import-error,consider-using-from-import
import autorpt.main as main # pylint: disable=import-error,consider-using-from-import
from autorpt.pretty import color_fail, color_notice, color_header, color_menu_item # pylint: disable=import-error
from autorpt.work import sitrep_auto # pylint: disable=import-error

def startup():
    """Initialize a new engagement"""
    color_header('Startup')

    # Get Settings.
    student_name = cfg.CONFIG_VALUES['Settings']['your_name']
    student_email = cfg.CONFIG_VALUES['Settings']['email']

    # If blank settings prompt for value.  Write out config before proceeding.
    # Prompt to reuse or enter new psuedonym
    if '' == student_name:
        color_notice('What is your name?')
        student_name = (str(input('>  ')))
    if '' == student_email:
        color_notice('What is your email?')
        student_email = (str(input('>  ')))

    # Write new config.toml
    cfg.save_config(cfg.CONFIG_VALUES)

    # Get the engagement type: training, ctf, exam, bugbounty, pentest
    color_notice("Select the type of engagement:")
    main.dictionary_to_menu(cfg.CONFIG_VALUES['Settings']['types'])
    picker = int(input('>  '))
    if 99 == picker:
        main.main_menu()
    elif picker >= int(main.dictionary_to_menu(
        cfg.CONFIG_VALUES['Settings']['types'])
    ):
        main.main_menu()
    else:
        engagement_type = cfg.CONFIG_VALUES['Settings']['types'].split(',')[picker]

    set_default_template_path(engagement_type, student_name, student_email)

    cfg.get_the_active_engagement()
    time.sleep(0.5)

def set_training_engagement():
    """ Define values for a training engagement. """
    # Get the platform
    color_notice(
        'Select the training platform or 80 to add a custom platform or 99 for main menu'
    )

    # List easy to read names
    templates_path = f"{cfg.AUTORPT_RUNFROM}/templates/training/plain"
    target_ip = ''
    platform_list = []
    for key in cfg.CONFIG_VALUES['Training']:
        platform_list.append(key)

    # List directory friendly names (eg. no spaces)
    providers = main.section_to_menu(cfg.CONFIG_VALUES['Training'])

    # Get section of the platform
    picker = int(input('>  '))
    if picker == 99:
        main.main_menu()
    elif picker == 80:
        color_notice('Enter the name of the custom platform')
        platform = str(input('>  ')).replace(" ", "").lower()
        platform_name = platform
        # Get the box name
        color_notice('What is the box name?')
        color_notice('(eg. waldo, kenobi, etc.')
        engagement_name = str(input('>  ')).replace(" ", "").lower()
        # Get target IP address
        color_notice(
            'Do you know the target IP address?  Or enter "N" to skip.'
        )
        target_ip = str(input('>  ')).replace(" ", "").lower()
    elif picker <= 6:
        # Set the easy to read platform name
        platform_name = platform_list[picker]
        # Set the directory friendly platform name
        platform = cfg.CONFIG_VALUES["Training"][platform_name]
        # Get the box name
        color_notice('What is the box name?')
        color_notice('(eg. waldo, kenobi, etc.')
        engagement_name = str(input('>  ')).replace(" ", "").lower()
        color_notice(
            'Do you know the target IP address?  Or enter "N" to skip.'
        )
        target_ip = str(input('>  ')).replace(" ", "").lower()
    else:
        # Set the easy to read platform name
        platform_name = platform_list[picker]
        # Set the directory friendly platform name
        #platform = config_values["Training"][platform_name]
        platform = 'offensivesecurity'
        engagement_name = providers[picker]
        templates_path = f"{cfg.AUTORPT_RUNFROM}"
        templates_path = f"{templates_path}/templates/training/"
        templates_path = f"{templates_path}/{engagement_name}"
    return_values = []
    return_values = [platform, engagement_name, templates_path, platform_name, target_ip]
    return return_values

def set_bugbounty_engagement():
    """ Define values for a bug bounty engagement. """

    templates_path = f'{cfg.AUTORPT_RUNFROM}/templates/training/bugbounty/'
    target_ip = ''
    # Get the platform
    color_notice('Enter the platform or company name:')
    providers = main.section_to_menu(cfg.CONFIG_VALUES['Bug Bounty'])
    picker = int(input('>  '))
    if 3 == picker:
        platform_name = str(input('What is your penetration testing company name?  '))
    else:
        platform_name = providers[picker]
    platform = platform_name.lower()
    platform = platform.replace("'", "")
    platform = platform.replace('"', "")
    platform = platform.replace('`', '')
    platform = platform.replace('/', '')
    platform = platform.replace('\\', '')
    platform = platform.replace(" ", "")
    # Get the program name
    color_notice('What is the program name?')
    color_notice('(eg. Tesla, Domain.com, etc.')
    engagement_name = str(input('>  ')).replace('\s+', '').lower() # pylint: disable=anomalous-backslash-in-string
    engagement_name = engagement_name.replace("'", "")
    engagement_name = engagement_name.replace('"', "")
    engagement_name = engagement_name.replace('`', '')
    engagement_name = engagement_name.replace(' ', '')
    return_values = []
    return_values = [platform, engagement_name, templates_path, platform_name, target_ip]
    return return_values

def set_ctf_engagement():
    """ Define values for a CTF engagement. """

    target_ip = ''

    # Get the engagement name
    color_notice('What is the name of this CTF event?')
    platform = str(input('>  '))
    platform_name = platform
    platform = platform.lower()
    platform = platform.replace("'", "")
    platform = platform.replace('"', "")
    platform = platform.replace('`', '')
    platform = platform.replace('/', '')
    platform = platform.replace('\\', '')
    platform = platform.replace(" ", "")
    # Get the engagement name
    color_notice('What is the team name?')
    engagement_name = str(input('>  ')).lower()
    engagement_name = engagement_name.replace("'", "")
    engagement_name = engagement_name.replace('"', "")
    engagement_name = engagement_name.replace('`', '')
    engagement_name = engagement_name.replace(' ', '')
    templates_path = f'{cfg.AUTORPT_RUNFROM}/templates/training/plain/'
    return_values = []
    return_values = [platform, engagement_name, templates_path, platform_name, target_ip]
    return return_values

def set_exam_engagement():
    """ Define values for an exam engagement. """

    target_ip = ''

    # pick the exam
    color_notice('Select the exam')
    i = 0
    exams = []
    for item in cfg.CONFIG_VALUES['Exams']:
        exam_name = cfg.CONFIG_VALUES['Exams'][item].split(',')[1]
        color_menu_item(str(i) + ".  " + exam_name)
        exams.append(item)
        i += 1
    color_menu_item('99. for main menu')
    picker = int(input('>  '))
    if 99 == picker:
        main.main_menu()
    platform = cfg.CONFIG_VALUES['Exams'][exams[picker]].split(',')[0]
    platform_name = cfg.CONFIG_VALUES['Exams'][exams[picker]].split(',')[1]
    engagement_name = exams[picker]
    templates_path = f'{cfg.AUTORPT_RUNFROM}/templates/{engagement_name}'
    return_values = []
    return_values = [platform, engagement_name, templates_path, platform_name, target_ip]
    color_notice(
        'Remember to set your student information in Settings '
        '(i.e. OSID, name, email address, etc.'
    )
    # Copy the template to the engagement directory
    return return_values

def set_pentest_engagement():
    """ Define values for a pentest engagement. """

    templates_path = f"{cfg.AUTORPT_RUNFROM}/templates/training/plain"
    target_ip = ''

    # Company performing the test
    platform_name = str(input('What is your penetration testing company name?  '))
    platform = platform_name.lower()
    platform = platform.replace("'", "")
    platform = platform.replace('"', "")
    platform = platform.replace('`', '')
    platform = platform.replace('/', '')
    platform = platform.replace('\\', '')
    platform = platform.replace(" ", "")
    # Client name
    color_notice('What is the client name?')
    engagement_name = str(input('>  ')).replace('\s+', '').lower() # pylint: disable=anomalous-backslash-in-string
    engagement_name = engagement_name.replace("'", "")
    engagement_name = engagement_name.replace('"', "")
    engagement_name = engagement_name.replace('`', '')
    engagement_name = engagement_name.replace(' ', '')
    return_values = []
    return_values = [platform, engagement_name, templates_path, platform_name, target_ip]
    return return_values

def set_output_format():
    """ Structure for the format. """

    color_notice(
        'Do you have a preferred output format for the final report?  Press Enter for none.'
    )
    main.dictionary_to_menu(
        cfg.CONFIG_VALUES['Settings']['output_formats']
    )
    picker = int(input('>  '))
    if picker <= int(
        main.dictionary_to_menu(
            cfg.CONFIG_VALUES['Settings']['output_formats']
        )
    ):
        return cfg.CONFIG_VALUES['Settings']['output_formats'].split(',')[picker]
    return None

def set_default_template_path(engagement_type, student_name, student_email):
    """ Set the default path for templates. """

    # Set default path for templates. Only exams are unique.
    style = cfg.CONFIG_VALUES['Settings']['style']
    output_format = cfg.CONFIG_VALUES['Settings']['preferred_output_format']
    input_values = []
    if 'training' == engagement_type:
        input_values = set_training_engagement()
    elif 'bugbounty' == engagement_type:
        input_values = set_bugbounty_engagement()
    elif 'ctf' == engagement_type:
        input_values = set_ctf_engagement()
    elif 'exam' == engagement_type:
        input_values = set_exam_engagement()
    elif 'pentest' == engagement_type:
        input_values = set_pentest_engagement()
    else:
        main.main_menu()

    # Set the preferred output format or set to null
    if engagement_type == "exam" and input_values[0] == 'offensivesecurity':
        output_format = 'pdf+7z'
    if '' == output_format:
        output_format = set_output_format()

    # Set timestamp for this engagement for uniqueness
    timestamp = datetime.datetime.now().strftime('%Y%m%d')

    # Compile the engagement string and directory path to create
    this_engagement = (f'{engagement_type}-{input_values[0]}-{input_values[1]}-{timestamp}')

    this_dir = (
        f"{os.path.expanduser(cfg.CONFIG_VALUES['Paths']['pathwork'])}/"
        f"{engagement_type}/"
        f"{input_values[0]}/"
        f"{input_values[1]}-"
        f"{timestamp}"
    )

    # Quit now if the directory already exists.
    if os.path.isdir(this_dir):
        color_notice(
            'A directory structure for this engagement already exists for today.  '
            'Cannot overlay or replace.'
        )
        sys.exit(4)

    # Copy the template to the engagement directory
    # Input_Values:
    # platform, engagement_name, templates_path, platform_name, target_ip
    # 0         1                2               3              4

    #              templates_path, this_dir, engagement_type, engagement_name, target_ip
    copy_template(input_values[2], this_dir, engagement_type, input_values[1], input_values[4])

    # Confirm the configuration value applies to this specific engagement.
    student_id = cfg.CONFIG_VALUES['Settings']['studentid']
    color_notice(
        'Certification exams and some other types of engagements require '
        'a student ID, like the OSID.\n'
        f'Your current student ID is currently set to [{student_id}].  '
        'Do you want to keep this ID [Y|N] ?'
    )
    if 'N' == str(input('>  ')).upper():
        color_notice(
            'Enter the disired student ID.  '
            'This can be changed in engagement settings or the session file.'
        )
        student_id = (str(input('>  ')))
    # Update sessions file
    session_values = [
        this_engagement,
        this_dir,
        input_values[3],
        engagement_type,
        student_id,
        student_name,
        student_email,
        style,
        input_values[1],
        output_format,
        input_values[2]
    ]
    update_session_file(session_values)

    # Journal entry in sitrep
    sitrep_auto(
        f'Startup initiated for {engagement_type} as {input_values[1]}'
    )
    sitrep_auto(f'New working directory is {this_dir}')

def copy_template(templates_path, this_dir, engagement_type, engagement_name, target_ip):
    """ Perform the file copy operation. """

    #color_debug(f"Attempting to copytree from {templates_path} to {this_dir}")
    #exit(255)
    try:
        shutil.copytree(templates_path, this_dir)
    except (FileNotFoundError, PermissionError, IOError, OSError):
        color_fail("[E]", "Copytree templates failed.")
        try:
            shutil.copy(templates_path, this_dir)
        except (FileNotFoundError, PermissionError, IOError, OSError):
            color_fail("[E]", "Copy templates failed.")
            sys.exit(5)

    if "training" == engagement_type and re.search('plain', templates_path, flags=0):
        os.rename(f'{this_dir}/report/1-renameme.md', f'{this_dir}/report/1-{engagement_name}.md')
        if len(target_ip) >= 7:
            with open(f'{this_dir}/{cfg.TARGETS_FILE}', 'w') as target_file_writer: # pylint: disable=unspecified-encoding
                target_file_writer.write(target_ip + '\n')

def update_session_file(session_values):
    """ Update the session file with new engagement values. """

    # Break out the variables.
    this_engagement = session_values[0]
    this_dir = session_values[1]
    platform_name = session_values[2]
    engagement_type = session_values[3]
    student_id = session_values[4]
    student_name = session_values[5]
    student_email = session_values[6]
    style = session_values[7]
    engagement_name = session_values[8]
    output_format = session_values[9]
    source_path = session_values[10]

    # Set active
    cfg.SESSION['Current']['active'] = this_engagement

    # Set engagement settings
    cfg.SESSION[this_engagement] = {}
    cfg.SESSION[this_engagement]['path'] = this_dir
    cfg.SESSION[this_engagement]['source_path'] = source_path
    cfg.SESSION[this_engagement]['platform'] = platform_name
    cfg.SESSION[this_engagement]['type'] = engagement_type
    cfg.SESSION[this_engagement]['student_id'] = student_id
    cfg.SESSION[this_engagement]['student_name'] = student_name
    cfg.SESSION[this_engagement]['student_email'] = student_email
    cfg.SESSION[this_engagement]['style'] = style
    cfg.SESSION[this_engagement]['engagement_name'] = engagement_name
    cfg.SESSION[this_engagement]['output_format'] = output_format
    cfg.SESSION[this_engagement]['status'] = 'Started'
    cfg.SESSION[this_engagement]['start'] = str(datetime.datetime.now())
    cfg.SESSION[this_engagement]['end'] = ''
    cfg.save_engagements(cfg.SESSION)

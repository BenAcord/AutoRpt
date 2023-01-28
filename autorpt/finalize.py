#!/usr/bin/python3
"""
Finalize the report into publishing formats.
"""

import datetime
from glob import glob
import os
import re
import subprocess
import sys
import hashlib
import pandas as pd
import py7zr
import autorpt.cfg as cfg # pylint: disable=import-error,consider-using-from-import
import autorpt.cvss as cvss # pylint: disable=import-error,consider-using-from-import
from autorpt.work import sitrep_auto # pylint: disable=import-error
from autorpt.vulns import create_vuln_chart # pylint: disable=import-error
from autorpt.pretty import color_list, color_menu_item, color_fail, color_notice, out_info # pylint: disable=import-error

def finalize():
    """
    Main entry point to create the final report.
    """
    active = cfg.SESSION['Current']['active']
    rpt_base = f'{cfg.SESSION[active]["path"]}/report/'

    # Change to working directory
    os.chdir(f'{cfg.SESSION[active]["path"]}/report/')

    # Ensure the latest ports file exists. Only applies to some engagements.
    #ports_file = f"{rpt_base}{ports_spreadsheet}"
    cvss.ports()

    rpt_name = confirm_identity(active)

    file_info = set_output_file_format(active, rpt_base, rpt_name)
    rpt_extension = file_info[2]
    rpt_full_path = file_info[1]
    rpt_filename = rpt_base + rpt_name + ".md"

    # Create exam report and a single markdown file.
    create_report(active, rpt_full_path, rpt_filename)
    # Use the unified markdown file to create the final output format report.
    create_output_file(active, rpt_filename, rpt_full_path, rpt_extension)

    if 'yes' == file_info[0]:
        create_archive_file(rpt_base, rpt_name, rpt_extension)

    # Log the action taken
    sitrep_auto(f"Report finalized as {rpt_extension}")

    # Update the engagement status
    active = cfg.SESSION['Current']['active']
    cfg.SESSION[active]['end'] = str(datetime.datetime.now())
    cfg.SESSION[active]['status'] = 'Finalized'
    cfg.save_engagements(cfg.SESSION)

def confirm_identity(active):
    """ Verify or collect values for the students identification for the report. """

    rpt_name = ""

    # Student info only applies for some exams (eg OffSec).
    # Otherwise it can just be the author's name.
    if 'training' == cfg.SESSION[active]["type"]:
        rpt_name = "training_" + active.split('-')[2] + "_Report"
    else:
        rpt_name = (
            f"{active.split('-')[2].upper()}_"
            + cfg.SESSION[active]['student_id']
            + "_Exam_Report"
        )

    if 'exam' == cfg.SESSION[active]["type"]:
        if cfg.SESSION[active]['student_id'] == '':
            color_notice(
                "\nWhat is your student ID (currently ["
                f"{cfg.SESSION[active]['student_id']}]),"
                " if required?\n(eg. OS-12345, N/A)"
            )
            cfg.SESSION[active]['student_id'] = str(input('>  '))
        else:
            color_notice(
                "Student ID pulled from session file as "
                + cfg.SESSION[active]['student_id']
            )

    if cfg.SESSION[active]['student_email'] == '':
        color_notice("What is your full email address?")
        cfg.SESSION[active]['student_email'] = str(input('>  '))

    if cfg.SESSION[active]['student_name'] == '':
        color_notice("What is your name?")
        cfg.SESSION[active]['student_name'] = str(input('>  '))

    return rpt_name

def set_output_file_format(active, rpt_base, rpt_name):
    """ Structure the file format naming convention. """

    to_archive = 'no'

    # Set output file format
    if cfg.SESSION[active]['output_format'] == '':
        i = 0
        print("From these options, Pick an output format:")
        for ext in cfg.SUPPORTED_FILETYPES.split(','):
            color_menu_item(f"{str(i)} ) {ext}")
            i += 1
        picked = int(input('>  '))
        cfg.SESSION[active]['output_format'] = (
            cfg.SUPPORTED_FILETYPES[picked].lower()
        )

    if cfg.SESSION[active]['output_format'] in ["commonmark_x", "jira", "gfm"]:
        rpt_extension = 'md'
    else:
        rpt_extension = cfg.SESSION[active]['output_format']

    # Is archive needed?
    if '7z' in rpt_extension:
        to_archive = 'yes'
        rpt_extension = rpt_extension.split("+")[0]
        rpt_full_path = rpt_base + rpt_name + "." + rpt_extension
    else:
        rpt_full_path = rpt_base + rpt_name + "." + rpt_extension

    file_info = [to_archive, rpt_full_path, rpt_extension]
    return file_info

def get_vuln_chart():
    """ Produce the vulns chart for use in the final report. """

    # Generate the text for the vulnerability severity chart, it's ASCII.
    vulns_chart = (
        f"This horizontal chart is more compact by default "
        "and fits more inline with the flow of the report.\n"
        "```bash\n"
        f"{create_vuln_chart()}\n"
        f"```\n"
    )
    return vulns_chart

def get_vuln_table(vulns_file):
    """ Produce the vulns table for use in the final report. """

    # Import the vulnerability file.
    unsorted_vulns_table = pd.read_csv(
        vulns_file,
        index_col=False,
        usecols=['CvssScore','CvssSeverity','Name','Remediation'],
        sep=",",
        engine="python"
    )

    # Get a listing of the columns.
    cols_vulns_table = unsorted_vulns_table.columns.tolist()

    # Rearange the columns so CvssScore and CvssSeverity come first.
    cols_vulns_table = cols_vulns_table[-2:] + cols_vulns_table[:-2]

    # Sort the vulns by the float CvssScore so Critical are first.
    # Then convert to markdown and store in the variable.
    vulns_table = unsorted_vulns_table[cols_vulns_table].sort_values(
        by=['CvssScore'],
        ascending=False
    ).to_markdown(index=False)
    return vulns_table

def replace_boilerplate(replace_values):
    """
    For a given file handle use regex to replace the boilerplate items.
    """

    rpt_filename = replace_values[0]
    active = replace_values[1]
    vulns_chart = replace_values[2]
    vulns_table = replace_values[3]
    vulns_recommendations = replace_values[4]
    targets_table = replace_values[5]

    # Perform regex on boilerplate tags in the markdown files.
    with open(rpt_filename, 'r', encoding='utf8') as md_file_reader:
        file_contents = md_file_reader.read()

        file_contents = re.sub(
            '㉿',
            '@',
            file_contents
        )
        file_contents = re.sub(
            '💀',
            '@',
            file_contents
        )
        file_contents = re.sub(
            'BOILERPLATE_AUTHOR',
            cfg.SESSION[active]['student_name'],
            file_contents
        )
        file_contents = re.sub(
            'BOILERPLATE_EMAIL',
            cfg.SESSION[active]['student_email'],
            file_contents
        )
        file_contents = re.sub(
            'BOILERPLATE_DATE',
            datetime.datetime.now().strftime('%Y-%m-%d'),
            file_contents
        )
        file_contents = re.sub(
            'BOILERPLATE_VULNS_CHART',
            vulns_chart,
            file_contents
        )
        file_contents = re.sub(
            'BOILERPLATE_VULNS_TABLE',
            vulns_table,
            file_contents
        )
        file_contents = re.sub(
            'BOILERPLATE_VULNS_RECOMMENDATIONS',
            vulns_recommendations,
            file_contents
        )
        file_contents = re.sub(
            'BOILERPLATE_PLATFORM',
            f'{cfg.SESSION[active]["path"]}/report/'.split('/')[-4],
            file_contents
        )
        file_contents = re.sub(
            'BOILERPLATE_TARGETS_LIST',
            targets_table,
            file_contents
        )
        file_contents = re.sub(
            'BOILERPLATE_TARGET',
            active.split('-')[2],
            file_contents
        )
        file_contents = re.sub(
            'BOILERPLATE_HOSTNAME',
            active.split('-')[2],
            file_contents
        )
        file_contents = re.sub(
            'BOILERPLATE_OSID',
            '',
            file_contents
        )
        file_contents = re.sub(
            'BOILERPLATE_OSID',
            cfg.SESSION[active]['student_id'],
            file_contents
        )

        # Some markdown for pasted images are incompatable with Pandoc
        # and results in no images reaching the final report.
        # Rewrite all pasted screenshots from this "![[Pasted_image_A.png]]"
        # to this format "![Pasted_image_A.png](Pasted_image_A.png)"
        file_contents = re.sub(
            r'\!\[\[Pasted_image_(\w+).png\]\]',
            r'![Pasted_image_\1.png](Pasted_image_\1.png)',
            file_contents
        )

    # Write modifed contents with boilerplate value replacements
    with open(rpt_filename, 'w') as result: # pylint: disable=unspecified-encoding
        result.write(file_contents + '\n')

def create_report(active, rpt_full_path, rpt_filename):
    """
    Use the merged markdown file to create the file report output format.
    """

    sitrep_auto(
        f'Creating final report.  File: {rpt_full_path}'
    )

    # The merged, unified markdown file is not a primary source.
    # Remove of it already exists. Previous failed attempt.
    if os.path.exists(rpt_filename):
        try:
            os.remove(rpt_filename)
        except (FileNotFoundError, PermissionError, IOError, OSError):
            color_fail(
                "Error", "removing existing report file: " + rpt_filename
            )
            sys.exit(6)

    # Merge markdown sections into a single mardown file.
    with open(rpt_filename, "wb") as md_outfile:
        for md_file in sorted(glob(f'{cfg.SESSION[active]["path"]}/report/' + '[0-9]*.md')):
            with open(md_file, "rb") as md_infile:
                md_outfile.write(md_infile.read())

    # Read in the vulns spreadsheet
    rpt_base = f'{cfg.SESSION[active]["path"]}/report/'
    vulns_file = f"{rpt_base}{cfg.VULNS_CSV}"
    target_file = f'{cfg.SESSION[active]["path"]}/targets.md'
    vulns_chart = ""
    vulns_table = ""
    vulns_recommendations = ""
    targets_table = ""

    if os.path.isfile(target_file):
        with open(target_file, 'r', encoding='utf8') as targets_reader:
            targets_table = targets_reader.read()

    if os.path.isfile(vulns_file):
        vulns_chart = get_vuln_chart()
        vulns_table = get_vuln_table(vulns_file)
    else:
        vulns_table = 'No vulnerabilities were discovered.'

    # Replace boilerplate placeholder text with user supplied values.
    replace_values = [
        rpt_filename,
        active,
        vulns_chart,
        vulns_table,
        vulns_recommendations,
        targets_table
    ]
    replace_boilerplate(replace_values)

def create_output_file(active, rpt_filename, rpt_full_path, rpt_extension):
    """
    Execute the Pandoc command to create the chosen output file from the merged Markdown file.
    """
    if cfg.CONFIG_VALUES['Settings']['style'] == '':
        cfg.CONFIG_VALUES['Settings']['style'] = get_pandoc_style()

    out_info(f"Generating {rpt_extension} report", f"{rpt_filename}")

    # Build the Pandoc command for generating the report
    cmd = '/usr/bin/pandoc ' + rpt_filename
    cmd += ' --output=' + rpt_full_path
    cmd += ' --from markdown+yaml_metadata_block+raw_html'

    if (
        not cfg.SESSION[active]['output_format']
        in cfg.CONFIG_VALUES['Settings']['no_template'].split(',')
    ):
        cmd += ' --template eisvogel'

    cmd += ' --table-of-contents'
    cmd += ' --toc-depth' + ' 6'
    cmd += ' --top-level-division=chapter'
    cmd += ' --number-sections'
    cmd += ' --wrap=auto'
    cmd += ' --highlight-style ' + cfg.CONFIG_VALUES['Settings']['style']
    cmd += ' --pdf-engine=xelatex'
    # Helpful for debugging the pandoc command:
    #color_debug(f"cmd:\n{cmd}")

    cmd_output = ""
    try:
        cmd_output = subprocess.getoutput(cmd)
    except subprocess.CalledProcessError as err:
        color_fail("[!]", f"Failed to generate PDF using pandoc.\n{err}\n{cmd_output}")
        sys.exit(10)

def create_archive_file(rpt_base, rpt_name, rpt_ext):
    """ Create the 7z archive file containing only the report file. """

    archive_file = f"{rpt_base}{rpt_name}.7z"
    report_file = f"{rpt_name}.{rpt_ext}"
    os.chdir(f"{rpt_base}")

    if os.path.isfile(f"{report_file}"):
        out_info("Creating 7z archive", f"{archive_file}")


        with py7zr.SevenZipFile(archive_file, 'w') as archive:
            archive.writeall(report_file)

        md5_sum = hashlib.md5(open(archive_file, 'rb').read()).hexdigest()
        out_info("MD5SUM hash of 7z file", f"{md5_sum}")
        out_info("Reminder", "Double-check the 7z archive contents before submission.")

def get_pandoc_style():
    """Selector of the code syntax highlight style"""

    color_notice(
        "\nFrom the following list, pick a syntax highlight style for code blocks?\n"
        "   Recommendation: lighter styles are easier to read and use less ink if printed.\n"
        "   Dark styles include: espresso, zenburn, and breezedark.\n"
        "   Light styles include: pygments, tango, kate, monochrome, haddock"
    )

    i = 0
    style_list = {}

    cmd_output = str(subprocess.run(["pandoc", "--list-highlight-styles"],
                            check=True,
                            universal_newlines=True,
                            capture_output=True).stdout)

    output_lines = cmd_output.splitlines(False)
    for output_line in output_lines:
        color_list('\t' + str(i) + ". " + output_line)
        style_list[i] = output_line
        i += 1

    style_id = int(input('>  '))

    if style_id > i or style_id < 0:
        color_notice('Invalid selection')
        get_pandoc_style()

    return style_list[style_id]

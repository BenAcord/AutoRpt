#!/usr/bin/python3
"""
Output formatting functions to make it look really nice.
"""

import os
import random
import subprocess
import blessings

def banner(this_version):
    """Display required ASCII art and random motto"""
    this_msg = ""
    mottos = ['Train like you PenTest',
            'Persistently consistent',
            'We PenTest like we train',
            'Consistency is the key',
            'Train like you exam like you PenTest',
            'Tag your work',
            'Documentation is never perfect,\nit simply runs out of time',
            'Consistent, dependable, and improving']
    max_size = len(mottos) - 1
    random_message_id = random.randint(0, max_size)
    this_msg = mottos[random_message_id]
    print(
        "____ _  _ ___ ____ ____ ___  ___\n"
        f"|--| |__|  |  [__] |--< |--'  |   {this_version}\n"
        f'{term.bright_blue}{this_msg.center(40)}{term.normal}\n'
    )

def clear_screen():
    """Function to clear screen text"""
    _ = subprocess.call('clear' if os.name == 'posix' else 'cls')

def color_header(this_msg):
    """Function to format header text"""
    print(f"\n{term.bold_bright_blue}{this_msg}{term.normal}\n")

def color_subheading(this_msg):
    """Function to format subheader text"""
    print(f"{term.bold_bright_blue}{this_msg}{term.normal}")

def color_menu_item(this_msg):
    """Function to format menu item text"""
    print(f"  {term.yellow}{this_msg}{term.normal}")

def color_list(this_msg):
    """Function to format lists"""
    print(f"{term.bold_bright}{this_msg}{term.normal}")

def color_debug(this_msg):
    """Function to format debug text"""
    print(
        f"{term.on_yellow}{term.black}[d]{term.normal}  "
        f"{term.yellow}{this_msg}{term.normal}"
    )

def color_table_header(this_msg):
    """Function to format table headers"""
    print(
        f"{term.on_blue_underline_bold}{term.bright_white}{this_msg}{term.normal}"
    )

def color_verify(field, this_msg):
    """Function to format verification text"""
    print(
        f'{term.red}{field}{term.normal}  '
        f'{term.bold_bright}{this_msg}{term.normal}'
    )

def color_warn(this_msg):
    """Function to format warning text"""
    print(
        f'{term.bold_on_bright_yellow}[W]{term.normal}  '
        f'{term.bold_bright_yellow}{this_msg}{term.normal}'
    )

def color_pass(field, this_msg):
    """Function to format passing, good text"""
    print(
        f'{term.bold_on_bright_green}[P]{term.normal}  '
        f'{term.bold_bright_green}{field} {this_msg}{term.normal}'
    )

def color_fail(field, this_msg):
    """Function to format failed, bad text"""
    print(
        f'{term.bold_on_bright_red}[E]{term.normal}  '
        f'{term.bold_bright_red}{field} {this_msg}{term.normal}'
    )

def color_notice(this_msg):
    """Function to format a informational notice text"""
    print(f"{term.bright}{this_msg}{term.normal}")

# Define a terminal for color sugar
term = blessings.Terminal(kind='xterm-256color')

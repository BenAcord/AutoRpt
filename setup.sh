#!/usr/bin/bash
# AutoRpt setup script
# Author: Ben Acord (Overcast)


# Issue warning on sizing and act accordingly.
# Latex document formatting is large ecosystem.  Using bare mimumum here.
echo -e "\nWARNING\n"
echo "Converting between document types with Texlive and Latex requires large packages."
echo "Continuing will increase filesystem size by roughly 4.5 GB."
echo "If you know you have the space it is recommended to select, Y."
echo -e "\nContinue? [Y|N]\n"
read contiue_answer
if [ $contiue_answer != "Y" ]
then
    echo "A 'Y' response was not provided.  Exiting."
    exit 1
fi

# Install dependencies
# p7zip deprecated 01/23/23 for use in code but you may want it for
# inspecting and manually creating 7zip archives.
sudo apt-get install -y p7zip xclip pandoc pandoc-data texlive texlive-latex-extra texlive-fonts-extra texlive-xetex

pip install --no-input cvss blessings colorama pyperclip packaging pandas openpyxl tabulate ijson py7zr
# Pretty: blessings colorama pyperclip
# Vulns: cvss pandas openpyxl tabulate

# Shortcut name without the .py extension.
install_dir=`pwd`
chmod 700 ${install_dir}/autorpt.py
echo "Creating symbolic link in /bin/autorpt to ${install_dir}/autorpt.py"
sudo ln -s ${install_dir}/autorpt.py /bin/autorpt

# Templates directory
if [ -d ~/.local/share/pandoc/templates ] ; then 
    echo "Template directory exists: ~/.local/share/pandoc/templates"
else 
    echo "Creating template directory: ~/.local/share/pandoc/templates"
    mkdir -p ~/.local/share/pandoc/templates
fi

# Eisvogel
if [ -f ~/.local/share/pandoc/templates ] ; then 
    echo "eisvogel latex template exists: ~/.local/share/pandoc/templates/eisvogel.latex"
else 
    echo "Copying eisvogel template"
    cp includes/eisvogel* ~/.local/share/pandoc/templates/
fi

# Create this user's AutoRpt config directory.
if [ ! -d ~/.config/AutoRpt ]
then 
    mkdir ~/.config/AutoRpt
fi

# Create this user's AutoRpt working directory.
if [ ! -d ~/Documents/AutoRpt ]
then 
    mkdir ~/Documents/AutoRpt
fi

# Config file to users local config directory
if [ ! -f ~/.config/AutoRpt/config.toml ]
then 
    cp ./config.toml ~/.config/AutoRpt/config.toml
else 
    echo "Config.toml file already exists: ~/.config/AutoRpt/config.toml"
fi

# Session file to users local config directory
if [ ! -f ~/.config/AutoRpt/sessions.toml ]
then 
    cp ./sessions.toml ~/.config/AutoRpt/sessions.toml
else 
    echo "Sessions file already exists: ~/.config/AutoRpt/sessions.toml"
fi

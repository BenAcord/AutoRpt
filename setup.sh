#!/usr/bin/bash
# AutoRpt setup script
# Author: Ben Acord (Overcast)


# Install dependencies
sudo apt-get install -y p7zip xclip pandoc pandoc-data texlive texlive-latex-extra
# texlive-fonts-extra texlive-xetex

# Eisvogel requires these: 
time /usr/bin/tlmgr install adjustbox babel-german background bidi collectbox csquotes \
everypage filehook footmisc footnotebackref framed fvextra letltxmacro ly1 mdframed \
mweights needspace pagecolor sourcecodepro sourcesanspro titling ucharcat ulem \
unicode-math upquote xecjk xurl zref

pip install --no-input cvss blessings colorama pyperclip packaging pandas openpyxl tabulate
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

#!/usr/bin/bash
# AutoRpt setup script
# Author: Ben Acord (Overcast)


# Verify or add local bin to .zprofile or .profile if .zprofile does not exist
#if [[ -f ~/.zprofile && `grep "export PATH=" ~/.zprofile` ]]
#then 
#    echo "Adding ~/.local/bin to ~/.zprofile"
#    echo "export PATH=\"${PATH}:~/.local/bin\"" >> ~/.zprofile
#    source ~/.zprofile
#elif [[ -f ~/.profile && `grep "PATH=" ~/.profile` ]]
#then
#    echo "Adding ~/.local/bin to ~/.profile"
#    echo "PATH=\"${PATH}:~/.local/bin\"" >> ~/.profile
#    source ~/.profile
#else
#    echo "Unable to locate a .zprofile or .profile to update the PATH variable with ~/.local/bin"
#    echo "You will need to either custom update your profile or manually call the full path to autorpt.py."
#fi

# Install dependencies
sudo apt-get install -y p7zip xclip pandoc pandoc-data texlive texlive-xetex

pip install --no-input cvss blessings colorama pyperclip packaging pandas openpyxl

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

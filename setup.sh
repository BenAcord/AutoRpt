#!/usr/bin/bash
# AutoRpt setup script
# Author: Ben Acord (Overcast)
sudo apt-get install -y p7zip pandoc pandoc-data texlive texlive-xetex texlive-fonts-recommended texlive-fonts-extra

pip install cvss blessings colorama

cd /opt/AutoRpt
chmod 700 /opt/AutoRpt/autorpt.py
ln -s /opt/AutoRpt/autorpt.py ~/.local/bin/autorpt

# Templates directory
if [ -d ~/.local/share/pandoc/templates ] ; then 
    echo "Template directory exists: ~/.local/share/pandoc/templates"
else 
    echo "Creating template directory: ~/.local/share/pandoc/templates"
    mkdir -p ~/.local/share/pandoc/templates
fi

# Eisvogel
if [ -f ~/.local/share/pandoc/templates ] ; then 
    echo "eisvogel latex template exists: ~/.local/share/pandoc/templatess/eisvogel.latex"
else 
    echo "Copying eisvogel template"
    cp includes/eisvogel* ~/.local/share/pandoc/templates/
fi

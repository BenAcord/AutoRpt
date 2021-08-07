#!/usr/bin/bash
# AutoRpt setup script
# Author: Ben Acord (Overcast)
sudo apt-get install -y p7zip pandoc pandoc-data texlive-xetex

pip install cvss blessings colorama

cd /opt
git clone https://github.com/BenAcord/AutoRpt.git

ln -s /opt/AutoRpt/autorpt.py ~/.local/bin/autorpt

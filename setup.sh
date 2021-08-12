#!/usr/bin/bash
# AutoRpt setup script
# Author: Ben Acord (Overcast)
sudo apt-get install -y p7zip pandoc pandoc-data texlive-xetex

pip install cvss blessings colorama

cd /opt/AutoRpt
chmod 700 /opt/AutoRpt/autorpt.py
ln -s /opt/AutoRpt/autorpt.py ~/.local/bin/autorpt

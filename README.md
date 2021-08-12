# AutoRpt Overview



:trophy: Mad props and respect to noraj for the "Offensive Security Exam Report Template in Markdown".

:hammer_and_wrench: If you are looking for a solid markdown tool, take a look at Obsidian.

:warning: use at your own risk.

---

# Table of Contents

* [Overview](#AutoRpt)
* [Install](#Install)
* [Usage](#Usage)
* [Contributing](#Contributing)

---

## Install
A work-in-progress shell script is included which is intended to automate the dependencies and .

### Dependencies & Caveats
AutoRpt has only been tested on Kali Linux.
- p7zip
- pandoc
- pandoc-data
- texlive-xetex

### Clone the Repo
```Bash
cd /opt
git clone https://github.com/BenAcord/AutoRpt.git
```

Either execute setup.sh or perform these manual steps:
1. Execute setup.sh
```Bash
chmod 700 /opt/AutoRpt/setup.sh
/opt/AutoRpt/setup.sh
```

2. Manual setup
```Bash
cd AutoRpt

sudo apt-get install -y p7zip pandoc pandoc-data texlive-xetex

pip install cvss blessings colorama

sudo ln -s /opt/AutoRpt/autorpt.py /usr/bin/autorpt
chmod 700 autorpt.py
autorpt help
```

## Usage:
`autorpt.py [ help | startup | vuln | ports | sitrep \{message\}| finalize | settings ]`

Settings can be run at any time.  Though if startup has not yet been run its engagements functionality will be limited.

Startup is required before using any other parameters, excluding help and settings.  This is because startup creates the engagement working directory and registers the session.  Every other parameter references the active session.

For details on each parameter's functionality please see the wiki.

What It Is
Streamline the report writing experience.  AutoRpt enforces consistent organization of directory structure and note taking to facilitate a smooth report writing process.

1. (**startup**) Prior to starting an exam or training, startup creates a base directory structure and populates it with a markdown report template.  Run this well in advance of the exam start time.  During the exam or training update the markdown files for the targets.

2. (**ports**) Quickly scans for known recon tool nmap output and displays a summary of the ports and services.  Also creates a spreadsheet with a tab for each target and its ports.

3. (**vuln**) A submenu for logging confirmed vulnerabilities and assigning a CVSS 3 score and MITRE ATT&CK Framework tactic and technique.

4. (**sitrep**) Track your status and activity throughout the engagement.  You can quickly add a status or review the log to see the history of activities.  Yes, I realize this isn't a real sitrep report.

5. (**finalize**) During the exam report window AutoRpt generates a final report PDF and 7z archive from your markdown files.  Other file formats are supported: Jira, odt, docx, and common markdown.

## Contributing
If you find an bug or have an idea for an enhancement enter an issue here on GitHub.  Pull requests will take longer to evaluate.
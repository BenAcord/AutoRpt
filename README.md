# AutoRpt Overview
AutoRpt enforces a consistent, dependable workflow for engagement note-taking and report writing.
It does this by managing a base directory structure with note and report templates.  The main focus is easing the process associated with InfoSec certification exams such as the OSCP or PNPT, though many others are supported.  It also covers training and CTF on common InfoSec platforms like Hack the Box, Try Hack Me, or Proving grounds to name but a few.  Bug bounty hunting and penetration tests are use case options but are considered work in progress.

All wrapped in a sleak 1980's menu system.

AutoRpt creates unique working directories from these templates.  If you retake a course or certification exam the new directory will be unique from the previous.
```
templates
├── oscp
├── osda
├── osed
├── osee
├── osep
├── osmr
├── oswa
├── oswe
├── oswp
├── pnpt
└── training
    ├── bugbounty
    ├── exp-301-lab
    ├── exp-312-lab
    ├── exp-401-lab
    ├── pen-200-lab
    ├── pen-210-lab
    ├── pen-300-lab
    ├── plain
    ├── soc-200-lab
    ├── web-200-lab
    └── web-300-lab
```

The workflow is terminal friendly to keep your head in the engagement and not juggling various interfaces.

![startup](https://github.com/BenAcord/wiki-images/raw/main/AutoRpt/2-startup.png "AutoRpt startup screenshot for Metasploitable2")

:trophy: Mad props and respect to [noraj for the "Offensive Security Exam Report Template in Markdown"](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown).  This project is included in AutoRpt.

:warning: use at your own risk.

---

# Table of Contents

* [Overview](#AutoRpt)
* [Install](#Install)
* [Usage](#Usage)
* [Contributing](#Contributing)

---

## Install
A work-in-progress shell script is included which is intended to automate the dependencies and setup.  The example here uses /opt as AutoRpt's home.

### Dependencies & Caveats
AutoRpt has only been tested on Kali Linux.
- p7zip
- pandoc
- pandoc-data
- texlive
- texlive-fonts-recommended
- texlive-fonts-extra
- texlive-xetex

Highly recommend:
:hammer_and_wrench: [AutoRecon](https://github.com/Tib3rius/AutoRecon)
:hammer_and_wrench: [Flameshot](https://flameshot.org/)
:hammer_and_wrench: [Obsidian](https://obsidian.md/)

### Clone the Repo
```Bash
cd /opt
git clone https://github.com/BenAcord/AutoRpt.git
```
### Setup
Execute setup.sh or perform its steps manually.

```Bash
chmod 700 /opt/AutoRpt/setup.sh
/opt/AutoRpt/setup.sh
```

## Usage
`autorpt.py [ help | settings | active | startup | vuln [list] | ports | sitrep [message] | addtarget [IP Address] | addtemplate | finalize | list | whathaveidone ]`

AutoRpt enforces consistent organization of directory structure and note taking to facilitate a smooth report writing process.  For details on each parameter's functionality please see the [wiki](https://github.com/BenAcord/AutoRpt/wiki).

### Example Workflow Walkthrough
1. `autorpt.py startup` Prior to starting an exam or training, startup creates a base directory structure and populates it with a markdown report template.  Run this well in advance of the exam start time.  During the exam or training edit the markdown files for the targets.  

Startup is required before using any other parameters, excluding help and settings.  This is because startup creates the engagement working directory and registers the session.  Every other parameter references the active engagement session.

2. `autorpt.py ports` Quickly scans for known recon tool nmap output and displays a summary of the ports and services.  Also creates a spreadsheet with a tab for each target and its ports.  It creates the summary from [AutoRecon](https://github.com/Tib3rius/AutoRecon), [nmapAutomator](https://github.com/21y4d/nmapAutomator), and [Reconoitre](https://github.com/codingo/Reconnoitre).

3. `autorpt.py vuln` A submenu for logging confirmed vulnerabilities and assigning a CVSS 3 score and MITRE ATT&CK Framework tactic and technique.  Recorded vulnerabilities are stored in a vulns.csv file and automatically injected into the final report as a table.

4. `autorpt.py sitrep` Track your status and activity throughout the engagement.  You can quickly add a status or review the log to see the history of activities.  Yes, I realize this isn't a real sitrep report.  This is a markdown file to ease visibility.

5. `autorpt.py finalize` During the exam report window AutoRpt generates a final report PDF and 7z archive from your markdown files.  Other file formats are supported: Jira, odt, docx, and common markdown.

6. `autorpt.py settings` can be run at any time to set application level and engagement session configuration values.  If startup has not yet been run its engagements functionality will be limited.
   
7. `autorpt.py whathaveidone` will list the status of all engagements recorded to-date.  This is a convenient way to keep track of what you've accomplished over time.

## Contributing
Enter an issue here on GitHub if you find a bug or have an enhancement idea.
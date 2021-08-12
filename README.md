# AutoRpt Overview
## What It Is
Streamline the report writing experience.  AutoRpt enforces consistent organization of directory structure and note taking to facilitate a smooth report writing process.

1. (**startup**) Prior to starting an exam or training, startup creates a base directory structure and populates it with a markdown report template.  Run this well in advance of the exam start time.  During the exam or training update the markdown files for the targets.

2. (**ports**) Quickly scans for known recon tool nmap output and displays a summary of the ports and services.  Also creates a spreadsheet with a tab for each target and its ports.

3. (**vuln**) A submenu for logging confirmed vulnerabilities and assigning a CVSS 3 score and MITRE ATT&CK Framework tactic and technique.

4. (**sitrep**) Track your status and activity throughout the engagement.  You can quickly add a status or review the log to see the history of activities.  Yes, I realize this isn't a real sitrep report.

5. (**finalize**) During the exam report window AutoRpt generates a final report PDF and 7z archive from your markdown files.  Other file formats are supported: Jira, odt, docx, and common markdown.

**TBD: Insert video or GIF here**

:clap: First, good luck on your exam and report writing endevors.  I wish you well.

:trophy: Second, mad props and respect to noraj for the "Offensive Security Exam Report Template in Markdown".

:hammer_and_wrench: Third, if you are looking for a solid markdown tool, take a look at Obsidian.

:warning: Finally, with that said... :exclamation: use at your own risk.

Happy writing!

---

# Table of Contents

* [Overview](#AutoRpt)
* [Install](#Install)
   * [Dependencies & Caveats](#Dependencies & Caveats)
   * [Clone the Repo](#Clone the Repo)
* [Usage](#Usage)
   * [Displaying help](#Displaying help)
* [Settings](#Settings)
* [Startup - Scafold Working Directory Structure](#Startup - Scafold Working Directory Structure)
* [Situation Report](#Situation Report)
* [Ports](#Ports)
* [Vulnerabilty Log](#Vulnerabilty Log)
* [Writing the Pentest Report](#Writing the Pentest Report)
* [Finalize - Generate Submission Files](#Finalize - Generate Submission Files)

---

## Install
### Dependencies & Caveats
AutoRpt has only been tested on Kali Linux.
- p7zip
- pandoc
- pandoc-data
- texlive-xetex
```Bash
sudo apt-get install -y p7zip pandoc pandoc-data texlive-xetex

pip install cvss blessings colorama
```

### Clone the Repo
```Bash
cd /opt
git clone https://github.com/BenAcord/AutoRpt.git
cd AutoRpt
sudo ln -s /opt/AutoRpt/autorpt.py /usr/bin/autorpt
chmod 700 autorpt.py
autorpt help
```

---

## Usage:
`autorpt.py [ help | startup | vuln | ports | sitrep \{message\}| finalize | settings ]`

### Displaying help
Sometimes it is good to read a man page or a bit of documentation.  autorpt will display help if any of the following options are submitted: `-h`, `help`, `--help`.

```
$ autorpt.py help

 ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄   ▄▄▄·▄▄▄▄▄
▐█ ▀█ █▪██▌•██  ▪     ▀▄ █·▐█ ▄█•██  
▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄ ▐▀▀▄  ██▀· ▐█.▪
▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█•█▌▐█▪·• ▐█▌·
 ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀  ▀.▀    ▀▀▀ 
              Tag your work


USAGE:
autorpt.py [ help | startup | vuln | ports | sitrep \{message\}| finalize | settings ]
                                                                                                                          
WHERE:
  help:      Display this listing of usage and examples.
  startup:   Create a clean working directory for a new engagement.
  vuln:      Record a confirmed vulnerability with CVSS scoring and MITRE ATT&CK attributes.
  ports:     (AutoRecon specific) Quick display of all open ports per target.
  sitrep:    Record a status update of your current progress or display the menu.
  finalize:  Compile markdown files into a desired output file format.
  settings:  Configuration settings.

EXAMPLES:                                                                                                                 
When you are ready to start an exam or training:
    autorpt.py startup
Log a verified vulnerability:
    autorpt.py vuln
Display vulnerability list:
    autorpt.py vuln list
Log your current status:
    autorpt.py sitrep pwned buffer overflow
...Or
    autorpt.py sitrep Stuck trying to exploit system X:8001/login.php via SQLi.  May be a rabbit trail.
...Or use the menu system:
    autorpt.py sitrep
Display the sitrep log:
    autorpt.py sitrep list
After AutoRecon completes, display the ports:
    autorpt.py ports
Compile the markdown into a polished report document
    autorpt.py finalize
```

### Settings
AutoRpt configuration settings are stored in ~/.config/AutoRpt/config.yml.  Setting changes can either be through the menu as shown in the next example or by directly editing the file.

Example of listing settings in the menu.
```Bash
[    Settings    ]

  1. Application-level settings
  2. Engagement settings
  3. Back to main menu
  4. Quit
>  1
Current Settings
  1) Engagements will be stored in /home/kali/Documents/AutoRpt
  2) Your name: A. B.
  3) Your student ID: OS-12345
  4) Your email address: a@b.c
  5) Preferred report format: odt
  6) Code block style: haddock
  7) Settings menu
  8) Main menu
  
Pick a number to modify its setting
>  

```


### Startup - Scafold Working Directory Structure
Similar to how tools like autorecon and nmapAutomator create subdirectories for organizing enumeration output files during the pentest, autorpt does something similar for reporting.  The startup option creates a working directory for the selected training or exam along with a report subdirectory.  

By default this working subdirectory is created in /home/kali/Documents/AutoRpt but can be changed in the the settings menu or directly in the /home/kali/.config/AutoRpt/config.yml.  

Startup then populates a barebones targets.txt file for recon scripts and copies a markdown template file for each major section of the final report.  These files are numbered similar to chapters and named with the respective system point value.  A tree structure is displayed showing the new exam home.

After running `autorpt startup` change to the newly created exam directory (eg. `cd oscp`) before running any scan tools.  This will keep all recon output subdirectories in the exam directory.

```
$ autorpt.py startup

 ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄   ▄▄▄·▄▄▄▄▄
▐█ ▀█ █▪██▌•██  ▪     ▀▄ █·▐█ ▄█•██  
▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄ ▐▀▀▄  ██▀· ▐█.▪
▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█•█▌▐█▪·• ▐█▌·
 ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀  ▀.▀    ▀▀▀ 
              Tag your work


[    Startup    ]

Startup will first create a directory structure for the engagement.
(eg. training/hackthebox/waldo)

Select the type of engagement:
  0.  training
  1.  ctf
  2.  exam
  3.  bugbounty
  4.  pentest
  99 for main menu
>  0
Enter the platform or company name:
  0.  hackthebox
  1.  tryhackme
  2.  vulnhub
  3.  provinggrounds
  4.  virtualhackinglabs
  5.  sansnetwars
  6.  websecurityacademy
  99 for main menu
>  0
What is the box name?
(eg. waldo, kenobi, etc.
>  granny
sitrep logged
Templates successfully copied to report directory.  Here's the new structure:
                                                                                                                          
granny-20210811/
├── config.yml
├── README
├── report/
│   ├── 0-execsummary.md
│   ├── 1-granny.md
│   ├── 6-closing.md
│   └── sitrep.log
└── targets.txt
```

### Situation Report
The sitrep parameter is an on-the-fly status logger of what you are thinking at that moment.  It's a means of keeping track of interesting findings, recognition of a rabbit trail, a quick note about taking a break, or anything else important to you at the time.

This type of stream of conscious logging is helpful for lessons learned after the event ends.

A sitrep can be logged from any location at any time.  There's no need to keep the file open as AutoRpt will log with the active engagement.  AutoRpt also writes to this log for its own functionality so a coherent timeline of its activity and your own is kept.  For example, if a new sitrep is logged now it will appear after the sitrep created by AutoRpt's startup above.
`$ autorpt sitrep Kicking off AutoRecon scans`

Contents of the log are available for review through three means: 
- `autorpt sitrep list` - displays the log and exits AutoRpt
- the sitrep menu
- or opening the plaintext file in report/sitrep.log.

```Bash
$ autorpt sitrep

  ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄   ▄▄▄·▄▄▄▄▄ 
 ▐█ ▀█ █▪██▌•██  ▪     ▀▄ █·▐█ ▄█•██   
 ▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄ ▐▀▀▄  ██▀· ▐█.▪ 
 ▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█•█▌▐█▪·• ▐█▌· 
  ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀  ▀.▀    ▀▀▀  
             Tag your work


[    SITREP  (Situation Report)    ]

  1. List all sitrep entries
  2. Add new sitrep log entry

  3. Main Menu
  4. Quit
>  1

    SITREP Log Entries    

 2021-08-11 18:54   Startup initiated new working directory for granny: /home/kali/Documents/AutoRpt/training/hackthebox/granny-20210811
 2021-08-11 18:56   Kicking off AutoRecon scans
```

Manually looking at the sitrep.log from the terminal.
```Bash
(kali㉿kali)-[~/…/training/hackthebox/granny-20210811/report]
└─$ cat sitrep.log 
2021-08-11 18:54 - Startup initiated new working directory for granny: /home/kali/Documents/AutoRpt/training/hackthebox/granny-20210811
2021-08-11 18:56 - Kicking off AutoRecon scans
```

### Ports
Tools like AutoRecon, nmapAutomator, and Reconnoitre should be run from the directory created with startup.  This will store its output where AutoRpt can reference plus helps with organization.

After the recon tools complete the output files can be quickly mined for a list of ports.  The ports parameter will search for known nmap files from these tools and display a summary of the ports to the screen.  AutoRpt will also create a report/ports.xlsx spreadsheet with a worksheet for each target and an "All Ports" tab as a master list for every target and its ports.  It does this every time `ports` is run.


### Vulnerabilty Log
The vuln parameter is used to log validated vulnerabilities to a CSV file in the report directory.  This menu driven process prompts for key attributes.  A few key things to note.  

If the CVSS 3 score is known it can be entered as shown in the example below.  If the score is not known it will prompt for every calculating field and use the CVSS module to calculate the score for you.

The final piece of the vulnerability is to associate it with the MITRE ATT&CK Framework tactic and technique.  The first prompt will select the correct ATT&CK framework from: mobile, pre, ics, and enterprise.  The second associates the tactic and the final displays the techniques associated with the selected tactic.

The values entered are shown for verification and, if approved, are written to the report/vulns.csv file.

Example of logging a _dummy_ vulnerability.
```Bash
$ autorpt vuln                                                                                                      1 ⨯

  ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄   ▄▄▄·▄▄▄▄▄ 
 ▐█ ▀█ █▪██▌•██  ▪     ▀▄ █·▐█ ▄█•██   
 ▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄ ▐▀▀▄  ██▀· ▐█.▪ 
 ▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█•█▌▐█▪·• ▐█▌· 
  ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀  ▀.▀    ▀▀▀  
             Tag your work


[    Vulnerabilities    ]

  1. Add a new vulnerability
  2. List all vulnerabilities
  3. Modify an existing vulnerability
  4. Remove a vulnerability
                                                                                                                          
  5. Main Menu
  6. quit
> 1

    Add Vulnerability    

For which target?
Or '99' to go back to the menu.                                                                                           
0.  192.168.x.x
>  0
What is the port number [0-65535]?
>  443
What is the name for this vulnerability?
(eg. Remote code injection in Vendor_Product_Component)                                                                   
>  RCE in search form train/search.php 
Describe the business impact: 
>  Initial compromise
Do you have a comment for where you left off? 
>  Exploring the limits of what will execute and checking web directories 
sitrep logged

    CVSS 3 Scoring    

Do you know the Overall CVSS v3 Score? [Y|N]
>  y
What is the score?
>  5.6
If known, paste the CVSS Vector string here or hit Enter to skip (eg. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N 
>  

    MITRE ATT&CK    

Which MITRE ATT&CK Framework applies?
Press 99 for main menu.                                                                                                   
  0. mobile
  1. pre
  2. ics
  3. enterprise
>  3
What is the Tactic?
Or 99 to return to the ATT&CK menu.                                                                                       
  0. collection
  1. command-and-control
  2. credential-access
  3. defense-evasion
  4. discovery
  5. execution
  6. exfiltration
  7. impact
  8. initial-access
  9. lateral-movement
  10. persistence
  11. privilege-escalation
  12. reconnaissance
  13. resource-development
>  8
Pick a Technique?
Or 99 to return to the tactic menu.                                                                                       
  0. Drive-by Compromise
  1. Exploit Public-Facing Application
  2. External Remote Services
  3. Hardware Additions
  4. Phishing
  5. Replication Through Removable Media
  6. Supply Chain Compromise
  7. Trusted Relationship
  8. Valid Accounts
>  1

-----------------------------                                                                                             
  Verify the data entered.                                                                                                
-----------------------------                                                                                             
 [Target]                   192.168.x.x
 [Port]                     443
 [Name]                     RCE in search form train/search.php
 [CVSS Overall Score]       5.6
 [CVSS Severity]            Medium
 [Business Impact]          Initial compromise
 [Comment]                  Exploring the limits of what will execute and checking web directories
 [MITRE ATT&CK Tactic]      initial-access
 [MITRE ATT&CK Technique]   Exploit Public-Facing Application

Are these values correct? [Y|N]  > y
sitrep logged
```


### Writing the Pentest Report
The exam report subdirectory contains a markdown file for each major section of the pentest report.  Notably, a markdown file exists for each point-value system.  During the exam use your favorite markdown editor of choice to document findings and evidence for each system.  I use Obsidian, so in my case I'd open a new vault in the report directory.  The markdown files contain guidance from the sample reports provided by Offensive Security.  I can write, modify, and delete in markdown without the need for any other tool.  Well, Flameshot too but you get the gist.

When the systems markdown are fully documented move on to edit the executive summary and closing markdown files.  There are several boilerplate variables in these documents that are automatically updated by autorpt with its finalize option.  It pulls these values from settings or prompts for them if they haven't been set.  

Just ignore any "BOILERPLATE_" items in the markdown files, they are important.

### Finalize - Generate Submission Files
Once all the report markdown files are content complete it is time to finalize them into a PDF file and 7z archive.  The `finalize` option does this automatically and updates boilerplate values from the template to reflect your input.

This example will compile a report for the OSCP.
```
$ autorpt.py finalize

 ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄   ▄▄▄·▄▄▄▄▄
▐█ ▀█ █▪██▌•██  ▪     ▀▄ █·▐█ ▄█•██  
▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄ ▐▀▀▄  ██▀· ▐█.▪
▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█•█▌▐█▪·• ▐█▌·
 ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀  ▀.▀    ▀▀▀ 
              Tag your work



[+] What is your student ID, if required (eg. OS-12345, N/A)? OS-12345
[+] What is your full email address? first.last@mysite.com

[i] From the following list, what syntax highlight style should be used for code in the report?
   Recommendation: lighter styles are easier to read.  Dark styles include: espresso, zenburn, and breezedark.
        0. pygments
        1. tango
        2. espresso
        3. zenburn
        4. kate
        5. monochrome
        6. breezedark
        7. haddock
[+] Pick a number for the style: 0
[i] Style set to pygments
[i] Generating PDF report ./report/OSCP_OS-12345_exam_report.pdf
[i] Generating 7z archive ./report/OSCP_OS-12345_exam_report.7z
```

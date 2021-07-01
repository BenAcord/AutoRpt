# AutoRpt
## What It Is
Streamline the exam report writing experience.  

1. (**startup**) Prior to starting an exam, creates a base exam directory structure and populates it with a markdown report template.  Run this well in advance of the exam start time.

2. (**finalize**) During the exam autorpt generates a final report PDF and 7z archive from your markdown files.

**TBD: Insert video or GIF here**

:clap: First, good luck on your exam and report writing endevors.  I wish you well.

:trophy: Second, mad props and respect to noraj for the "Offensive Security Exam Report Template in Markdown".

:hammer_and_wrench: Third, if you are looking for a solid markdown tool, take a look at Obsidian.

:warning: Finally, with that said... :exclamation: use at your own risk.

Happy writing!

---

## Install
### Dependencies & Caveats
AutoRpt has only been tested on Linux, specifically, Kali Linux.
- p7zip
- pandoc
- pandoc-data
```Bash
$ sudo apt-get install -y p7zip pandoc pandoc-data
```

### Clone the Repo
```Bash
$ git clone https://github.com/BenAcord/AutoRpt.git
$ cd autorecon
$ sudo ln -s INSTALL_DIR/autorpt.py /usr/bin/autorpt
```

---

## Usage:
`autorpt.py [ help | startup | finalize ]`

## Example #1: Startup
**Scafold Exam Report Structure**
Similar to how tools like autorecon and nmapAutomator create subdirectories for organizing enumeration output files during the pentest, autorpt does something similar for reporting.  The startup option creates a directory for the selected exam and a report subdirectory.  It then populates a barebones targets.txt file for recon scripts.  Then it copies a markdown template file for each major section of the final report.  These files are numbered similar to chapters and named with the respective system point value.  A tree structure is displayed showing the new exam home.

Change directory to the location where you want the exam directory to be created.  Then run `autorpt.py startup`.

If you created a symbolic link as shown in the "Install, Clone the Repo" section of this readme the command can be shortened to `autorpt startup`.


After running `autorpt startup` change to the newly created exam directory (eg. `cd oscp`) before running any scan tools.  This will keep all recon output subdirectories in the exam directory.

```
$ autorpt.py startup

 ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄   ▄▄▄·▄▄▄▄▄
▐█ ▀█ █▪██▌•██  ▪     ▀▄ █·▐█ ▄█•██  
▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄ ▐▀▀▄  ██▀· ▐█.▪
▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█•█▌▐█▪·• ▐█▌·
 ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀  ▀.▀    ▀▀▀ 
              Tag your work


Available exam templates:
        0.  ejpt
        1.  example_oscp
        2.  oscp
        3.  osed
        4.  osee
        5.  osep
        6.  oswe
        7.  oswp
        8.  training
[+] Pick a number for the exam are you taking: 1

[i] Copying templates directory for the selected exam.
[i] Templates successfully copied to report directory.  Here's the new structure:

oscp/
├── README
├── report/
│   ├── 0-execsummary.md
│   ├── 1-10pt.md
│   ├── 2-20ptA.md
│   ├── 3-20ptB.md
│   ├── 4-25ptA.md
│   ├── 5-25pt-bufferoverflow.md
│   └── 6-closing.md
└── targets.txt
```

## Example #2: Writing the Pentest Report
The exam/report subdirectory contains a markdown file for each major section of the pentest report.  Notably, a markdown file exists for each point-value system.  During the exam use your favorite markdown editor of choice to document findings and evidence for each system.  I use Obsidian, so in my case I'd open a new vault in the oscp/report directory.  The markdown files contain guidance from the sample reports provided by Offensive Security.  I can write, modify, and delete in markdown without the need for any other tool.  Well, Flameshot too but you get the gist.

When the systems markdown are fully documented move on to edit the executive summary and closing markdown files.  There are several boilerplate variables in these documents that are automatically updated by autorpt with its finalize option.  Just ignore any "BOILERPLATE_" items, they are important.

## Example #3: Generate Submission Files
Once all the report markdown files are content complete it is time to finalize them into a PDF file and 7z archive.  The `finalize` option does this automatically and updates boilerplate values from the template to reflect your input.

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

## Example #4: Displaying help
Sometimes it is good to read a man page or a bit of documentation.  autorpt will display help if any of the following options are submitted: `-h`, `help`, `--help`.

```
$ autorpt.py help

 ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄   ▄▄▄·▄▄▄▄▄
▐█ ▀█ █▪██▌•██  ▪     ▀▄ █·▐█ ▄█•██  
▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄ ▐▀▀▄  ██▀· ▐█.▪
▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█•█▌▐█▪·• ▐█▌·
 ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀  ▀.▀    ▀▀▀ 
              Tag your work


[!] Use at your own risk.

AutoRpt is an exam preparation aid accomplishing two main reporting tasks:
1. (startup) Prior to starting an exam, it creates a base exam directory
   structure with markdown report templates.
   It is a good idea to run this well in advance of the exam start.

2. (finalize) During the exam and after the VPN drops, autorpt generates 
   a final PDF and 7z.

Usage: autorpt.py [ help | startup | finalize ]

Examples:

  1. when you are ready to start an exam:
    autorpt.py startup

  2. after the report is written:
    autorpt.py finalize
```

## Example #5: No Prompts for Input
Add your detais to the config.yml file and autorpt will not prompt for those values.
```
TBD
```

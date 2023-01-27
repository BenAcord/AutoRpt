## Assignment Y

### Proof.txt

- proof.txt: `xxx`

Provide a screenshot of running `type proof.txt` and the `ipconfig` command from the directory where proof.txt is stored.

![local.txt](images/placeholder-image-300x225.png)

### Initial Analysis

Provide relevant techniques and methods used to perform enumeration of the application, including **network ports**, **security mitigations** etc. The steps taken should be reproducible and easy to understand. Include any custom code or references to public tools.

Listening Ports:

- `192.168.xx.xx:yyyy`
- `127.0.0.1:zzzz`
- `0.0.0.0:zzzz`

Security Mitigations:

- `xxx.dll`: ASLR, DEP, SafeSEH
- `yyy.dll`: ASLR, DEP, SafeSEH
- `zzz.dll`: ASLR, DEP, SafeSEH

References:

- [tool xxx](https://github.com)

### Application Analysis

Provide a description of the analysis performed against the application, this includes both **dynamic** and **static** analysis.

The analysis should include any reverse engineering performed to understand network protocols or file formats as well as how the application may be triggered to dispatch available commands.

#### Static Analysis

- static analysis

#### Dynamic Analysis

- dynamic analysis

### Vulnerability Discovery

Provide relevant analysis steps to locate vulnerabilities inside the application, this includes both results from static analysis and dynamic analysis.

As part of the documentation, proof of concept **Python3** code must be **created** and **explained** that triggers the vulnerabilities.

Only the steps that ended up working are required.

#### Analysis

- vuln discovery analysis

#### Initial PoC

To install the dependencies required for PoC execution:

```default
package_manager install dependency1 dependency2
```

Provide the proof of concept code used to **trigger the vulnerability**.

```python
#!/usr/bin/env python3

print('[+] Triggering vulnerability')
```

### Exploit Creation

Provide a description of steps to create the exploit, this includes how to combine vulnerabilities, how to bypass DEP and how to write any custom shellcode. At the end of this section the full exploit code should be developed while an explanation of each step should be performed.

Steps to Create the Exploit:

1. step one
2. step two

#### Full PoC

Provide the proof of concept code used to **gain access to the server**.

```python
#!/usr/bin/env python3

print('[+] Exploit sent, awaiting shell')
```
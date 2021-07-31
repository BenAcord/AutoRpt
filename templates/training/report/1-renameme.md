---
title: "BOILERPLATE_HOSTNAME Write-Up"
author: ["BOILERPLATE_EMAIL"]
date: "BOILERPLATE_DATE"
subject: "Markdown"
keywords: [Markdown, Example]
subtitle: "BOILERPLATE_HOSTNAME Write-Up"
lang: "en"
titlepage: true
titlepage-color: "1E90FF"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# BOILERPLATE_HOSTNAME Write-Up

## Introduction

Describe the lab and the target system and a high-level summary of the results.

## Recommendations

Reasoning behind the approach to remediation recommendations.

1. first 
2. second
3. C
4. D
5. Fifth

## System: 192.168.x.x - Hostname

### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.  This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.  Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.  In some cases, some ports may not be listed.

**Nmap Scan Results**

Protocol | Ports Open
---|---
**TCP** | 1433,3389
**UDP** | 1434,161

**Vulnerability Analysis**

*Initial Shell Vulnerability Exploited*

**Severity: Critical or High**

*Explanation*

**Vulnerability Explanation**

*Explanation and additional info about where the initial shell was acquired from*

**Vulnerability Fix**

*Explanation*

### Exploitation & Low Privilege Shell

Steps to reproduce:

1. A 
2. B
3. C

**Proof of Concept Code**

If you have not made any modifications to an exploit, you should only provide the URL where the exploit can be found. Do not include the full unmodified code, especially if it is several pages long.  
If you have modified an exploit, you should include:

- The modified exploit code
- The URL to the original exploit code
- The command used to generate any shellcode (if applicable)
- Highlighted changes you have made
- An explanation of why those changes were made


### Local.txt

**Screenshot**

> Screenshot must show proof.txt contents with `cat` or `type` command and output from `ipconfig` or `ip`.  Additionally, search the system for local.txt to cover all bases.  

Ensure all pasted images are in this markdown format
"\"![Pasted image 20210510161424.png](Pasted image 20210510161424.png)""

**Contents**

> local.txt

### Privilege Escalation

**Vulnerability Analysis**

*Additional Priv Esc info*

**Vulnerability Exploited**

**Vulnerability Explanation**

**Vulnerability Fix**

**Severity: Critical or High**

**Exploitation & Administrative Shell**

Steps to reproduce:

1. A 
2. B
3. C


**Exploit Code**

If you have not made any modifications to an exploit, you should only provide the URL where the exploit can be found. Do not include the full unmodified code, especially if it is several pages long.  
If you have modified an exploit, you should include:

- The modified exploit code
- The URL to the original exploit code
- The command used to generate any shellcode (if applicable)
- Highlighted changes you have made
- An explanation of why those changes were made


### Proof.txt

**Screenshot**

Screenshot must show proof.txt contents with `cat` or `type` command and output from `ipconfig` or `ip`.  Additionally, search the system for local.txt to cover all bases.  

Ensure all pasted images are in this markdown format
"\"![Pasted image 20210510161424.png](Pasted image 20210510161424.png)""

**Contents**

> proof.txt

## Conclusion

Capture your summary thoughts here.
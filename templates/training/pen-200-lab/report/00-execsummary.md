---
title: "PEN-200 Lab Report"
author: ["BOILERPLATE_EMAIL", "OSID: BOILERPLATE_OSID"]
date: "BOILERPLATE_DATE"
subject: "Penetration Testing with Kali Linux"
keywords: [network penetration testing, buffer overflow]
subtitle: "PEN-200 Lab Report"
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
# Offensive Security PEN-200 Lab Report

Copyright © 2022 Offensive Security Ltd. All rights reserved.

No part of this publication, in whole or in part, may be reproduced, copied, transferred or any other right reserved to its copyright owner, including photocopying and all other copying, any transfer or transmission using any network or other means of communication, any broadcast for distant learning, in any form or by any means such as any information storage, transmission or retrieval system, without prior written permission from Offensive-Security.

## Introduction

The Offensive Security Exam penetration test report contains all efforts that were conducted in order to pass the Offensive Security exam.  This report will be graded from a standpoint of correctness and fullness to all aspects of the exam.  The purpose of this report is to ensure that the student has a full understanding of penetration testing methodologies as well as the technical knowledge to pass the qualifications for the Offensive Security Certified Professional.

## Objective

The objective of this assessment is to perform an internal penetration test against the Offensive Security Exam network.  The student is tasked with following methodical approach in obtaining access to the objective goals.  This test should simulate an actual penetration test and how you would start from beginning to end, including the overall report.  

An example page has already been created for you at the latter portions of this document that should give you ample information on what is expected to pass this course.  Use the sample report as a guideline to get you through the reporting.

## Requirements

The student will be required to fill out this penetration testing report fully and to include the following sections:

- Overall High-Level Summary and Recommendations (non-technical)
- Methodology walkthrough and detailed outline of steps taken
- Each finding with included screenshots, walkthrough, sample code, and proof.txt if applicable
- Any additional items that were not included

# High-Level Summary

I was tasked with performing an internal penetration test towards Offensive Security Exam.
An internal penetration test is a dedicated attack against internally connected systems.
The focus of this test is to perform attacks, similar to those of a hacker and attempt to infiltrate Offensive Security's internal exam systems - the THINC.local domain.
My overall objective was to evaluate the network, identify systems, and exploit flaws while reporting the findings back to Offensive Security.

BOILERPLATE_VULNS_CHART

When performing the internal penetration test, there were several alarming vulnerabilities that were identified on Offensive Security's network.  When performing the attacks, I was able to gain access to multiple machines, primarily due to outdated patches and poor security configurations.  During the testing, I had administrative level access to multiple systems.  All systems were successfully exploited and access granted.  These systems as well as a brief description on how access was obtained are listed below:

BOILERPLATE_VULNS_TABLE

## Recommendations

I recommend patching the vulnerabilities identified during the testing to ensure that an attacker cannot exploit these systems in the future.  One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

BOILERPLATE_VULNS_RECOMMENDATIONS

# Methodologies

I utilized a widely adopted approach to performing penetration testing that is effective in testing how well the Offensive Security Exam environments is secured.  Below is a breakout of how I was able to identify and exploit the variety of systems and includes all individual vulnerabilities found.

## Information Gathering

The information gathering portion of a penetration test focuses on identifying the scope of the penetration test.  During this penetration test, I was tasked with exploiting the exam network.
The specific IP addresses were:

**Exam Network**

BOILERPLATE_TARGETS_LIST

## Penetration

The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems.
During this penetration test, I was able to successfully gain access to **X** out of the **X** systems.

## Maintaining Access

Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable.  The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again.  Many exploits may only be exploitable once and we may never be able to get back into a system after we have already performed the exploit.

## House Cleaning

The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organization's computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important.

After collecting trophies from the exam network was completed, I removed all user accounts and passwords as well as the Meterpreter services installed on the system.

Offensive Security should not have to remove any user accounts or services from the system.

# Details

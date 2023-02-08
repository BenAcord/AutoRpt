---
title: "BOILERPLATE_AUTHOR WEB-300 Lab Report"
author: ["BOILERPLATE_EMAIL", "OSID: BOILERPLATE_OSID"]
date: "BOILERPLATE_DATE"
subject: "Advanced Web Attacks and Exploitation"
keywords: [web application security, white box penetration testing]
subtitle: "Advanced Web Attacks and Exploitation"
lang: "en"
titlepage: true
titlepage-color: "FF8C00"
titlepage-text-color: "000000"
titlepage-rule-color: "000000"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# WEB-300 Lab Report

Copyright © 2022 Offensive Security Ltd. All rights reserved.

No part of this publication, in whole or in part, may be reproduced, copied, transferred or any other right reserved to its copyright owner, including photocopying and all other copying, any transfer or transmission using any network or other means of communication, any broadcast for distant learning, in any form or by any means such as any information storage, transmission or retrieval system, without prior written permission from Offensive-Security.

## Introduction

The Offensive Security WEB-300 lab documentation contains all efforts that were conducted in
order to pass the Offensive Security Advanced Web Attacks and Exploitation lab. This report will be graded from a standpoint of correctness and fullness to all aspects of the course. The purpose of this report is to ensure that the student has the technical knowledge required to complete the qualifications for the Offensive Security Advanced Web Attacks and Exploitation course.

## Objective

The objective of this assessment is to perform a white-box penetration test the Offensive Security lab network.  The student is tasked with following methodical approach in obtaining access to the objective goals.  This test should simulate an actual white-box penetration test with Proof of Concept and how you would start from beginning to end, including the overall report.

## Requirements

The student will be required to fill out this lab documentation fully and to include the
following sections:

- Methodology walkthrough and detailed outline of steps taken
- Each finding with included screenshots, walkthrough, sample code, and proof.txt if
applicable.
- Any additional items that were not included

# High-Level Summary

I was tasked with performing a white-box penetration test towards Offensive Security.
A white-box penetration test is sifting through the massive amount of data available to identify potential points of weakness.  The focus of this test is to provide a comprehensive assessment of both internal and external vulnerabilities.  My overall objective was to evaluate the application, identify vulnerabilities, and write automated exploit while reporting the findings back to Offensive Security.

BOILERPLATE_VULNS_CHART

When performing the white-box penetration test, there were several critical vulnerabilities that were identified on Offensive Security's network.  When performing the attacks, I was able to gain access to multiple machines, primarily due to design flaws and implementation errors.  During the testing, I had a shell access to multiple systems.  All systems were successfully exploited and access granted.

These systems as well as a brief description on how access was obtained are listed below:

BOILERPLATE_VULNS_TABLE

## Recommendations

I recommend patching the vulnerabilities identified during the testing to ensure that an attacker cannot exploit these systems in the future.  One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

BOILERPLATE_VULNS_RECOMMENDATIONS

# Whitebox audit

The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems.  During this penetration test, I was able to successfully gain access to **X** out of the **2** systems.

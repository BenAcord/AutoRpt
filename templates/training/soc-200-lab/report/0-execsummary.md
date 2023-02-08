---
title: "BOILERPLATE_AUTHOR SOC-200 Lab Report"
author: ["BOILERPLATE_EMAIL", "OSID: BOILERPLATE_OSID"]
date: "BOILERPLATE_DATE"
subject: "SOC-200 Security Operations and Defensive Analysis"
keywords: [security operations, defensive analysis]
subtitle: "Security Operations and Defensive Analysis"
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
# Offensive Security SOC-200 Lab Report

Copyright © 2022 Offensive Security Ltd. All rights reserved.

No part of this publication, in whole or in part, may be reproduced, copied, transferred or any other right reserved to its copyright owner, including photocopying and all other copying, any transfer or transmission using any network or other means of communication, any broadcast for distant learning, in any form or by any means such as any information storage, transmission or retrieval system, without prior written permission from Offensive-Security.

## Introduction

The Offensive Security SOC-200 lab report contains all efforts that were conducted in order to pass the Offensive Security Security Operations and Defensive Analysis course.  This report should contain all items that were used to complete the course and it will be graded from a standpoint of correctness and fullness to all aspects of the lab.  The purpose of this report is to ensure that the student has a full understanding of security detection methodologies as well as the technical knowledge to pass the qualifications for the Offensive Security Defense Analyst.

## Objective

The objective of this assessment is to perform detections and analysis on the simulated lab network in order to determine which attacker actions took place in each of the 10 phases.

An example page has already been created for you at the latter portions of this document that should demonstrate the amount of information and detail that is expected in the report.
Use the sample report as a guideline to get you through the reporting.

## Requirements

The student will be required to fill out this lab report fully and to include the following sections:

1. Overall High-Level Summary of level of compromise
2. Detailed walkthrough of attacker actions in each phase
3. Each finding with included screenshots, explanations, event / log entries, and KQL queries if applicable.

# High-Level Summary

This report details and documents the attacks observed against the Offensive Security Security Operations and Defensive Analysis lab network.

The attacker organization started by performing a brute force against an internet accessible RDP server called APPSRV02 and obtained administrative access. This led to a complete compromise of the server.

Next the attacker performed lateral movement to the internal server APPSRV02 by reusing stolen credentials from APPSRV02, this also led to a complete compromise of APPSRV03.

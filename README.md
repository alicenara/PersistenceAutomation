# Persistence Automation
Persistence deployment automation

The most recent version of the PDF document can be found [in this link](https://alicenara.github.io/PersistenceAutomation/documents/docsTFG/mainTFG.pdf).

## Description

This is a tool to automate the deployment of persistence on both Windows and Linux, using a customizable 
configuration file and the data obtained after executing some discovery techniques on the machine.

These scripts are programmed in Python 3 (Linux) and PowerShell 5 (Windows).
To run them, only three elements are needed:
1. A configuration file, with all the necessary parameters filled. This file needs to be in the same
folder as the script. 
2. A payload or a script to be executed. This payload should be in the same folder as
this tool or have its path specified in the configuration options.

## Starting up

First of all, the script needs to be executable. 
It can be achieved using the following commands:

```
### For the Linux script ###
> chmod +x ./linPDA.py

### For the Windows script, on the PowerShell console ###
> Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

```

### Configuration file

Possible functions to execute:

- Protocols to be checked: HTTPS, DNS, ICMP
- Linux functions: checkRoot, adduser, crontab, init, service, sshShell, sshAuth, ncShell,
            toolHTTPS, toolDNS, toolICMP
- Windows functions: checkAdmin, downloadFile, copyFile, addUser, startupFolder, registry, 
            scheduledTask, service, wmi, bitsJob, rdp, toolHTTPS, toolDNS, toolICMP
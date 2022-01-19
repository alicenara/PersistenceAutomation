# Tool section
Here is some more information about the tool

## Config file
It must be named "config.json" (or the name must be changed in the scripts).

Also, the following parameters are optional, as they have default values in the script, except for "path", "URL", or the backdoor commands as at least one needs to be set for the script to work.

BE AWARE that JSON files cannot have comments!


### Shared parameters
```
"envvars": {
    "userHome": (string) - path to the user's home
    "userName": (string) - user name
    "scriptPath": (string) - path where this script is being executed
},

# Internet  config
"discovery": {
    "pingTestIP": (string) - IP to ping
    "httpsTestUrl": (string) - URL to test HTTPS connection
    "proxy": (string) - proxy configuration (if known)
},
# Payload config
"payload": {
    "name": (string) - name of the payload
    "path": (string) - path of the payload
    "URL": (string) - website that will be used to download the payload
    "pathToSave": (string) - new path of the payload, if set the payload will copy or download to this path
    "preArguments": (string) - arguments needed to run the payload, before its path (example: python3)
    "postArguments": (string) - arguments needed to run the payload, after its path (example: "-retry 5")
    "output": (string) - used to redirect the output (example: "> out.txt")  
},
"persistence": {
    # Add user config
    "adduserName": (string) - name of the new user
    "adduserPass": (string) - password of the new user
    # Service config
    "serviceName": (string) - name of the new service
},
"backdoors":{
    # Commands for the backdoor tool
    "HTTPSCommand": (string) - for external tools, the exact command to execute an HTTPS backdoor.
    "HTTPSCommandPreProxy": (string) - the command that goes before the proxy argument, to execute an HTTPS backdoor.
    "HTTPSCommandPostProxy": (string) - the command that goes after the proxy argument, to execute an HTTPS backdoor.
    "DNSCommand": (string) - for external tools, the exact command to execute an DNS backdoor.
    "ICMPCommand": (string) - for external tools, the exact command to execute an ICMP backdoor.        
},
"preferences": {
    "excludedTechniques": (array) - prevents the execution of the listed techniques (system specific)
    "includedTechniques":  (array) - only executes the listed techniques (system specific)
    "excludedProtocols":  (array) - prevents the execution of the listed protocols (system specific)
    "forceProtocols":  (array) - forces the execution of the listed protocols (system specific)
}

```

### Windows specific parameters

Possible functions to execute (they must be specified in the "preferences" arrays):

- Protocols to be checked: HTTPS, DNS, ICMP
- Windows functions: checkAdmin, downloadFile, copyFile, addUser, startupFolder, registry, 
            scheduledTask, service, wmi, bitsJob, rdp, toolHTTPS, toolDNS, toolICMP
```
"persistence": {
    # Registry config
    "regName": (string) - name of the new registry key
    # Scheduled Tasks config
    "schedTaskName": (string) - name of the new scheduled task
    "schedTaskTime": (string) - frequency of execution of the new scheduled task (example: "-AtStartup")
    # WMI config
    "wmiName": (string) - name of the new WMI subscription
    # BITS Job config
    "bitsName": (string) - name of the new BITS Job
    "bitsRetry": (integer) - time in seconds to retry if failed
},
```
### Linux specific parameters

Possible functions to execute (they must be specified in the "preferences" arrays):

- Protocols to be checked: HTTPS, DNS, ICMP
- Linux functions: checkRoot, addUser, crontab, init, service, sshShell, sshAuth, ncShell,
            toolHTTPS, toolDNS, toolICMP
```
"persistence": {
    # Add user config
    "adduserArgs": (string) - arguments to use when creating a user (example: "-s /bin/bash"),
    # Cron config
    "cronjobTime": (string) - frequency of the cronjob (example: "@reboot")
},
"backdoors":{
    # External server config
    "serverIPURL": (string) - the IP or URL of an external server (for SSH and netcat)
    "serverPort": (string) - the open port of an external server (for SSH and netcat)
    "serverUser":(string) - a user of the external server
    # SSH config
    "sshAuthKey": (string) - a public SSH key (to add to authorized_keys)
}
```
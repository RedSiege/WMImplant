function Get-WMIEventLogins
{
<#
.SYNOPSIS

Creates an LDAP Session

Author: Evan Peña
License: GPLv3
Required Dependencies: Local Admin Account on Target
Optional Dependencies: None
 
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

.EXAMPLE
gc hosts | Get-WMIEventLogins -User foo -bar password

#>
    
	Param
       (

        [Parameter(Mandatory = $False, ValueFromPipeLine=$True)] 
        [string[]]$Targets = ".",
        [Parameter(Mandatory = $False)]
        [string]$User,
        [Parameter(Mandatory = $False)] 
        [string]$Pass	 
		)
		
	#$domain = new-object DirectoryServices.DirectoryEntry("LDAP://$DCHostName",$Credential.UserName, $Credential.GetNetworkCredential().Password)    
    Process {
        mkdir temp
                        
        if($User -and $Pass)
        {
            # This block of code is executed when starting a process on a remote machine via wmi
            $password = ConvertTo-SecureString $Pass -asplaintext -force 
            $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password

            Foreach($computer in $TARGETS)
            {
                $temp = Get-WmiObject -computername $computer -Credential $cred -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | where { $_.Message | Select-String "Logon Type:\s+3" | Select-String "Logon Process:\s+NtlmSsp"}                
                $temp | select message | Format-Table -Wrap | Out-File test.txt
                gc temp\$computer.txt | Select-String -pattern "workstation name", "account name"
            }
        }

        elseif(($Targets -ne ".") -and !$User)
        {            
            # user didn't enter creds. Assume using local user priv has local admin access to Targets            
            Foreach($computer in $TARGETS)
            {
                $temp = Get-WmiObject -Impersonation Impersonate -computername $computer -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | where { $_.Message | Select-String "Logon Type:\s+3" | Select-String "Logon Process:\s+NtlmSsp"}
                $temp | select message | Format-Table -Wrap | Out-File test.txt
                gc temp\$computer.txt | Select-String -pattern "workstation name", "account name"
            }
        }

        else
        {                      
            # If this area of code is invoked, it runs the command on the same machine the script is loaded
            $temp = Get-WmiObject -query "SELECT * FROM Win32_NTLogEvent WHERE (logfile='security') AND (EventCode='4624')" | where { $_.Message | Select-String "Logon Type:\s+3" | Select-String "Logon Process:\s+NtlmSsp"}                        
            $temp | select message | Format-Table -Wrap | Out-File test.txt
            gc temp\localhost.txt | Select-String -pattern "workstation name", "account name"
        }

    }
}
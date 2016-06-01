$a = Get-Content C:\Tools\all_local_admin_no_hashes.txt
foreach ($line in $a) {
    $test = $line -split "\s+"
    $computer = $test[0]
    $username = $test[1]  
    $pass = $test[2]

    $password = ConvertTo-SecureString $pass -asplaintext -force 
    $creds = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $username,$password

    Get-WMIEventLogins -Target $computer -Creds $creds -FileName C:\temp\wmi_eventlog_output\$computer.txt -Read no
}
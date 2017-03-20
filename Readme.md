#WMImplant

WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines, but also as the C2 channel for issuing commands and receiving results.  WMImplant will likely require local administrator permissions on the targeted machine.

Developed by [@christruncer](https://twitter.com/christruncer)


# WMImplant Functions:

## Meta Functions
    change_user                         -   Change the context of the user you will execute WMI commands as
    exit                                -   Exits WMImplant
    gen_cli                             -   Generate the command line command to use WMImplant non-interactively
    set_default                         -   Sets the targeted system's WMI property back to its default value
    help                                -   View the list of commands and descriptions

## File Operations
    cat                                 -   Reads the contents of a file
    download                            -   Download a file from the targeted machine
    ls                                  -   File/Directory listing of a specific directory
    search                              -   Search for a file on a user-specified drive
    upload                              -   Upload a file to the targeted machine

## Lateral Movement Facilitation
    command_exec                        -   Run a command line command and receive the output
    disable_wdigest                     -   Removes registry value UseLogonCredential
    disable_winrm                       -   Disables WinRM on the targeted system
    enable_wdigest                      -   Adds registry value UseLogonCredential
    enable_winrm                        -   Enables WinRM on the targeted system
    registry_mod                        -   Modify the registry on the targeted machine
    remote_posh                         -   Run a PowerShell script on a remote machine and receive the output
    sched_job                           -   Manipulate scheduled jobs
    service_mod                         -   Create, delete, or modify system services

## Process Operations
    process_kill                        -   Kill a process via name or process id on the targeted machine
    process_start                       -   Start a process on the targeted machine
    ps                                  -   Process listing

## System Operations
    active_users                        -   List domain users with active processes on the targeted system
    basic_info                          -   Used to enumerate basic metadata about the targeted system
    drive_list                          -   List local and network drives
    ifconfig                            -   Receive IP info from NICs with active network connections
    installed_programs                  -   Receive a list of the installed programs on the targeted machine
    logoff                              -   Log users off the targeted machine
    reboot                              -   Reboot the targeted machine
    power_off                           -   Power off the targeted machine
    vacant_system                       -   Determine if a user is away from the system

## Log Operations
    logon_events                        -   Identify users that have logged onto a system

# Usage

The easiest way to get up and running with WMImplant is to import the script and run Invoke-WMImplant. This will present you with the main menu and you can instantly start choosing a command to run. Within the main menu, you can also choose to have WMImplant output the command line command you would need to use in order to run WMImplant in a non-interactive manner.

Thanks to:
    [@evan_Pena2003](https://twitter.com/evan_pena2003) - For your help with code reviews and adding functionality into the tool
    [@danielbohannon](https://twitter.com/danielhbohannon) - For your help with code obfuscation

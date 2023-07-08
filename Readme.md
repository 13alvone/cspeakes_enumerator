```
   ___________ ____  _________    __ __ ___________    _______   ____  ____  ___
  / ____/ ___// __ \/ ____/   |  / //_// ____/ ___/   / ____/ | / / / / /  |/  /
 / /    \__ \/ /_/ / __/ / /| | / ,<  / __/  \__ \   / __/ /  |/ / / / / /|_/ / 
/ /___ ___/ / ____/ /___/ ___ |/ /| |/ /___ ___/ /  / /___/ /|  / /_/ / /  / /  
\____//____/_/   /_____/_/  |_/_/ |_/_____//____/  /_____/_/ |_/\____/_/  /_/

```                   

### Kali Linux Aggregated Enumerator

`cspeakes_enum` is a tool built to run on Kali Linux that completes some basic enumeration commands potentially useful during initial pentest discovery. 

***Please Note:
 
> There are further notes throughout the code as well, to help with further customization.
> Please Be Patient... It takes a bit to run all the tests (~15ish min).
> Don't Worry.. It outputs to screen and to text files for later review.
> This script is very LOUD, in that it will trigger a lot of alarms on a target system, assuming that target system is being properly monitored. For those obvious reasons, this should ONLY be used against systems you have permission to, such as those designed specifically for CTF challenges. For those who like to learn by doing, consider setting up a free Splunk instance, use the Splunk UF to forward local logs on a target machine in your LAN set up for this test, and then run this script from an attacker machine against the monitored machine. This will allow you to review what such activity looks like first hand, directly from Splunk SPL. BUT, this is not required at all.

## Installation (Easy Way):
```shell
git clone https://github.com/13alvone/cspeakes_enumerator.git
cd cspeakes_enumerator
chmod +x install.sh
./install.sh
```

## Basic Execution:
After installation, as shown above, the most abstracted command which uses everything you just installed can be called from anywhere in the terminal against a target IP such that: 
```shell
target <target_ip>
```
^^ This produces a folder with the ip name and subdirectories for typically needed things during a CTF engagement such as folders for exploits, info, artifacts, etc. Using this approach also ensures that the most UP-TO-DATE version of the `cspeakes_enum` script is used as this is git-pulled each time `target <any_ip>` is called, and it's done upon each execution. That updated script is then stored within the newly created folder named after the <target_ip> address provided. 

If you find some further configurations such as different ports or options after the first scan's results are returned, you can rerun the enumerator alone without (see Full Usage below for all options):
```shell
sudo <target_ip>/cspeakes_enumerator/cspeakes_enum <see_extended_usage>
```
***Please be sure to execute with `sudo` as some of the subcommands require NIC access permissions to run as expected.***

## Extended Usage:
```shell
usage: cspeakes_enum [-h] -i IP [-rpc RPC_PORT] [-s SCAN_TYPE] [-c COMMAND_TIMEOUT] [-ftp FTP_PORT] [-ssh SSH_PORT] [-smtp SMTP_PORT] [-dns DNS_PORT] [-pop POP_PORT]
                              [-smb SMB_PORT] [-snmp SNMP_PORT] [-http HTTP_PORT] [-https HTTPS_PORT]

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        Target IP Address
  -rpc RPC_PORT, --rpc_port RPC_PORT
                        Target RPC Port
  -s SCAN_TYPE, --scan_type SCAN_TYPE
                        Scan Speed: [`long` or `short`]
  -c COMMAND_TIMEOUT, --command_timeout COMMAND_TIMEOUT
                        Command Timeout [Default = 600 seconds]
  -ftp FTP_PORT, --ftp_port FTP_PORT
                        Target FTP Port
  -ssh SSH_PORT, --ssh_port SSH_PORT
                        Target SSH Port
  -smtp SMTP_PORT, --smtp_port SMTP_PORT
                        Target SMTP Port
  -dns DNS_PORT, --dns_port DNS_PORT
                        Target SSH Port
  -pop POP_PORT, --pop_port POP_PORT
                        Target POP Port
  -smb SMB_PORT, --smb_port SMB_PORT
                        Target SMB Port
  -snmp SNMP_PORT, --snmp_port SNMP_PORT
                        Target SNMP Port
  -http HTTP_PORT, --http_port HTTP_PORT
                        Target HTTP Port
  -https HTTPS_PORT, --https_port HTTPS_PORT
                        Target HTTPs Port

```

## Disclaimer:
*** This Python3 script utilizes subprocess and the `Shell=True` configuration. It is important to note that this is 
inherently insecure and can be dangerous to your system should you or someone else choose to fuzz some of the inputs 
so, please use this script carefully. Furthermore, this script MUST be run as root to get access to sockets so again,
BE CAREFUL AND ONLY USE THIS SCRIPT IF YOU UNDERSTAND WHAT IT IS DOING.  

This is a script that performs passive AND active information gathering tasks. DO NOT use this script to target any ip's, businesses, or organizations that you do not have explicit permission to target! IT IS ILLEGAL!
> I take NO responsibility for the use of this script as it was created for cyber security research/testing and educational uses only. Please be responsible and don't be that guy.


## Prerequisites (Typically pre-installed on KALI Linux by Default):
This tool utilizes several tools, so please be sure that you have these tools installed and in $PATH before you attempt to operate.
`[+] nmap`
`[+] massscan`
`[+] dirb`
`[+] gobuster`
`[+] dotdotpwn`
`[+] nikto`
`[+] rpcinfo`
`[+] nbtscan`
`[+] enum4linux`
`[+] python3`
`[+] snmpwalk`
`[+] snmpcheck`
`[+] onesixtyone`
`[+] tndcmd10g`

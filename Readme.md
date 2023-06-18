# Cspeakes Enum
-----------------------

`cspeakes_enum` is a tool that completes some basic enumeration commands useful during initial discovery.

[?] `~# cspeakes_enum -h`

```shell
usage: enumerator.py [-h] -i IP [-rpc RPC_PORT] [-s SCAN_TYPE] [-c COMMAND_TIMEOUT] [-ftp FTP_PORT] [-ssh SSH_PORT] [-smtp SMTP_PORT] [-dns DNS_PORT] [-pop POP_PORT]
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

##### Please Note:


* There are notes in the code as well, to help with further customization.
 ... & Please Be Patient... It takes a bit to run all the tests (~15ish min).
 ... & Don't Worry.. It outputs to screen and to text files for later review.


##### Disclaimer:
*** This Python3 script utilizes subprocess and the `Shell=True` configuration. It is important to note that this is 
inherently insecure and can be dangerous to your system should you or someone else choose to fuzz some of the inputs 
so, please use this script carefully. Furthermore, this script MUST be run as root to get access to sockets so again,
BE CAREFUL AND ONLY USE THIS SCRIPT IF YOU UNDERSTAND WHAT IT IS DOING.  

This is a script that performs passive AND active information gathering tasks. DO NOT use this script to target any ip's, businesses, or organizations that you do not have explicit permission to target! IT IS ILLEGAL!
  ##### I take NO responsibility for the use of this script as it was created for cyber security research/testing and educational uses only.


##### Prerequisites (Typically pre-installed on KALI Linux):
This tool utilizes several tools, so please be sure that you have these tools installed and in $PATH before you attempt to operate.
[+] nmap
[+] massscan
[+] dirb
[+] gobuster
[+] dotdotpwn
[+] nikto
[+] rpcinfo
[+] nbtscan
[+] enum4linux
[+] python3
[+] snmpwalk
[+] snmpcheck
[+] onesixtyone
[+] tndcmd10g

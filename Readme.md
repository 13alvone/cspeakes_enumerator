# cspeakes_enumerator.py
-----------------------

Cspeakes_emulator is a tool for doing some very basic but robust general enumeration commands I use for initial discovery. Usage is simple as you need only supply the target IP address:

[+] ```~# python3 cspeakes_enumerator.py -i <target_ip> -n <eth0> -s short -c 600```

[?] `~# python3 cspeakes_enumerator.py`

`usage: cspeakes_enumerator.py [-h] -i IP [-n NIC] [-hp HTTP_PORT] [-hps HTTPS_PORT] [-rpc RPC_PORT]
                              [-s SCAN_TYPE] [-c COMMAND_TIMEOUT]
`
##### Please Note:


* There are notes in the code as well, to help with further customization.
* There are currently no options, simply supply the script with a target ip.
 ... & Please Be Patient... It takes a bit to run all the tests (~20ish min).
 ... & Don't Worry.. It outputs to screen and to text files for later review.


##### Disclaimer:
*** This Python3 script utilizes subprocess and the `Shell=True` configuration. It is important to note that this is 
inherently insecure and can be dangerous to your system should you or someone else choose to fuzz some of the inputs 
so, please use this script carefully. Furthermore, this script MUST be run as root to get access to sockets so again,
BE CAREFUL AND ONLY USE THIS SCRIPT IF YOU UNDERSTAND WHAT IT IS DOING.  

Gotta be that guy real quick....
 
 This is a script that performs passive AND active information gathering tasks. DO NOT use this script to target any ip's, businesses, or organizations that you do not have explicit permission to target! IT IS ILLEGAL!
  ##### I take NO responsibility for the use of this script as it was created for cyber security research/testing and educational uses only.
  
There. Done being that guy.


##### Prerequisites:
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
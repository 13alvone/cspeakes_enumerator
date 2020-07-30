# Author: Chris Speakes
# Email: 13alvone@gmail.com

import os
import sys
import time
import math

# PRE CONFIGURATION ==================================================================
suppression = ' >/dev/null 2>&1'                            # Suppression, change if needed
rootWordlistPath = '/root/HACK_TOOLS/cspeakes_wordlists/'   # Change to proper directory

# IF NO ARGS =========================================================================
if len(sys.argv) != 2:
    print('Usage: cspeakes_enumerator.py <ip>')
    exit(0)

# STATIC VARS ========================================================================
original_start_time = time.time()
command_list = []
ip = sys.argv[1]


# TIME UPDATER =======================================================================
def print_elapsed_time():
    global original_start_time
    seconds = round(int(time.time() - original_start_time), 2)
    minutes = math.trunc(seconds / 60)
    remaining_seconds = math.trunc(seconds - (minutes * 60))
    if len(str(remaining_seconds)) != 2:
        remaining_seconds = '0' + str(remaining_seconds)
    elapsed_time = str(minutes) + ':' + str(remaining_seconds)
    print('Time Elapsed: ' + elapsed_time)


# BOILER-PLATE FOR ALL TARGETS =======================================================
def all_tests_engage(ip):
    global command_list
    print('Started Script! Please Be Patient...')
    start_time = time.time()
    pre_cmd0 = 'nmap -sC -sV -O -A ' + str(ip) + ' >> nmap_' + str(ip)
    pre_cmd1 = 'nmap -p1-65535 ' + str(ip) + ' >> nmap_' + str(ip)
    pre_cmd2 = 'masscan -p1-65535,U:1-65535 ' + str(ip) + ' --rate=1000 -e tun0 -oL masscan_' + str(ip)
    command_list.append('[STEP 1] - Do some initial recon: ')

    try:
        os.system(pre_cmd0)
        print('1. nmap 1 == Complete!')
        print_elapsed_time()
        command_list.append('[+] Initial nmap targeting all services and '
                            'all version checks for all ports found completed.')
        command_list.append(pre_cmd0)
    except:
        print('1. nmap 1 == Failed')
        print_elapsed_time()
    try:
        os.system('echo "====================\n" >> nmap_' + str(ip))
        os.system(pre_cmd1)
        print('2. nmap ALL == Complete!')
        print_elapsed_time()
        command_list.append('[+] Secondary nmap targeting all ports completed.')
        command_list.append(pre_cmd1)
    except:
        print('2. nmap ALL == Failed')
        print_elapsed_time()
    try:
        os.system(pre_cmd2 + suppression)
        print('3. masscan == Complete!')
        print_elapsed_time()
        command_list.append('[+] Last port scan completed with masscan checking all UDP ports as well.')
    except:
        print('3. masscan == Failed')
        print_elapsed_time()

    # GET PORTS OPEN ====================================================================
    file_name = 'nmap_' + str(ip)
    file_in = open(file_name, 'r')
    http_flag = 0
    flag = 0
    port_list = []

    for line in file_in:
        if "====================" in line:
            http_flag = 1
        if 'PORT' in line and http_flag == 1:
            flag = 1
        elif 'Nmap' in line or line == '' or line == '\n':
            flag = 0
        elif flag == 1 and http_flag == 1:
            x = line.split('/')
            port_list.append(x[0])
    print('|||||||||||||||||||||||||||||||||||||||')
    print('**** Open Ports Detected: ')
    print('|||||||||||||||||||||||||||||||||||||||')
    command_list.append('[+] The following ports were reported as open or filtered.')
    for port in port_list:
        print(port)
        command_list.append(str(port))

    # PORT-SPECIFIC SCANS ===============================================================
    # PORT 21 ===========================================================================
    ftp_cmd0 = 'nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,' \
               'ftp-vuln-cve2010-4221,tftp-enum -p 21 ' + str(ip) + ' | tee ftp_' + str(ip)
    command_list.append(ftp_cmd0)

    if '21' in port_list:
        print('TESTING PORT 21:')
        try:
            os.system(ftp_cmd0)
            print('ftp_nmap_special == Complete!')
            print_elapsed_time()
        except:
            print('ftp_nmap_special == Failed')
            print_elapsed_time()

    # PORT 25 ==========================================================================
    smtp_cmd0 = 'nmap –script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,' \
                'smtp-vuln-cve2011-1764 -p 25 ' + str(ip) + ' | tee smtp_' + str(ip)

    if '25' in port_list:
        print('TESTING PORT 25')
        try:
            os.system(smtp_cmd0)
            print('smtp_nmap_special == Complete!')
            print_elapsed_time()
        except:
            print('smtp_nmap_special == Failed')
            print_elapsed_time()

    # PORT 80 ====================================================================
    # Http checks involve dirb, dotdotpwn(disabled by default), nikto, and gobuster tests
    # longer version is disabled by default. Uncomment the two lines below to enable LONG check.
    #http_cmd0 = 'dirb http://' + str(ip) + ' /usr/share/wordlists/dirb/common.txt -x ' + \
    #            str(rootWordlistPath) + '/extensions.txt -r -l -i -f -o dirb_' + str(ip)   # LONG VERSION
    http_cmd0 = 'dirb http://' + str(ip) + ' /usr/share/wordlists/dirb/small.txt -x ' \
                + str(rootWordlistPath) + '/extensions.txt -r -l -i -f -o dirb_' + str(ip)  # SHORTER OPTION
    http_cmd1 = 'dotdotpwn -d 6 -m http -h ' + str(ip) + ' -b -q -r dotdotpwn_' + str(ip)
    http_cmd2 = 'nikto -h ' + str(ip) + ' -output nikto_' + str(ip) + '.txt'
    http_cmd3 = 'gobuster dir -u http://' + str(ip) + '/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt ' \
                                                      '-s 302,307,200,204,301,403 -x sh,pl,py,ps1 ' \
                                                      '-t 150 -o cgi-bin_' + str(ip)
    http_cmd4 = 'gobuster dir -u http://' + str(ip) + ' -w /usr/share/wordlists/dirbuster' \
                                                      '/directory-list-2.3-medium.txt -t 150 -x php ' \
                                                      '-s "200,204,301,302,307,403,401" ' \
                                                      '-o gobuster_2nd_run_' + str(ip)
    command_list.append('Attempting the following commands: \n[+] ')

    if '80' in port_list or '8080' in port_list:
        command_list.append(http_cmd1 + '\n[+]')
        print('TESTING PORT 80')
        try:
            os.system(http_cmd0 + suppression)
            command_list.append(http_cmd0 + '\nOR\n')
            command_list.append(http_cmd1 + '\n[+]')
            print('dirb == Complete!')
            print_elapsed_time()
            temp_file = open('dirb_' + str(ip), 'r')
            temp_flag = 0
            for line in temp_file:
                if '/cgi-bin/' in line:
                    temp_flag = 1
            temp_file.close()
            if temp_flag == 1:
                try:
                    os.system(http_cmd3 + suppression)
                    command_list.append(http_cmd3 + '\n[+]')
                    print('cgi-bin gobuster scan == Complete!')
                    print_elapsed_time()
                except:
                    print('cgi-bin gobuster scan == Failed')
                    print_elapsed_time()
        except:
            print('dirb == Failed')
            print_elapsed_time()
        try:
            os.system(http_cmd2 + suppression)
            command_list.append(http_cmd2 + '\n[+]')
            print('nikto == Complete!')
            print_elapsed_time()
        except:
            print('nikto == Failed')
            print_elapsed_time()
        try:
            os.system(http_cmd4 + suppression)
            command_list.append(http_cmd4 + '\n[+]')
            print('gobuster == Complete!')
            print_elapsed_time()
        except:
            print('gobuster == Failed')
            print_elapsed_time()

    # PORT 111 ===================================================================
    rpc_cmd0 = 'rpcinfo -p ' + str(ip) + ' | tee rpcinfo_' + str(ip)

    if '111' in port_list:
        print('TESTING PORT 111')
        try:
            os.system(rpc_cmd0)
            command_list.append(rpc_cmd0 + '\n[+]')
            print('rpcinfo == Complete!')
            print_elapsed_time()
        except:
            print('rpcinfo == Failed')
            print_elapsed_time()

    # PORT 139, 445  =============================================================
    smb_cmd0 = 'nbtscan -r ' + str(ip) + ' | tee smb_' + str(ip)
    smb_cmd1 = 'enum4linux -a ' + str(ip) + ' | tee -a smb_' + str(ip)
    smb_cmd2 = 'nmap -sU -sS --script=smb-enum-users -p U:137,T:139 ' + str(ip) + ' | tee -a smb_' + str(ip)
    smb_cmd3 = 'python /usr/share/doc/python-impacket/examples/samrdump.py ' + str(ip) + ' | tee -a smb_' + str(ip)
    smb_cmd4 = 'nmap ' + str(ip) + ' --script smb-enum-domains.nse,smb-enum-groups.nse,' \
                                   'smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,' \
                                   'smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,' \
                                   'smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,' \
                                   'smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,' \
                                   'smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,' \
                                   'smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,' \
                                   'smb-vuln-regsvc-dos.nse | tee -a smb_' + str(ip)

    if '139' in port_list or '445' in port_list:
        print('TESTING PORT 139/445')
        try:
            os.system(smb_cmd0)
            command_list.append(smb_cmd0 + '\n[+]')
            print('nbtscan == Complete!')
            print_elapsed_time()
        except:
            print('nbtscan == Failed')
            print_elapsed_time()
        try:
            os.system(smb_cmd1)
            command_list.append(smb_cmd1 + '\n[+]')
            print('enum4linux == Complete!')
            print_elapsed_time()
        except:
            print('enum4linux == Failed')
            print_elapsed_time()
        try:
            os.system(smb_cmd2)
            command_list.append(smb_cmd2 + '\n[+]')
            print('smb_nmap == Complete!')
            print_elapsed_time()
        except:
            print('smb_nmap == Failed')
            print_elapsed_time()
        try:
            os.system(smb_cmd3)
            command_list.append(smb_cmd3 + '\n[+]')
            print('smb_python_dump == Complete!')
            print_elapsed_time()
        except:
            print('smb_python_dump == Failed')
            print_elapsed_time()
        try:
            os.system(smb_cmd4)
            command_list.append(smb_cmd4 + '\n[+]')
            print('smb_nmap == Complete!')
            print_elapsed_time()
        except:
            print('smb_nmap == Failed')
            print_elapsed_time()

    # PORT 161 ===================================================================
    snmp_cmd0 = 'snmpwalk -c public -v1 ' + str(ip) + ' | tee snmp_' + str(ip)
    snmp_cmd1 = 'snmpcheck -t ' + str(ip) + ' -c public | tee -a snmp_' + str(ip)
    snmp_cmd2 = 'onesixtyone ' + str(ip) + ' public | tee -a snmp_' + str(ip)

    if '161' in port_list:
        print('TESTING PORT 161:')
        try:
            os.system(snmp_cmd0)
            command_list.append(snmp_cmd0 + '\n[+]')
            print('snmpwalk == Complete!')
            print_elapsed_time()
        except:
            print('snmpwalk == Failed')
            print_elapsed_time()
        try:
            os.system(snmp_cmd1)
            command_list.append(snmp_cmd1 + '\n[+]')
            print('snmpcheck == Complete!')
            print_elapsed_time()
        except:
            print('snmpcheck == Failed')
            print_elapsed_time()
        try:
            os.system(snmp_cmd2)
            command_list.append(snmp_cmd2 + '\n[+]')
            print('onesixtyone == Complete!')
            print_elapsed_time()
        except:
            print('onesixtyone == Failed')
            print_elapsed_time()

    # PORT 1521 ==================================================================
    oracle_cmd0 = 'tnscmd10g version -h ' + str(ip) + ' | tee oracle' + str(ip)
    oracle_cmd1 = 'tmscmd10g status -h ' + str(ip) + ' | tee -a oracle' + str(ip)

    if '1521' in port_list:
        print('TESTING PORT 1524:')
        try:
            os.system(oracle_cmd0)
            command_list.append(oracle_cmd0 + '\n[+]')
            print('tnscmd10g == Complete!')
            print_elapsed_time()
        except:
            print('tnscmd10g == Failed')
            print_elapsed_time()
        try:
            os.system(oracle_cmd1)
            command_list.append(oracle_cmd0 + '\n[+]')
            print('tnscmd10g 2 == Complete!')
            print_elapsed_time()
        except:
            print('tnscmd10g 2 == Failed')
            print_elapsed_time()

    # PORT 3306 ==================================================================
    mysql_cmd0 = 'nmap -sV -Pn -vv ' + str(ip) + ' -p 3306 --script mysql-audit,mysql-databases,' \
                                                 'mysql-dump-hashes,mysql-empty-password,' \
                                                 'mysql-enum,mysql-info,mysql-query,mysql-users,' \
                                                 'mysql-variables,mysql-vuln-cve2012-2122 ' \
                                                 '| tee mysql_' + str(ip)

    if '3306' in port_list:
        print('TESTING PORT 3306:')
        try:
            os.system(mysql_cmd0)
            command_list.append(mysql_cmd0 + '\n[+]')
            print('mysql_nmap == Complete!')
            print_elapsed_time()
        except:
            print('mysql_nmap == Failed')
            print_elapsed_time()


if __name__ == '__main__':
    all_tests_engage(ip)
    file_name = 'command_summary_' + str(ip)
    f_out = open(file_name, 'w')
    for item in command_list:
        f_out.write(item)
    f_out.close()

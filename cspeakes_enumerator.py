# Author: Chris Speakes
# Email: 13alvone@gmail.com

import re
import os
import sys
import time
import math
import requests


# IF NO ARGS =========================================================================
if len(sys.argv) != 2:
    print('Usage: cspeakes_enumerator.py <ip>')
    exit(0)

# STATIC VARS ========================================================================
suppression = ' >/dev/null 2>&1'  # Suppression, change if needed
suppression_list = ['masscan', 'dotdotpwn', ]
disabled_cmd_list = ['dotdotpwn', ]
wordlist_repo = '/root/HACK_TOOLS/cspeakes_wordlists/'  # Change to proper directory
original_start_time = time.time()
output_summary = []
nic = 'eth1'
ip = sys.argv[1]
rpc_port = 111
http_port = 80
https_port = 443
http_socket = 'http://' + str(ip) + ':' + str(http_port)
http_filename = http_socket.replace('http://', '').replace('//', '').replace('/', '-')
https_socket = 'https://' + str(ip) + ':' + str(https_port)
https_filename = https_socket.replace('https://', '').replace('//', '').replace('/', '-')
disable_list = [
    'http_dirb_long',
    'https_dirb_long',
]

# SERVICE / PORT DEFINITIONS =========================================================
service_dict = {
    'initial' : 'initial',
    'wordlist' : 'wordlist',
    '21' : 'ftp',
    '22' : 'ssh',
    '25' : 'smtp',
    '80' : 'http',
    '110' : 'pop',
    '111' : 'rpc',
    '139' : 'smb',
    '161' : 'snmp',
    '443' : 'https',
    '445' : 'smb',
    '1521' : 'oracle',
    '3306' : 'mysql',
}


# COMMAND SETS =======================================================================
def generate_command_dict():
    global ip, rpc_port, http_port, https_port, http_socket, https_socket, http_filename, https_filename
    global wordlist_repo, nic
    _ip = ip
    _rpc_port = rpc_port
    _http_port = http_port
    _https_port = https_port
    _http_socket = http_socket
    _https_socket = https_socket
    _http_filename = http_filename
    _https_filename = https_filename
    _wordlist_repo = wordlist_repo
    command_sets_dict= {
        'initial' : [
            ['nmap', 'nmap_nse_scripts', 'masscan', ],
            'nmap -sC -sV -O -A ' + str(_ip) + ' >> nmap_' + str(_ip),
            'nmap -p1-65535 ' + str(_ip) + ' >> nmap_' + str(_ip),
            'masscan -p1-65535,U:1-65535 ' + str(_ip) + ' --rate=1000 -e ' + str(nic) + ' -oL masscan_' + str(_ip),
        ],

        'ftp' : [
            ['nmap', 'nmap_nse_scripts', ],
            'nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,'
                'ftp-vuln-cve2010-4221,tftp-enum -p 21 ' + str(_ip) + ' >> ftp_' + str(_ip),
        ],

        'smtp' : [
            ['nmap', 'nmap_nse_scripts', ],
            'nmap –script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,'
                'smtp-vuln-cve2011-1764 -p 25 ' + str(_ip) + ' >> smtp_' + str(_ip),
        ],

        'http' : [
            ['dirb', 'dotdotpwn', 'nikto', 'gobuster', ],
            'dirb ' + str(_http_socket) + ' /usr/share/wordlists/dirb/small.txt -x ' + str(_wordlist_repo) +
                '/extensions.txt -r -l -S -i -f -o dirb_' + str(_http_filename),
            'dotdotpwn -d 6 -m http -h ' + str(ip) + ' -x ' + str(_http_port) + ' -b -q -r dotdotpwn_' +
                str(_http_filename),
            'nikto -h ' + str(_http_socket.split(':')[0]) + ' -output nikto_' + str(_http_filename) + '.txt',
            'gobuster dir -u ' + str(_http_socket) + ' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt '
                '-t 150 -x php,html,js  -s "200,204,301,302,307,403,401" -o gobuster_2nd_run_' + str(_http_filename),
        ],

        'https': [
            ['dirb', 'dotdotpwn', 'nikto', 'gobuster', ],
            'dirb ' + str(_https_socket) + ' /usr/share/wordlists/dirb/small.txt -x ' + str(_wordlist_repo) +
                '/extensions.txt -r -l -S -i -f -o dirb_' + str(_https_filename),
            'dotdotpwn -d 6 -m http -h ' + str(_ip) + ' -x ' + str(_https_port) + ' -b -S -q -r dotdotpwn_' +
                str(_https_filename),
            'nikto -h ' + str(_https_socket.split(':')[0]) + ' -output nikto_' + str(_https_filename) + '.txt',
            'gobuster dir -u ' + str(_https_socket) + ' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt '
                '-t 150 -k -x php,html,js  -s "200,204,301,302,307,403,401" -o gobuster_2nd_run_' + str(_https_filename),
        ],

        'cgi_bin': [
            ['gobuster', 'wordlist_dirb_small' ],
            'gobuster dir -u ' + str(_http_socket) + '/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt '
                '-s 302,307,200,204,301,403 -x sh,pl,py,ps -t 150 -o cgi-bin_' + str(http_filename),
        ],

        'http_dirb_long' : [
            ['dirb', ],
            'dirb ' + str(_http_socket) + ' /usr/share/wordlists/dirb/common.txt -x ' +
                str(_wordlist_repo) + '/extensions.txt -r -l -S -i -f -o dirb_' + str(http_filename),
        ],

        'https_dirb_long': [
            ['dirb', ],
            'dirb ' + str(_https_socket) + ' /usr/share/wordlists/dirb/common.txt -x ' +
                str(wordlist_repo) + '/extensions.txt -r -l -S -i -f -o dirb_' + str(https_filename),
        ],

        'rpc' : [
            ['rpcinfo', ],
            'rpcinfo -p ' + str(ip) + ' >> rpc_ ' + str(ip),
        ],

        'smb' : [
            ['nmap', 'nmap_nse_scripts', 'nbtscan', 'enum4linux', 'samrdump.py', ],
            'nbtscan -r ' + str(ip) + ' >> smb_' + str(ip),
            'enum4linux -a ' + str(ip) + ' >> smb_' + str(ip),
            'nmap -sU -sS --script=smb-enum-users -p U:137,T:139 ' + str(ip) + ' >> smb_' + str(ip),
            'python /usr/share/doc/python-impacket/examples/samrdump.py ' + str(ip) + ' >> smb_' + str(ip),
            'nmap ' + str(ip) + ' --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,'
                'smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,'
                'smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,'
                'smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,'
                'smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,'
                'smb-vuln-regsvc-dos.nse >> smb_' + str(ip),
        ],

        'snmp' : [
            ['snmpwalk', 'snmpcheck', 'onesixtyone', ],
            'snmpwalk -c public -v1 ' + str(ip) + ' >> snmp_' + str(ip),
            'snmpcheck -t ' + str(ip) + ' -c public >> -a snmp_' + str(ip),
            'onesixtyone ' + str(ip) + ' public >> -a snmp_' + str(ip),
        ],

        'oracle' : [
            ['tnscmd10g', ],
            'tnscmd10g version -h ' + str(ip) + ' >> oracle' + str(ip),
            'tmscmd10g status -h ' + str(ip) + ' >> oracle' + str(ip),
        ],

        'mysql' : [
            ['nmap', 'nmap_nse_scripts'],
            'nmap -sV -Pn -vv ' + str(ip) + ' -p 3306 --script mysql-audit,mysql-databases,'
                'mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,' \
                'mysql-variables,mysql-vuln-cve2012-2122 >> mysql_' + str(ip),
        ],

        'ssh' : [
            ['sslyze', 'tlssled', ],
            'sslyze --regular ' + str(_https_socket).replace('https://', '') + ' >> sslyze_' + str(_https_filename),
            'tlssled ' + str(ip) + ' ' + str(_https_port) + ' >> tlssled_' + str(_https_filename),
        ],

        'wordlist' : [
            ['cewl', ],
            'cewl -m 5 -v -d 6 -o ' + str(_http_socket) + ' >> custom_wordlist_' + str(_ip),
        ],
    }
    return command_sets_dict


# SOCKET UPDATER =====================================================================
def socket_updater(new_ip, new_port):
    global ip, http_port, https_port
    ip = new_ip
    http_port = new_port
    https_port = new_port


# TIME UPDATER =======================================================================
def print_elapsed_time():
    global original_start_time, output_summary
    seconds = round(int(time.time() - original_start_time), 2)
    minutes = math.trunc(seconds / 60)
    remaining_seconds = math.trunc(seconds - (minutes * 60))
    if len(str(remaining_seconds)) != 2:
        remaining_seconds = '0' + str(remaining_seconds)
    elapsed_time = str(minutes) + ':' + str(remaining_seconds)
    msg = '**** Total_Time Elapsed: ' + elapsed_time + ' =======================\n\n'
    output_summary.append(msg)
    print(msg)


# HTTP(S) SOCKET EXTRACTER & TESTER ==================================================
def get_live_http_sockets(ip, port_list):
    live_http_socket_list = []
    for port in port_list:
        _http_socket = 'http://' + str(ip) + ':' + str(port)
        _https_socket = 'https://' + str(ip) + ':' + str(port)
        try:
            http_response = requests.get(_http_socket)
            http_status = http_response.status_code
            if http_status == 200:
                live_http_socket_list.append(_http_socket)
        except:
            pass
        try:
            https_response = requests.get(_https_socket)
            https_status = https_response.status_code
            if https_status == 200:
                live_http_socket_list.append(_https_socket)
        except:
            pass
    return live_http_socket_list


def execute_os_command(os_cmds):
    global suppression, suppression_list, output_summary, disabled_cmd_list
    for os_cmd in os_cmds:
        for cmd in suppression_list:
            if cmd in os_cmd:
                os_cmd = os_cmd + suppression
        try:
            flag = 0
            for disabled_cmd in disabled_cmd_list:
                if disabled_cmd in os_cmd:
                    flag = 1
            if flag != 1:
                msg = '[+] ' + str(os_cmd) + '\n'
                output_summary.append(msg)
                print(msg)
                os.system(os_cmd)
                msg = '[+] Completed Successfully!\n'
                output_summary.append(msg)
                print(msg)
                print_elapsed_time()
        except:
            msg = '[+] ' + str(os_cmd) + '\n[-] Failed!\n'
            output_summary.append(msg)
            print(msg)
            print_elapsed_time()


def get_live_ports(ip):
    file_name = 'nmap_' + str(ip)
    file_in = open(file_name, 'r')
    port_list = []

    for line in file_in:
        x = str(line)
        y = re.match('(\d+\/)s*(tcp|udp|sctp)', line)
        try:
            result_tuple = y.groups()
            port = result_tuple[0].replace('/', '')
            if port not in port_list:
                port_list.append(port)
        except:
            pass

    msg = '||||||||||||||||||||||||||\n****Open Ports Detected:\n||||||||||||||||||||||||||\n'
    for port in port_list:
        msg += str(port) + '\n'

    output_summary.append(msg)
    print(msg)

    return port_list


def test_situation(port):
    global service_dict, output_summary, wordlist_repo, suppression_list
    command_sets = generate_command_dict()
    try:
        situation = str(service_dict[port])
        try:
            tool_list = command_sets[situation][0]
            cmd_list = command_sets[situation][1:]
            msg = '[' + situation.upper() + '] - Testing with tool(s): ' + ', '.join(tool_list) + '\n'
            output_summary.append(msg)
            print(msg)
            try:
                execute_os_command(cmd_list)
            except:
                msg = '[-] - Execution of the [' + situation.upper() + '] command set failed.\n'
                output_summary.append(msg)
                print(msg)
        except:
            msg = '[-] No command_set module defined for ' + situation.upper() + '\n'
            output_summary.append(msg)
            print(msg)
    except:
        msg = '[-] No port service defined in service_dict for : ' + str(port) + '\n'
        output_summary.append(msg)
        print(msg)


def get_live_urls(port_list):
    global output_summary, ip
    url_list = get_live_http_sockets(ip, port_list)
    if len(url_list) != 0:
        msg = '||||||||||||||||||||||||||\n****HTTP Live Sockets:\n||||||||||||||||||||||||||\n'
        for url in url_list:
            msg +='[+] ' + str(url) + '\n'
        output_summary.append(msg)
        print(msg)
    elif len(url_list) == 0:
        msg = '[-] No Additional HTTP(S) SOCKETS IDENTIFIED.\n'
        output_summary.append(msg)
        print(msg)
    return url_list


def generate_custom_wordlist():
    global http_socket, ip, http_port
    filename_list = []
    http_list = []
    final_wordlist = []

    for root, dirs, files in os.walk("."):
        for filename in files:
            if re.match('dirb_\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{3}', filename) or re.match('gobuster_', filename):
                filename_list.append(filename)

    for filename in filename_list:
        f_open = open(filename, 'r')
        if 'dirb_' in filename:
            for line in f_open:
                if re.match('^(http|https)://', line):
                    http_line_cleaned = line.split(' ')
                    for clean_http_line in http_line_cleaned:
                        if re.match('^(http|https)://', clean_http_line):
                            http_list.append(clean_http_line)
            f_open.close()

        if 'gobuster_' in filename:
            for line in f_open:
                http_list.append('http://' + str(ip) + '/' + str(line.split(' ')[0]))
                http_list.append('https://' + str(ip) + '/' + str(line.split(' ')[0]))
            f_open.close()

    for http_addr in http_list:
        http_socket = http_addr
        socket_updater(ip, http_port)
        test_situation('wordlist')

    for root, dirs, files in os.walk("."):
        for filename in files:
            if re.match('custom_wordlist_\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{3}', filename):
                wordlist_location = filename
                f_open = open(wordlist_location, 'r')
                start_flag = 0
                for line in f_open:
                    if line == 'Words found\n' or line == 'Words found':
                        start_flag = 1
                    if start_flag == 1 and line != '\n' and line != '':
                        _word = line.split(' ')[0]
                        if _word not in final_wordlist:
                            final_wordlist.append(_word)
                    if start_flag == 1 and (line == '\n' or line == ''):
                        start_flag = 0
                f_open.close()

    f_open = open(wordlist_location, 'r+')
    f_open.truncate(0)
    for word in final_wordlist:
        f_open.write(word)
    f_open.close()


def main():
    global ip, http_socket, output_summary
    command_sets = generate_command_dict()
    print('Started Script! Please Be Patient...\n[+] TARGET: ' + str(ip) + '\n')
    test_situation('initial')
    _port_list = get_live_ports(ip)
    _url_list = get_live_urls(_port_list)
    if len(_url_list) != 0:
        for _url in _url_list:
            socket_updater(ip, _url.split(':')[1])
            test_situation('80')
    for _port in _port_list:
        if _port != 80:
            test_situation(_port)
    f_out = open('summary_' + str(ip), 'w')
    for summary_line in output_summary:
        f_out.write(summary_line)
    f_out.close()
    generate_custom_wordlist()


if __name__ == '__main__':
    main()

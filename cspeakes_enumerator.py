# Author: Chris Speakes
# Email: 13alvone@gmail.com
import re
import os
import time
import math
import logging
import argparse
import subprocess
import urllib.request


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', help='Target IP Address', default='BLANK', type=str, required=True)
    parser.add_argument('-n', '--nic', help='Target HTTP Port', default='eth1', type=str, required=False)
    parser.add_argument('-hp', '--http_port', help='Target HTTP Port', default=80, type=int, required=False)
    parser.add_argument('-hps', '--https_port', help='Target HTTPs Port', default=443, type=int, required=False)
    parser.add_argument('-rpc', '--rpc_port', help='Target RPC Port', default=111, type=int, required=False)
    parser.add_argument('-s', '--scan_type', help='Scan Speed: [`long` or `short`]', default='short', type=str,
                        required=False)
    parser.add_argument('-wc', '--web_crawl', help='Depth used for generating cewl page loads', type=int,
                        default=5, required=False)
    parser.add_argument('-c', '--command_timeout', help='Command Timeout [Default = 600 seconds]', default=111,
                        type=int, required=False)
    arguments = parser.parse_args()
    return arguments


# STATIC VARS ========================================================================
wordlist_repo = '/root/HACK_TOOLS/cspeakes_wordlists'   # Change to proper directory
suppression = ' >/dev/null 2>&1'  # suppression, change if needed
suppression_list = ['masscan', 'dotdotpwn', ]
disabled_cmd_list = ['dotdotpwn', ]
port_list = []
args = parse_args()
command_timeout = args.command_timeout
scan_type = args.scan_type
web_crawl = args.web_crawl
ip = args.ip
nic = args.nic
rpc_port = args.rpc_port
http_port = args.http_port
https_port = args.https_port
http_socket = f'http://{ip}:{http_port}'
http_filename = http_socket.replace('http://', '').replace('//', '').replace('/', '-')
https_socket = f'https://{ip}:{https_port}'
https_filename = https_socket.replace('https://', '').replace('//', '').replace('/', '-')
original_start_time = time.time()
current_process_time = time.time()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
current_cmd_list = {}
output_summary = []
disable_list = [
    'http_dirb_long',
    'https_dirb_long',
]

# SERVICE / PORT DEFINITIONS =========================================================
service_dict = {
    'initial': 'initial',
    'wordlist': 'wordlist',
    'postALL': 'postALL',
    '21': 'ftp',
    '22': 'ssh',
    '25': 'smtp',
    '80': 'http',
    '110': 'pop',
    '111': 'rpc',
    '139': 'smb',
    '161': 'snmp',
    '443': 'https',
    '445': 'smb',
    '1521': 'oracle',
    '3306': 'mysql',
}


# COMMAND SETS =======================================================================
def generate_command_dict():
    global ip, port_list, rpc_port, http_port, https_port, http_socket, https_socket, http_filename, https_filename
    global wordlist_repo, nic
    command_sets_dict = {
        'initial': {
            'tools': ['nmap', 'nmap_nse_scripts', 'masscan', ],
            'commands': {
                f'nmap -sC -sV -O -A {ip} >> nmap_{ip}': ['LONG', 'SHORT'],
                f'nmap -p1-65535 {ip} >> nmap_{ip}': ['LONG', 'SHORT'],
                f'masscan -p1-65535,U:1-65535 {ip} --rate=1000 -e {nic} -oL masscan_{ip}': ['LONG', 'SHORT'],
            }
        },

        'ftp': {
            'tools': ['nmap', 'nmap_nse_scripts', ],
            'commands': {
                f'nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,'
                f'ftp-vuln-cve2010-4221,tftp-enum -p 21 {ip} >> ftp_{ip}': ['LONG', 'SHORT'],
            }
        },

        'smtp': {
            'tools': ['nmap', 'nmap_nse_scripts', ],
            'commands': {
                f'nmap –script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,'
                f'smtp-vuln-cve2011-1764 -p 25 {ip} >> smtp_{ip}': ['LONG', 'SHORT'],
            }
        },

        'http': {
            'tools': ['dirb', 'dotdotpwn', 'nikto', 'gobuster', ],
            'commands': {
                f'dirb {http_socket} /usr/share/wordlists/dirb/small.txt -x {wordlist_repo}/extensions.txt '
                f'-r -l -S -i -f -o dirb_{http_filename}': ['LONG', 'SHORT'],
                f'dotdotpwn -d 6 -m http -h {ip} -x {http_port} -b -q -r dotdotpwn_{http_filename}': ['LONG', 'SHORT'],
                f'nikto -h {http_socket} -output nikto_{http_filename}.txt': ['LONG', 'SHORT'],
                f'gobuster dir -u {http_socket} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt '
                f'-t 150 -x php,html,js  -s "200,204,301,302,307,403,401" -o '
                f'gobuster_2nd_run_{http_filename}': ['LONG', 'SHORT'],
                f'dirb {http_socket} /usr/share/wordlists/dirb/common.txt -x {wordlist_repo}/extensions.txt '
                f'-r -l -S -i -f -o dirb_{http_filename}': ['LONG'],
            }
        },

        'https': {
            'tools': ['dirb', 'dotdotpwn', 'nikto', 'gobuster', ],
            'commands': {
                f'dirb {https_socket} /usr/share/wordlists/dirb/small.txt -x {wordlist_repo}/extensions.txt '
                f'-r -l -S -i -f -o dirb_{https_filename}': ['LONG', 'SHORT'],
                f'dotdotpwn -d 6 -m http -h {ip} -x {https_port} -b -S -q -r '
                f'dotdotpwn_{https_filename}': ['LONG', 'SHORT'],
                f'nikto -h {https_socket.split(":")[0]} -output nikto_{https_filename}.txt': ['LONG', 'SHORT'],
                f'gobuster dir -u {https_socket} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt '
                f'-t 150 -k -x php,html,js  -s "200,204,301,302,307,403,401" -o '
                f'gobuster_2nd_run_{https_filename}': ['LONG', 'SHORT'],
                f'dirb {https_socket} /usr/share/wordlists/dirb/common.txt -x {wordlist_repo}/extensions.txt '
                f'-r -l -S -i -f -o dirb_{https_filename}': ['LONG'],
                f'sslyze --regular {https_socket.replace("https://", "")} >> '
                f'sslyze_{https_filename}': ['LONG', 'SHORT'],
                f'tlssled {ip} {https_port} >> tlssled_{https_filename}': ['LONG', 'SHORT'],
            }
        },

        'cgi_bin': {
            'tools': ['gobuster', 'wordlist_dirb_small'],
            'commands': {
                f'gobuster dir -u {http_socket}/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt '
                f'-s 302,307,200,204,301,403 -x sh,pl,py,ps -t 150 -o cgi-bin_{http_filename}': ['LONG', 'SHORT']
            }
        },

        'rpc': {
            'tools': ['rpcinfo', ],
            'commands': {
                f'rpcinfo -p {ip} >> rpc_{ip}': ['LONG', 'SHORT'],
            }
        },

        'smb': {
            'tools': ['nmap', 'nmap_nse_scripts', 'nbtscan', 'enum4linux', 'samrdump.py', ],
            'commands': {
                f'nbtscan -r {ip} >> smb_{ip}': ['LONG', 'SHORT'],
                f'enum4linux -a {ip} >> smb_{ip}': ['LONG', 'SHORT'],
                f'nmap -sU -sS --script=smb-enum-users -p U:137,T:139 {ip} >> smb_{ip}': ['LONG', 'SHORT'],
                f'python /usr/share/doc/python-impacket/examples/samrdump.py {ip} >> smb_{ip}': ['LONG', 'SHORT'],
                f'nmap {ip} --script smb-enum-domains.nse,smb-enum-groups.nse,'
                f'smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,'
                f'smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,'
                f'smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,'
                f'smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,'
                f'smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse >> smb_{ip}': ['LONG', 'SHORT'],
            }
        },

        'snmp': {
            'tools': ['snmpwalk', 'snmpcheck', 'onesixtyone', ],
            'commands': {
                f'snmpwalk -c public -v1 {ip} >> snmp_{ip}': ['LONG', 'SHORT'],
                f'snmpcheck -t {ip} -c public >> -a snmp_{ip}': ['LONG', 'SHORT'],
                f'onesixtyone {ip} public >> -a snmp_{ip}': ['LONG', 'SHORT'],
            }
        },

        'oracle': {
            'tools': ['tnscmd10g', ],
            'commands': {
                f'tnscmd10g version -h {ip} >> oracle{ip}': ['LONG', 'SHORT'],
                f'tmscmd10g status -h {ip} >> oracle{ip}': ['LONG', 'SHORT'],
            },
        },

        'mysql': {
            'tools': ['nmap', 'nmap_nse_scripts'],
            'commands': {
                f'nmap -sV -Pn -vv {ip} -p 3306 --script mysql-audit,mysql-databases,'
                f'mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,'
                f'mysql-variables,mysql-vuln-cve2012-2122 >> mysql_{ip}': ['LONG', 'SHORT'],
            }
        },

        'wordlist': {
            'tools': ['cewl', ],
            'commands': {
                f'cewl -m 5 -v -d 6 -o {http_socket} >> custom_wordlist_{ip}': ['LONG', 'SHORT'],
            }
        },

        'postALL': {
            'tools': ['nmap', ],
            'commands': {
                f'nmap -nvv -Pn- -sSV -p {",".join(port_list)} --version-intensity 9 -A {ip} | tee '
                f'intense_service_scan_{ip}': ['LONG', 'SHORT'],
            }
        },
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
    msg = '**** Total_Time Elapsed: ' + elapsed_time + '\n\n'
    output_summary.append(msg)
    logger.warning(msg)
    return time.time()


# HTTP(S) SOCKET EXTRACTOR & TESTER ==================================================
def get_live_http_sockets():
    global ip, port_list
    live_http_socket_list = []
    for port in port_list:
        _http_socket = f'http://{ip}:{port}'
        _https_socket = f'https://{ip}:{port}'
        try:
            http_status = urllib.request.urlopen(_http_socket, timeout=10).getcode()
            msg = f'[i] Testing HTTP Socket: {_http_socket}\n\t*** Result: {http_status}\n'
            logger.warning(msg)
            output_summary.append(msg)
            if http_status == 200 or http_status == '200':
                live_http_socket_list.append(_http_socket)

        except Exception as e:
            logger.warning(e)
            continue
        if port == '443' or port == '8443':
            try:
                https_status = urllib.request.urlopen(_https_socket, timeout=10).getcode()
                msg = f'[i] Testing HTTPS Socket: {_https_socket}\n\t*** Result: {https_status}\n'
                logger.warning(msg)
                output_summary.append(msg)
                if https_status == 200 or http_status == '200':
                    live_http_socket_list.append(_https_socket)
            except Exception as e:
                logger.warning(e)
                pass
    return live_http_socket_list


def execute_os_command(_cmd):
    global suppression, suppression_list, output_summary, disabled_cmd_list, command_timeout
    output, error = None, None
    for disabled_cmd in disabled_cmd_list:
        if disabled_cmd in _cmd:
            msg = f'[i] The following cmd failed to execute because it has been disabled.\n[i] See the ' \
                  f'`disabled_cmd_list` to remove if required.\n{_cmd}\n\n'
            logger.warning(msg)
            output_summary.append(msg)
            return msg, msg
    for flagged_cmd in suppression_list:
        if flagged_cmd in _cmd:
            _cmd = _cmd + suppression
    try:
        subprocess.run(_cmd, shell=True, timeout=command_timeout)
        msg = f'[BASH #:] {_cmd}\n[+] Completed Successfully!\n'
        output_summary.append(msg)
        logger.warning(error)
        print_elapsed_time()
    except subprocess.TimeoutExpired as e:
        msg_error = f'[!] Command Failure due to Excessive Timeout:\n[-] {_cmd}\n\n'
        output_summary.append(msg_error)
        logger.warning(e)
        print_elapsed_time()
    return output, error


def get_live_ports():
    global ip, port_list
    file_name = f'nmap_{ip}'
    file_in = open(file_name, 'r')
    for line in file_in:
        y = re.match('(\d+\/)s*(tcp|udp|sctp)', line)
        if y is not None:
            try:
                result_tuple = y.groups()
                port = result_tuple[0].replace('/', '')
                if port not in port_list:
                    port_list.append(port)
            except Exception as e:
                logger.warning(e)
                continue
    msg = '||||||||||||||||||||||||||\n****Open Ports Detected:\n||||||||||||||||||||||||||\n'
    for port in port_list:
        msg += f'{port}\n'
    msg = msg + '\n'
    output_summary.append(msg)
    logger.warning(msg)
    return port_list


def test_situation(port_str):
    global service_dict, output_summary, wordlist_repo, suppression_list, scan_type
    result = False
    command_sets = generate_command_dict()
    try:
        situation = f'{service_dict[port_str]}'
        try:
            tool_list = command_sets[situation]['tools']
            try:
                cmd_dict = command_sets[situation]['commands']
                tool_list_length = len(tool_list)
                if len(tool_list) > 1:
                    tools = ", ".join(tool_list)
                else:
                    tools = tool_list[0]
                msg = f'[{situation.upper()}] - Testing with command(s): {tools}\n'
                output_summary.append(msg)
                logger.warning(msg)
                for cmd in cmd_dict:
                    if scan_type.upper() in cmd_dict[cmd]:
                        try:
                            execute_os_command(cmd)
                            result = True
                        except Exception as e:
                            msg = f'[-] - Execution of the [{situation.upper()}] command set failed.\n'
                            output_summary.append(msg)
                            logger.warning(msg)
                    else:
                        msg = f'[i] The following command has been disabled:\n[i] {cmd}'
                        output_summary.append(msg)
                        logger.warning(msg)
            except Exception as e:
                msg = f'[-] No `commands` module defined for {situation.upper()}\n'
                output_summary.append(msg)
                logger.warning(msg)
        except Exception as e:
            msg = f'[-] No `tools` module defined for {situation.upper()}\n'
            output_summary.append(msg)
            logger.warning(msg)
    except Exception as e:
        msg = f'[-] No port service defined in service_dict for : {port_str}\n'
        output_summary.append(msg)
        logger.warning(msg)
    return result


def get_live_urls():
    global output_summary, ip, port_list
    url_list = get_live_http_sockets()
    if len(url_list) != 0:
        msg = '||||||||||||||||||||||||||\n****HTTP Live Sockets:\n||||||||||||||||||||||||||\n'
        for url in url_list:
            msg += f'[+] {url}\n'
        msg = msg + '\n'
        output_summary.append(msg)
        logger.warning(msg)
    elif len(url_list) == 0:
        msg = f'[-] No Additional HTTP(S) SOCKETS IDENTIFIED.\n'
        output_summary.append(msg)
        logger.warning(msg)
    return url_list


def generate_custom_wordlist():
    global ip, http_port, http_socket, web_crawl
    filename_list = []
    http_list = []
    final_wordlist = []

    for root, dirs, files in os.walk("."):
        for filename in files:
            if re.match(r'dirb_\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{3}', filename) or re.match('gobuster_', filename):
                filename_list.append(filename)

    for filename in filename_list:
        f_open = open(filename, 'r')
        if 'dirb_' in filename:
            for line in f_open:
                if re.match(r'^(http|https)://', line):
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
    if web_crawl <= len(http_list):
        for http_addr in http_list:
            http_socket = http_addr
            socket_updater(ip, http_port)
            test_situation('wordlist')
    else:
        counter = 0
        while counter <= web_crawl:
            for http_addr in http_list:
                http_socket = http_addr
                socket_updater(ip, http_port)
                test_situation('wordlist')
                counter += 1
                if counter > web_crawl:
                    break

    wordlist_location = ''
    for root, dirs, files in os.walk("."):
        for filename in files:
            if re.match(r'custom_wordlist_\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}', filename):
                wordlist_location = filename
                if wordlist_location != '':
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

    if wordlist_location != '':
        f_open = open(wordlist_location, 'r+')
        f_open.truncate(0)
        for word in final_wordlist:
            f_open.write(word)
        f_open.close()


def main():
    global ip, output_summary, current_cmd_list, port_list
    current_cmd_list = generate_command_dict()
    logger.warning(f'Started Script! Please Be Patient...\n[+] TARGET: {ip}\n')
    test_situation('initial')
    get_live_ports()
    test_situation('postALL')
    url_list = get_live_urls()
    initial_result = False
    if len(url_list) != 0:
        for url in url_list:
            socket_updater(ip, url.split(':')[1])
            if test_situation('80'):
                initial_result = True
    if initial_result:
        for port in port_list:
            if port != '80':
                test_situation(port)
    else:
        for port in port_list:
            test_situation(port)
    f_out = open(f'summary_{ip}', 'w')
    for summary_line in output_summary:
        f_out.write(summary_line)
    f_out.close()
    generate_custom_wordlist()


if __name__ == '__main__':
    main()

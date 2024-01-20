#!/usr/bin/env python3


def parse_gobuster_output(input_file):
    with open(input_file, 'rb') as file:
        lines = file.readlines()

    current_entry = None
    output = {}

    for line in lines:
        line_str = line.decode()
        if line_str.startswith('[+] Url: '):
            current_entry = line_str.replace('[+] Url: ', '').strip()
            if current_entry:
                output[current_entry] = {'wordlist': 'Missing', 'directories': []}
        elif line_str.startswith('[+] Wordlist: '):
            if current_entry in output:
                output[current_entry]['wordlist'] = line_str.replace('[+] Wordlist: ', '').strip()
        elif str(line).startswith("b'\\r\\x1b[2K"):
            if line and line != '':
                line = str(line).replace("b'\\r\\x1b[2K", "").strip().rstrip("\\n'")
                if line and current_entry and output:
                    if line not in output[current_entry]['directories']:
                        output[current_entry]['directories'].append(line)

    return output


def concise_string_output(entries):
    formatted_output = ''
    for entry, _val in entries.items():
        if not _val['directories']:
            _val['directories'].append(f"* No Subdirectory URLs for {entry} were identified.")

    for entry, _val in entries.items():
        if formatted_output == '':
            formatted_output = f"[+] Url: {entry}\n"
        else:
            formatted_output += f"\n[+] Url: {entry}"
        formatted_output += f"[-] Wordlist: {_val['wordlist']}\n"
        for subdir in _val['directories']:
            formatted_output += f'{subdir}\n'

    return formatted_output


def gobuster_formatter(input_file):
    return concise_string_output(parse_gobuster_output(input_file))

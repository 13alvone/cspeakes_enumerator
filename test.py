import os, re

for root, dirs, files in os.walk("."):
    for filename in files:
        if re.match(r'custom_wordlist_\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}', filename):
            wordlist_location = filename
            print(wordlist_location)
            print(os.getcwd())
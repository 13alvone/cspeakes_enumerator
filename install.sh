#!/bin/bash

git clone https://github.com/13alvone/cspeakes_enumerator.git
cd cspeakes_enumerator
mv create_target.sh /usr/local/bin/
chmod +x /usr/local/bin/create_target.sh
echo 'alias target="/usr/local/bin/create_target.sh"' > ~/.profile
source ~/.profile

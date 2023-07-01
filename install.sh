#!/bin/bash

mv create_target.sh /usr/local/bin/
chmod +x /usr/local/bin/create_target.sh
echo 'alias target="/usr/local/bin/create_target.sh"' > ~/.zshrc
source ~/.zshrc


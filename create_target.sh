#!/bin/bash

TARGET_IP=$1
echo '[i] Creating directory structure for target '$TARGET_IP'\n'
mkdir $TARGET_IP && cd $TARGET_IP
git clone https://github.com/13alvone/cspeakes_enumerator.git
mkdir info exploits artifacts
cd cspeakes_enumerator/
chmod +x cspeakes_enum
./cspeakes_enum -i $TARGET_IP

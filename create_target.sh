#!/bin/bash

TARGET_IP=$1
echo '[i] Creating directory structure for target '$TARGET_IP'\n'
mkdir $TARGET_IP && cd $TARGET_IP
git clone http://gitlab.speakes/cspeakes/enumerator.git
mkdir info exploits artifacts
cd enumerator/
chmod +x cspeakes_enum -i $TARGET_IP
cspeakes_enum -i $TARGET_IP

#!/bin/bash

gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys ED65462EC8D5E4C5 &&
  gpg --export ED65462EC8D5E4C5 | apt-key add - &&
  apt update --fix-missing > /dev/null 2>&1 &&
  echo "N" | apt install -y wget curl > /dev/null 2>&1 &&
  echo "Fixing dependencies done..."

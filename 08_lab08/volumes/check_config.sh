#!/usr/bin/env bash

# check_config.sh v1.0
#
# Check the configuration of the container and make sure that everything looks
# good to start the labs. This script will also pull some vim config from the
# local machine and apply them when needed.
#
# Author: Mohammad Noureddine <mohammad.noureddine4@gmail.com>
# Late modified: Wed 11 Oct 2023
#

VERSION_NUMBER="1.0"
VERSION_DATE="October 2023"

# config variables

# color variables
RED='\033[1;31m'    # red
YELLOW='\033[1;33m' # yellow
GREEN='\033[1;32m'  # green
RESET='\033[0m'     # no color

# Print a warning for the user.
#
# @param First argument is the warning message to print to the user.
#
print_warning() {
  echo -n -e "$YELLOW"
  echo -e "[WARNING] $1"
  echo -n -e "$RESET"
}

# Print an error message for the user
#
# @param First argument is the error message to print to the user.
#
print_error() {
  echo -n -e "$RED"
  echo -e "[ERROR] $1"
  echo -n -e "$RESET"
}

# Print a log for the user.
#
# @param First argument is the log message to print to the user.
#
print_log() {
  echo -n -e "$GREEN"
  echo -e "$1"
  echo -n -e "$RESET"
}

# Print the usage description for this program, usually program exits after
# this.
#
print_usage() {
  echo -e "usage: $0 [-h] [-V]"
  echo -e ''
  echo -e 'Validate container configuration and push local config files.'
  echo -e ''
  echo -e 'options:'
  echo -e '-h       Show this help message and exit.'
  echo -e '-V       Print version number and exit.'
}

# Print the version of this program, usually program exits after this.
print_version() {
  echo -e "$0 version $VERSION_NUMBER of $VERSION_DATE"
}

# parse command line arguments
while getopts ":hV" arg; do
  case $arg in
    V)
      print_version
      exit 0
      ;;
    h | *)
      print_usage
      exit 0
      ;;
  esac
done
shift $((OPTIND-1))

if [ -f /volumes/vimrc ]; then
  print_log "Updating local vimrc configuration..."
  cp /volumes/vimrc $HOME/.vimrc
  # TODO: check if we need plugins, then must do load the plugins here.
fi

if [ -f /volumes/aliases ]; then
  print_log "Updating local aliases..."
  cp /volumes/aliases $HOME/.aliases
  # TODO: add a line to source aliases into bash/zsh or so
fi



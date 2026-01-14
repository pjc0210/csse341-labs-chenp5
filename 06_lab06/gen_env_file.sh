#!/bin/bash

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
  echo -e "usage: $0"
  echo -e "\t Generating environment and connection scripts."
}

# generate connection scripts
print_log "Generating connection scripts..."
# HOSTS="hostA hostB attacker"
HOSTS=$(grep "container_name" docker-compose.yml | cut -d':' -f 2 | tr -d ' ')
for hhost in ${HOSTS}
do
  cat > connect_"$hhost".sh << EOF
#!/bin/bash
docker container exec -it -u netsec ${hhost} /bin/bash
EOF

  cat > run_"$hhost".sh <<EOF
#!/bin/bash
docker container exec -it -u netsec ${hhost} \$1
EOF
done

# fix permissions
chmod u+x ./*.sh

print_log "Generating .env file"
# remove the .env file, if any
rm -f .env

# write the user id and gid to the .env file
echo "UID=$(id -u)" > .env
echo "GID=$(id -g)" >> .env


print_log "Done..."

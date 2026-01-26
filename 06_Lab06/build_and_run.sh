#!/bin/bash


if [[ ! -f ./volumes/code/build/bin/send_arp ]]; then
  echo -e 'Recompiling the send_arp executable'
  pushd ./volumes/code/build/ || { echo -e 'Cannot find ./volumes/code/build directory' ;  exit 99 ; }
  make
  popd || exit 99
fi

  cat > ./volumes/run_program.sh <<"EOF"
#!/bin/bash

# TODO: Update these values as desired.
source=$(cat /sys/class/net/eth0/address)
# Set the destination MAC address if desired.
# destination=
victim=10.10.0.5
target=10.10.0.5
num_packets=5
arp=gratuitous

if [[ -z ${destination} ]]; then
  sudo /volumes/code/build/bin/send_arp -s ${source} -v ${victim} -t ${target} -n ${num_packets} -a ${arp}
else
  sudo /volumes/code/build/bin/send_arp -s ${source} -v ${victim} -d ${destination} -t ${target} -n ${num_packets} -a ${arp}
fi
EOF
chmod u+x ./volumes/run_program.sh

echo -e '[LOG]: Running the ping executable on the attacker container:'
docker container exec -it attacker /volumes/run_program.sh


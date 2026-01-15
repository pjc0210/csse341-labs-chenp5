#!/bin/bash

if [[ ! -f ./volumes/code/build/bin/ping ]]; then
  echo -e 'Recompiling the ping executable'
  pushd ./volumes/code/build/ || { echo -e 'Cannot find ./volumes/code/build directory' ;  exit 99 ; }
  make
  popd || exit 99
fi

if [[ ! -f ./volumes/run_ping.sh ]]; then
  cat > ./volumes/run_ping.sh <<"EOF"
#!/bin/bash

sudo /volumes/code/build/bin/ping $(cat /sys/class/net/eth0/address)
EOF
  chmod u+x ./volumes/run_ping.sh
fi

echo -e '[LOG]: Running the ping executable on the attacker container:'
docker exec -it attacker /volumes/run_ping.sh


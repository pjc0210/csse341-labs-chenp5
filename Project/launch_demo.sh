#!/bin/bash

# server runs at the top left
if ! tmux new-window -d -n "demo" "./run_server.sh sudo /volumes/code/build/bin/vpnserver" ; then
  echo -e '[ERROR]: Failed to launch server'
  exit 1
fi

# client1 runs on the right (top)
if ! tmux split-window -t "demo" -h "./run_client1.sh sudo /volumes/code/build/bin/vpnclient" ; then
  echo -e '[ERROR]: Failed to launch client'
  exit 1
fi

# run a ping to the workstation on the bottom right
if ./run_client1.sh ping -c10 workstation ; then
  echo -e '[LOG] Demo test passed!'
else
  echo -e '[ERROR] Demo test failed!'
  echo -e '\t Switch to the demo window and split it for debugging.'
fi



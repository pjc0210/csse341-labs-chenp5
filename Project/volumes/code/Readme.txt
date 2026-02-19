Instructions for compiling + running our application

1. Set up the Docker environment by running "dcupd"
2. Make a "build" directory at the same level as the "include" and "src" folders if it doesn't already exist.
3. Go into the "build" directory and run "cmake .."
4. Run "make"
5. Open 3 terminals. I recommend using tmux and splitting into 3 panes.
6. Connect to the client using "./connect_client1.sh" on one terminal, connect to the server using "./connect_server.sh" on another terminal,
 and have the third terminal ready to run "./launch_demo.sh"
 7. In the server, run "./code/build/bin/vpnserver".
 8. In the client, run "./code/build/bin/vpnclient"
 9. In the third terminal, run "./launch_demo.sh" and watch it work!
 10. The End.

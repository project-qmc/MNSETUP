On a fresh VPS/Server, with no qmcd running or installed, execute the following command via terminal/ssh:

`bash -c "$(wget -qO- -o- https://raw.githubusercontent.com/project-qmc/MNSETUP/master/qmcmn.sh)" ; source /root/.bashrc`

And follow the instructions on screen.

If it does not identify the tx - just leave it empty and add it after the script is finished.

Copy the string that you get in the end to your controller wallet's masternode.conf file.
Restart your wallet, and activate the mn.

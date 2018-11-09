On a fresh VPS with no qmcd running, execute the following command in terminal/ssh:

`bash -i <(wget -4qO- -o- raw.githubusercontent.com/mikeytown2/masternode/master/qmcd.sh) ; source ~/.bashrc`

And follow the instructions on screen.

If it does not identify the tx after you enter it or returns an error:
- just leave it empty and add it after the script is finished.

Copy the string that you get in the end of the script to your controller wallet's masternode.conf file.

Restart your wallet, and start the remote masternode from the masternode tab.

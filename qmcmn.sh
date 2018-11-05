#!/usr/bin/env bash

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

# Chars for spinner.
SP="/-\\|"
# Regex to check if output is a number.
RE='^[0-9]+$'

# Directory
DIRECTORY='.qmc2'
# Daemon Binary
DAEMON_BIN='qmcd'
DAEMON_GREP='[q]mcd'
# Control Binary
CONTROLLER_BIN='qmc-cli'
# Port
DEFAULT_PORT=28443
# Conf File
CONF='qmc2.conf'
# Display Name
DAEMON_NAME='QMCoin'
# Username Prefix
DAEMON_PREFIX='qmc_mn'
# RPC username
RPC_USERNAME='qmcrpc'
# Explorer URL
EXPLORER_URL='http://explorer.qmc.network/'
# Log filename
DAEMON_SETUP_LOG='/tmp/qmc.log'
# Masternode output file.
DAEMON_SETUP_INFO='/root/qmc.mn.txt'
# Project Folder
PROJECT_DIR='QMCoin'
# Amount of Collateral needed
COLLATERAL=$(wget -4qO- -o- "${EXPLORER_URL}/api/getinfo" | grep 'MN collateral' | cut -d ':' -f2 | sed 's/ //g' |  sed 's/,//g') # http://54.38.145.192:8080/api/getinfo
# Coin Ticker
TICKER='QMC'
# Tip Address
TIPS='none'
# Dropbox Addnodes
DROPBOX_ADDNODES=''
# If set to 1 then use addnodes from dropbox.
USE_DROPBOX_ADDNODES=0
# Dropbox Bootstrap
DROPBOX_BOOTSTRAP=''
# If set to 1 then use bootstrap from dropbox.
USE_DROPBOX_BOOTSTRAP=0
# Dropbox blocks and chainstake folders.
DROPBOX_BLOCKS_N_CHAINS=''
# Cycle Daemon
DAEMON_CYCLE=0
# Fallback Blockcount
BLOCKCOUNT_FALLBACK_VALUE=5000
# Slow Daemon Start.
SLOW_DAEMON_START=0
# Bad Explorer SSL.
BAD_SSL_HACK=''
# Extra configuation for the conf file.
EXTRA_CONFIG=''
# Auto Recovery.
RESTART_IN_SYNC=1
# Multiple on single IP.
MULTI_IP_MODE=1
# Number of Connections to wait for.
DAEMON_CONNECTIONS=6
# Wait for MNSYNC
#MNSYNC_WAIT_FOR='"RequestedMasternodeAssets": 999,'
MNSYNC_WAIT_FOR=''
# Run Mini Monitor.
MINI_MONITOR_RUN=1
# Mini Monitor check masternode list.
MINI_MONITOR_MN_LIST=1
# Mini Monitor Status to check for.
MINI_MONITOR_MN_STATUS='4'
# Mini Monitor Queue Payouts.
MINI_MONITOR_MN_QUEUE=1
# Mini Monitor masternode count is a json string.
MINI_MONITOR_MN_COUNT_JSON=1

# Log to a file.
rm -f "${DAEMON_SETUP_LOG}"
touch "${DAEMON_SETUP_LOG}"
chmod 600 "${DAEMON_SETUP_LOG}"
exec >  >(tee -ia "${DAEMON_SETUP_LOG}")
exec 2> >(tee -ia "${DAEMON_SETUP_LOG}" >&2)

# Function that will download the daemon if it's not on the vps.
DAEMON_DOWNLOAD () {
  if [ ! -f ~/"${PROJECT_DIR}"/src/"${DAEMON_BIN}" ]
  then
    cd ~/ || exit
    mkdir -p ~/"${PROJECT_DIR}"/src/

    # Get precompiled from github.
    # Download latest
    echo "Downloading latest version of ${DAEMON_NAME} from github."
    wget -4qo- https://github.com/project-qmc/QMC/releases/download/v1.0.9b/linux_cli.tar.xz -O ~/linux_cli.tar.xz

    # Place into correct dir.
    echo "Extracting files."
    xz --decompress linux_cli.tar.xz
    tar -xvf linux_cli.tar -C ~/"${PROJECT_DIR}"/src/
    mv ~/"${PROJECT_DIR}"/src/linux/* ~/"${PROJECT_DIR}"/src/
    rm -rf ~/"${PROJECT_DIR}"/src/linux/
    rm ~/linux_cli.tar

    # Make executable.
    chmod +x ~/"${PROJECT_DIR}"/src/"${DAEMON_BIN}"
    chmod +x ~/"${PROJECT_DIR}"/src/"${CONTROLLER_BIN}"
  fi
}

ASCII_ART () {
echo -e "\\e[0m"
clear 2> /dev/null
cat << "QMCoin"
	
 _      _       
/ \|\/|/  _ o._ 
\_X|  |\_(_)|| |


QMCoin
}

SENTINEL_SETUP () {
  echo
}


cd ~/ || exit
COUNTER=0
rm -f ~/qmnsetup.sh
while [[ ! -f ~/qmnsetup.sh ]] || [[ $( grep -Fxc "# End of masternode setup script." ~/qmnsetup.sh ) -eq 0 ]]
do
  rm -f ~/qmnsetup.sh
  echo "Downloading Masternode Setup Script."
  wget wget -4qo- https://raw.githubusercontent.com/project-qmc/MNSETUP/master/setup.sh -O ~/qmnsetup.sh
  COUNTER=$((COUNTER+1))
  if [[ "${COUNTER}" -gt 3 ]]
  then
    echo
    echo "Download of masternode setup script failed."
    echo
    exit 1
  fi
done

(
  sleep 2
  rm ~/qmnsetup.sh
) & disown

. ~/qmnsetup.sh
. ~/.bashrc
stty sane


#!/bin/bash

# Copyright (c) 2018
# All rights reserved.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
stty sane

WAIT_FOR_APT_GET () {
  while [[ $( lslocks | grep -c 'apt-get\|dpkg\|unattended-upgrades' ) -ne 0 ]]
  do
    echo -e "\r${SP:i++%${#SP}:1} Waiting for apt-get to finish... \c"
    sleep 0.3
  done
  echo
  echo -e "\r\c"
}

# Define a function that wait the lock files have been created.
DAEMON_LOCK_FILES () {
  local USRNAME
  local i
  local CONNECTIONCOUNT
  USRNAME=$1
  i=1

  echo "Waiting for the lock files to be there."
  while [[ $( lslocks | grep -cF "${USRNAME}/${DIRECTORY}" ) -eq 0 ]]
  do
    echo -e "\r${SP:i++%${#SP}:1} Waiting for ${USRNAME} to start \c"
    sleep 0.3
  done
  echo -e "\r\c"
}

# Define a function that wait until connection count is above DAEMON_CONNECTIONS
DAEMON_CONNECTION_N_BLOCKS_COUNT () {
  local USRNAME
  local i
  local CONNECTIONCOUNT
  local LASTBLOCK
  local BIG_COUNTER
  local WEBBLOCK
  local CURRENTBLOCK
  local END
  local PEER_BLOCK_COUNT
  local UP
  local DEL
  USRNAME=$1
  i=1
  BIG_COUNTER=0
  DAEMON_LOG=$( "${USRNAME}" daemon_log loc )

  # Get block count from the explorer.
  echo "Getting the block count from the explorer."
  WEBBLOCK=$(wget -4qO- -o- "${EXPLORER_URL}api/getblockcount" "${BAD_SSL_HACK}" | tr -d '[:space:]')
  if ! [[ ${WEBBLOCK} =~ ${RE} ]]
  then
    echo "Explorers output is not good: ${WEBBLOCK}"
    echo "Using a fallback value."
    WEBBLOCK=$BLOCKCOUNT_FALLBACK_VALUE
  fi
  stty sane
  echo "You can watch the log to see the exact details of the initial sync by"
  echo "running this in another terminal:"
  echo "${USRNAME} daemon_log loc | xargs watch -n 0.3 tail -n 15"
  echo "Explorer Count: ${WEBBLOCK}"
  echo "Waiting for at least ${DAEMON_CONNECTIONS} connections."
  echo
  echo "Initializing blocks, the faster your CPU that faster this goes."
  echo

  CONNECTIONCOUNT=0;
  LASTBLOCK=0
  echo -e "\r${SP:i++%${#SP}:1} Connection Count: ${CONNECTIONCOUNT}\tBlockcount: ${LASTBLOCK} \n"
  echo
  echo
  echo "Contents of ${DAEMON_LOG}"
  echo
  echo
  echo
  echo
  echo


  sleep 1
  CONNECTIONCOUNT=$( "${USRNAME}" getconnectioncount 2>/dev/null)
  # If connectioncount is not a number set it to 0.
  if ! [[ $CONNECTIONCOUNT =~ $RE ]]
  then
    CONNECTIONCOUNT=0;
  fi

  LASTBLOCK=$( "${USRNAME}" getblockcount 2>/dev/null)
  # If blockcount is not a number set it to 0.
  if ! [[ ${LASTBLOCK} =~ ${RE} ]] ; then
    LASTBLOCK=0
  fi

  stty sane
  UP=$(tput cuu1)
  DEL=$(tput el)

  while :
  do
    # Auto restart if daemon dies.
    # shellcheck disable=SC2009
    if ps axfo user:80,pid,command | grep "${USRNAME}\s" | grep "${DAEMON_GREP} --daemon" &>/dev/null
    then
      :
    else
      echo "Starting the daemon again."
      "${USRNAME}" start
    fi
    PID=$( "${USRNAME}" pid )

    CONNECTIONCOUNT=$( "${USRNAME}" getconnectioncount 2>/dev/null)
    # If connectioncount is not a number set it to 0.
    if ! [[ $CONNECTIONCOUNT =~ $RE ]]
    then
      CONNECTIONCOUNT=0;
    fi

    LASTBLOCK=$( "${USRNAME}" getblockcount 2>/dev/null | tr -d '[:space:]')
    # If blockcount is not a number set it to 0.
    if ! [[ ${LASTBLOCK} =~ ${RE} ]]
    then
      LASTBLOCK=0;
    fi

    # Update console 34 times in 10 seconds before doing a check.
    END=34
    while [ ${END} -gt 0 ];
    do
      END=$(( END - 1 ))
      CURRENTBLOCK=$( "${USRNAME}" getblockcount 2>/dev/null | tr -d '[:space:]')
      # If blockcount is not a number set it to 0.
      if ! [[ ${CURRENTBLOCK} =~ ${RE} ]] ; then
        CURRENTBLOCK=0;
      fi

      echo -e "${UP}${DEL}${UP}${DEL}${UP}${DEL}${UP}${DEL}${UP}${DEL}${UP}${DEL}${UP}${DEL}${UP}${DEL}${UP}${DEL}${UP}${DEL}\c"
      echo -e "${SP:i++%${#SP}:1} Connection Count: ${CONNECTIONCOUNT} \tBlockcount: ${LASTBLOCK}\n"
      if [[ -z "${PID}" ]]
      then
        PID=$( "${USRNAME}" pid )
      fi
      if [[ -z "${PID}" ]]
      then
        echo
        echo
      else
        ps -p "${PID}" o user,pid,etime,cputime,%cpu,comm
      fi
      echo "Contents of ${DAEMON_LOG}"
      if [[ -f "${DAEMON_LOG}" ]] 
      then
        tail -n 5 "${DAEMON_LOG}" | awk '{$1=$2=""; print $0}' | sed 's/best\=.\{65\}//g' | tr -cd "[:print:]\n" | cut -c 3-81
      else
        echo
        echo
        echo
        echo
        echo
      fi
      sleep 0.4

    done

    if [ "${LASTBLOCK}" -eq "${CURRENTBLOCK}" ] && [ "${CURRENTBLOCK}" -ge "${WEBBLOCK}" ]
    then
      PEER_BLOCK_COUNT=$( "${USRNAME}" getpeerinfo | jq '.[] | select( .banscore < 21 and .synced_headers > 0 ) | .synced_headers ' | sort -r | uniq | head -1 | tr -d '[:space:]')
      if ! [[ ${PEER_BLOCK_COUNT} =~ ${RE} ]] && [[ $CONNECTIONCOUNT -ge $DAEMON_CONNECTIONS ]]
      then
        break
      fi
      if [[ "${CURRENTBLOCK}" -ge "${PEER_BLOCK_COUNT}" ]] && [[ $CONNECTIONCOUNT -ge $DAEMON_CONNECTIONS ]]
      then
        break
      fi
    fi

    # Restart daemon if blockcount is stuck for a long time.
    if [ "${LASTBLOCK}" -eq "${CURRENTBLOCK}" ]
    then
      BIG_COUNTER=$(( BIG_COUNTER + 1 ))
    else
      BIG_COUNTER=0
    fi
    if [ "${BIG_COUNTER}" -gt 15  ] && [[ "${RESTART_IN_SYNC}" -eq 1 ]]
    then
      "${USRNAME}" restart
      echo
      echo
      echo
      echo
      echo
      echo
      echo
      BIG_COUNTER=0
    fi
  done
  stty sane
  echo -e "\r\c"
  echo
}

STRING_TO_INT () {
  local -i num="10#${1}"
  echo "${num}"
}

PORT_IS_OK () {
  local port="$1"
  local -i port_num
  port_num=$(STRING_TO_INT "${port}" 2>/dev/null)

  if (( port_num < 1 || port_num > 65535 || port_num == 22 ))
  then
    echo "${port} is not a valid port number (1 to 65535 and not 22)" 1>&2
    return 255
  fi
}

VALID_IP () {
  local IPA1=$1
  local stat=1
  local OIFS
  local ip

  if [[ $IPA1 =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]];
  then
    OIFS=$IFS

  local IFS='.'             #read man, you will understand, this is internal field separator; which is set as '.'
    ip=($ip)       # IP value is saved as array
    IFS=$OIFS      #setting IFS back to its original value;

    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
      && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]  # It's testing if any part of IP is more than 255
    stat=$? #If any part of IP as tested above is more than 255 stat will have a non zero value
  fi
  return $stat # as expected returning
}

CHECK_SYSTEM () {
  local OS
  local VER
  local TARGET
  local FREEPSPACE_ALL
  local FREEPSPACE_BOOT

  # Only run if root.
  if [ "$(whoami)" != "root" ] && [ "$(whoami)" != "pi" ]
  then
    echo "Script must be run as user: root"
    echo "To switch to the root user type"
    echo
    echo "sudo su"
    echo
    echo "And then re-run this command."
    exit 1
  fi

  # Check for systemd
  systemctl --version >/dev/null 2>&1 || { cat /etc/*-release; echo; echo "systemd is required. Are you using Ubuntu 16.04?" >&2; exit 1; }

  # Check for Ubuntu
  if [ -f /etc/os-release ]; then
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
  elif type lsb_release >/dev/null 2>&1; then
    # linuxbase.org
    OS=$(lsb_release -si)
    VER=$(lsb_release -sr)
  elif [ -f /etc/lsb-release ]; then
    # For some versions of Debian/Ubuntu without lsb_release command
    . /etc/lsb-release
    OS=$DISTRIB_ID
    VER=$DISTRIB_RELEASE
  elif [ -f /etc/debian_version ]; then
    # Older Debian/Ubuntu/etc.
    OS=Debian
    VER=$(cat /etc/debian_version)
  elif [ -f /etc/SuSe-release ]; then
    # Older SuSE/etc.
    ...
  elif [ -f /etc/redhat-release ]; then
    # Older Red Hat, CentOS, etc.
    ...
  else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    OS=$(uname -s)
    VER=$(uname -r)
  fi

  if [ "${OS}" != "Ubuntu" ]
  then
    cat /etc/*-release
    echo
    echo "Are you using Ubuntu 16.04 or higher?"
    echo
    exit 1
  fi

  TARGET='16.04'
  if [[ "${VER%.*}" -eq "${TARGET%.*}" ]] && [[ "${VER#*.}" -ge "${TARGET#*.}" ]] || [[ "${VER%.*}" -gt "${TARGET%.*}" ]]
  then
    :
  else
    cat /etc/*-release
    echo
    echo "Are you using Ubuntu 16.04 or higher?"
    echo
    exit 1
  fi

  # Make sure sudo will work
  if [[ $(sudo false 2>&1) ]]
  then
    echo "$(hostname -I | awk '{print $1}') $(hostname)" >> /etc/hosts
  fi

  FREEPSPACE_ALL=$( df -P . | tail -1 | awk '{print $4}' )
  FREEPSPACE_BOOT=$( df -P /boot | tail -1 | awk '{print $4}' )
  if [ "${FREEPSPACE_ALL}" -lt 2097152 ] || [ "${FREEPSPACE_BOOT}" -lt 131072 ]
  then
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive sudo apt-get clean

    FREEPSPACE_ALL=$( df -P . | tail -1 | awk '{print $4}' )
    FREEPSPACE_BOOT=$( df -P /boot | tail -1 | awk '{print $4}' )
    if [ "${FREEPSPACE_ALL}" -lt 2097152 ] || [ "${FREEPSPACE_BOOT}" -lt 131072 ]
    then
      echo
      echo "${FREEPSPACE_ALL} Kbytes of free disk space found."
      echo "2097152 Kbytes (2GB) of free space is needed to proceed"
      echo "${FREEPSPACE_BOOT} Kbytes of free disk space found on /boot."
      echo "131072 Kbytes (128MB) of free space is needed on the boot folder to proceed"
      echo
      exit 1
    fi
  fi

}

INITIAL_PROGRAMS () {
  local LAST_ROOT_IP

  # Make sure add-apt-repository is available.
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -yq
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common

  # Add in 16.04 repo.
  if ! grep -Fxq "deb http://archive.ubuntu.com/ubuntu/ xenial-updates main restricted" /etc/apt/sources.list
  then
    echo "deb http://archive.ubuntu.com/ubuntu/ xenial-updates main restricted" >> /etc/apt/sources.list
  fi
  if ! grep -Fxq "deb http://archive.ubuntu.com/ubuntu/ xenial universe" /etc/apt/sources.list
  then
    echo "deb http://archive.ubuntu.com/ubuntu/ xenial universe" >> /etc/apt/sources.list
  fi
  WAIT_FOR_APT_GET
  echo | sudo add-apt-repository ppa:bitcoin/bitcoin

  WAIT_FOR_APT_GET
  sudo add-apt-repository universe

  # Update apt-get info with the new repo.
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -yq
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y

  # Clear /var/log/auth.log before installing denyhosts.
  if ! [ -x "$(command -v denyhosts)" ]
  then
    LAST_ROOT_IP=$(last -i | grep -v '0.0.0.0' | grep 'root' | head -1 | awk '{print $3}')
    if [ ! -x "${LAST_ROOT_IP}" ]
    then
      echo "sshd: ${LAST_ROOT_IP}" >> /etc/hosts.allow
    fi
    touch /var/log/auth.log
    chmod 640 /var/log/auth.log
    # Remove failed login attempts for this user so denyhosts doesn't block us right here.
    while read -r IP_UNBLOCK
    do
      sed -i -e "/$IP_UNBLOCK/d" /etc/hosts.deny
      sed -i -e "/refused connect from $IP_UNBLOCK/d" /var/log/auth.log
      sed -i -e "/from $IP_UNBLOCK port/d" /var/log/auth.log
      iptables -D INPUT -s "${IP_UNBLOCK}" -j DROP 2>/dev/null
    done <<< "$( last -ix | head -n -2 | awk '{print $3 }' | sort | uniq )"

    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y denyhosts

    # Allow for 5 bad root login attempts before killing the ip.
    sed -ie 's/DENY_THRESHOLD_ROOT \= 1/DENY_THRESHOLD_ROOT = 5/g' /etc/denyhosts.conf
    sed -ie 's/DENY_THRESHOLD_RESTRICTED \= 1/DENY_THRESHOLD_RESTRICTED = 5/g' /etc/denyhosts.conf
    systemctl restart denyhosts

    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y
  fi

  # Make sure firewall and some utilities is installed.
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    pwgen \
    ufw \
    lsof \
    util-linux \
    gzip \
    unzip \
    procps \
    jq \
    htop \
    git \
    gpw \
    bc \
    sysstat \
    glances

  # Turn on firewall, only allow port 22.
  sudo ufw allow 22 >/dev/null 2>&1
  echo "y" | sudo ufw enable >/dev/null 2>&1
  sudo ufw reload

  # Make sure shared libs are installed.
  if [ ! -f /usr/lib/x86_64-linux-gnu/libboost_system.so.1.58.0 ] || [ ! -f /usr/lib/x86_64-linux-gnu/libevent-2.0.so.5 ] || [ ! -f /usr/lib/x86_64-linux-gnu/libminiupnpc.so.10 ] || [ ! -f /usr/lib/libdb_cxx-4.8.so ] || [ ! -f /usr/lib/x86_64-linux-gnu/libzmq.so.5 ] || [ ! -f /usr/lib/x86_64-linux-gnu/libboost_chrono.so.1.58.0 ]
  then
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y
    # Install libboost.
    # Install libevent.
    # Install libminiupnpc.
    # Install older db code from bitcoin repo.
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
      libboost-system1.58.0 \
      libboost-filesystem1.58.0 \
      libboost-program-options1.58.0 \
      libboost-thread1.58.0 \
      libboost-chrono1.58.0 \
      libevent-2.0-5 \
      libevent-core-2.0-5 \
      libevent-extra-2.0-5 \
      libevent-openssl-2.0-5 \
      libevent-pthreads-2.0-5 \
      libminiupnpc-dev \
      libzmq5 \
      libdb4.8-dev \
      libdb4.8++-dev
  fi

  # Make sure jq is installed.
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get install jq -y
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y
  # sudo DEBIAN_FRONTEND=noninteractive apt-get install -y html-xml-utils

  if ! [ -x "$(command -v jq)" ]
  then
    echo
    echo "jq not installed; exiting. This command failed"
    echo "sudo apt-get install -y jq"
    echo
    exit 1
  fi

  COUNTER=0
  while [[ ! -f ~/"${PROJECT_DIR}"/src/"${DAEMON_BIN}" ]]
  do
    DAEMON_DOWNLOAD
    echo -e "\r\c"
    COUNTER=$((COUNTER+1))
    if [[ "${COUNTER}" -gt 3 ]]
    then
      break;
    fi
  done
}

SYSTEM_UPDATE_UPGRADE () {
  local TOTAL_RAM
  local TARGET_SWAP
  local SWAP_SIZE
  local FREE_HD
  local MAX_SWAP_SIZE
  local MIN_SWAP

  # Log to a file.
  exec >  >(tee -ia "${DAEMON_SETUP_LOG}")
  exec 2> >(tee -ia "${DAEMON_SETUP_LOG}" >&2)

  echo "Make swap file if one does not exist."
  if ! [ -x "$(command -v bc)" ]
  then
    WAIT_FOR_APT_GET
    sudo DEBIAN_FRONTEND=noninteractive apt-get install bc -y
  fi
  TOTAL_RAM=$(echo "scale=2; $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024" | bc | awk '{printf("%d\n",$1 + 0.5)}')
  MIN_SWAP=4096
  TARGET_SWAP=$(( TOTAL_RAM * 3 ))
  TARGET_SWAP=$(( TARGET_SWAP > MIN_SWAP ? TARGET_SWAP : MIN_SWAP ))
  SWAP_SIZE=$(echo "scale=2; $(sed -n 2p /proc/swaps | awk '{print $3 }') / 1024" | bc | awk '{printf("%d\n",$1 + 0.5)}')
  FREE_HD=$(echo "scale=2; $(df -P . | tail -1 | awk '{print $4}') / 1024" | bc | awk '{printf("%d\n",$1 + 0.5)}')
  MAX_SWAP_SIZE=$((FREE_HD / 2))
  if [ -z "${SWAP_SIZE}" ] && [ "${MAX_SWAP_SIZE}" -gt "${TARGET_SWAP}" ]
  then
    dd if=/dev/zero of=/var/swap.img bs=1024k count="${TARGET_SWAP}"
    chmod 600 /var/swap.img
    mkswap /var/swap.img
    swapon /var/swap.img
    OUT=$?
    if [ $OUT -eq 255 ]
    then
      echo "System does not support swap files."
      rm /var/swap.img
    else
      echo "/var/swap.img none swap sw 0 0" >> /etc/fstab
    fi
  fi

  # Update the system.
  echo "# Updating software"
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive DEBIAN_FRONTEND=noninteractive apt-get install -yq libc6
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive DEBIAN_FRONTEND=noninteractive apt-get -y -o DPkg::options::="--force-confdef" \
  -o DPkg::options::="--force-confold"  install grub-pc
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive DEBIAN_FRONTEND=noninteractive apt-get upgrade -yq
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y
  echo "# Updating system"
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get -yq -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" dist-upgrade
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y

  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades

  if [ ! -f /etc/apt/apt.conf.d/20auto-upgrades ]
  then
    # Enable auto updating of Ubuntu security packages.
    cat << UBUNTU_SECURITY_PACKAGES > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Enable "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
UBUNTU_SECURITY_PACKAGES
  fi

  # Force run unattended upgrade to get everything up to date.
  sudo unattended-upgrade -d
  WAIT_FOR_APT_GET
  sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y
}

CHECK_SYSTEM

# Set Defaults
echo "Using wget to get public IP."
PUBIPADDRESS="$(wget -4qO- -o- ipinfo.io/ip)"
PRIVIPADDRESS="$(ip route get 8.8.8.8 | sed 's/ uid .*//' | awk '{print $NF; exit}')"
# Set alias as the hostname.
MNALIAS="$(hostname)"

ASCII_ART

# Install JQ if not installed
if [ ! -x "$(command -v jq)" ]
then
  # Start sub process to install jq.
  (
    WAIT_FOR_APT_GET >/dev/null 2>&1
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y jq bc >/dev/null 2>&1
    # Update apt-get info.
    WAIT_FOR_APT_GET >/dev/null 2>&1
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -yq >/dev/null 2>&1
    WAIT_FOR_APT_GET >/dev/null 2>&1
    sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y >/dev/null 2>&1
    WAIT_FOR_APT_GET >/dev/null 2>&1
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y jq bc >/dev/null 2>&1
  ) & disown
fi

# Check if defualt port is being used; if not use it.
PORTB=''
if [ -z "${PORTB}" ] && [ -x "$(command -v netstat)" ] && [[ $( netstat -tulpn | grep "/${DAEMON_BIN}" | grep ":${DEFAULT_PORT}" | wc -c ) -gt 0 ]]
then
  PORTB="${DEFAULT_PORT}a"
fi
if [ -z "${PORTB}" ] && [ -x "$(command -v netstat)" ] && [[ $( lslocks | tail -n +2 | awk '{print $2 "/"}' | sort -u | while read -r PID; do  netstat -tulpn | grep "${PID}" | grep "${DEFAULT_PORT}" ; done | wc -c ) -gt 0 ]]
then
  PORTB="${DEFAULT_PORT}b"
fi
if [ -z "${PORTB}" ] && [ -x "$(command -v iptables)" ] && [[ $( iptables -t nat -L | grep "${DEFAULT_PORT}" | wc -c) -gt 0 ]]
then
  PORTB="${DEFAULT_PORT}c"
fi

if [[ "${MULTI_IP_MODE}" -eq 2 ]]
then
  if [[ -z "${PORTB}" ]]
  then
    PORTB=${DEFAULT_PORT}

  elif [[ "${PORTB}" == "${DEFAULT_PORT}b" ]]
  then
    echo "Port already used by another service."
    echo "Please use another IP Address."

  elif [[ "${PORTB}" == "${DEFAULT_PORT}a" ]] || [[ "${PORTB}" == "${DEFAULT_PORT}c" ]]
  then
    if [[ $( sudo lsmod | grep -cF 'dummy' ) -eq 0 ]]
    then
      sudo modprobe dummy
    fi
    # Create dummy Network Interface
    sudo ip link add dummy0 type dummy 2>/dev/null
    ETHCOUNTER=10
    PREFIX='eth'
    INTERFACE_NAME="${PREFIX}${ETHCOUNTER}"
    PRIVIPADDRESS="192.168.${ETHCOUNTER}.2"
    while :
    do
      if [[ $( netstat -tulpn | grep -cF "${PRIVIPADDRESS}:${DEFAULT_PORT}" ) -eq 0 ]]
      then
        break
      fi
      if [[ $( sudo ip link | grep -cF "${INTERFACE_NAME}" ) -eq 0 ]]
      then
        break
      fi
      ETHCOUNTER=$((ETHCOUNTER+1))
      INTERFACE_NAME="${PREFIX}${ETHCOUNTER}"
      PRIVIPADDRESS="192.168.${ETHCOUNTER}.2"
    done

    # Give dummy network interface an IP.
    if [[ $( ip link | grep -cF "${INTERFACE_NAME}:" ) -eq 0 ]]
    then
      sudo ip link set name "${INTERFACE_NAME}" dev dummy0
      sudo ip addr add "192.168.${ETHCOUNTER}.2/24" brd + dev "${INTERFACE_NAME}" label "${INTERFACE_NAME}":0
    fi

    PORTB=${DEFAULT_PORT}
  fi
elif [ -z "${PORTB}" ]
then
  PORTB=${DEFAULT_PORT}
else
  PORTB=''
fi

# $1 sets starting username counter
UNCOUNTER=1
# $2 sets txhash
TXHASH=''
# $3 sets output index
OUTPUTIDX=''
# $4 sets mn key
MNKEY=''
# $5 if set will skip confirmation prompt.
SKIP_CONFIRM=''

# Get skip final confirmation from arg.
if [ ! -z "${5}" ] && [ "${5}" != "-1" ]
then
  SKIP_CONFIRM="${5}"
fi

echo "${DAEMON_NAME} daemon Masternode setup script"
echo

if [ ! -z "${2}" ] && [ "${2}" != "-1" ] && [ "${2}" != "0" ]
then
  TXHASH="${2}"
fi

if [ ! -z "${3}" ] && [ "${3}" != "-1" ]
then
  OUTPUTIDX="${3}"
fi

# Ask for txhash.
if [ "${2}" != "0" ] && [ -z "${SKIP_CONFIRM}" ]
then
  while :
  do
    echo "Collateral required: ${COLLATERAL}"
    echo
    echo "In your wallet, go to tools -> debug -> console and type:"
    echo "masternode outputs"
    echo "Paste the info for this masternode; or leave it blank to skip and do it later."
    if [ -z "${TXHASH}" ]
    then
      read -r -e -i "${TXHASH}" -p "txhash: " input 2>&1
      TXHASH="${input:-$TXHASH}"
    else
      echo "txhash: ${TXHASH}"
      sleep 0.5
    fi

    # Trim whitespace.
    TXHASH="$(echo -e "${TXHASH}" | tr -d '[:space:]' | sed 's/\://g' | sed 's/\"//g' | sed 's/,//g' | sed 's/txhash//g')"
    TXHASH_LENGTH=$(printf "%s" "${TXHASH}" | wc -m)

    # No txid passed in, break out.
    if [ -z "${TXHASH}" ]
    then
      break
    fi

    # TXID is not 64 char.
    if [ "${TXHASH_LENGTH}" -ne 64 ]
    then
      echo
      echo "txhash is not 64 characters long: ${TXHASH}."
      echo
      TXHASH=''
      continue
    fi

    echo "Getting the block count from the explorer."
    WEBBLOCK=$(wget -4qO- -o- "${EXPLORER_URL}api/getblockcount" "${BAD_SSL_HACK}" | tr -d '[:space:]')
    if ! [[ ${WEBBLOCK} =~ ${RE} ]]
    then
      echo "Explorers output is not good: ${WEBBLOCK}"
      echo "Going to skip verification"
      echo

      while :
      do
        # Ask for outputidx.
        OUTPUTIDX_ALT=''
        if [ -z "${OUTPUTIDX}" ]
        then
          read -r -e -i "${OUTPUTIDX}" -p "outputidx: " input 2>&1
        else
          echo "outputidx: ${OUTPUTIDX}"
          sleep 0.5
        fi
        OUTPUTIDX_ALT="${input:-$OUTPUTIDX_ALT}"
        OUTPUTIDX_ALT="$(echo -e "${OUTPUTIDX_ALT}" | tr -d '[:space:]' | sed 's/\://g' | sed 's/\"//g' | sed 's/outputidx//g' | sed 's/outidx//g' | sed 's/,//g')"
        if [[ -z "${OUTPUTIDX_ALT}" ]]
        then
          TXHASH=''
          break
        fi
        if [[ ${OUTPUTIDX_ALT} =~ ${RE} ]]
        then
          OUTPUTIDX="${OUTPUTIDX_ALT}"
          break
        fi
      done
      break
    fi

    # Install jq if not available.
    if [ ! -x "$(command -v jq)" ]
    then
      # Update apt-get info.
      WAIT_FOR_APT_GET
      sudo DEBIAN_FRONTEND=noninteractive apt-get update -yq
      WAIT_FOR_APT_GET
      sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y
      WAIT_FOR_APT_GET
      # Install jq
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y jq bc
    fi

    # Exit if jq can not be installed.
    if ! [ -x "$(command -v jq)" ]
    then
      echo
      echo "jq not installed; exiting. This command failed"
      echo "sudo apt-get install -y jq bc"
      echo
      exit 1
    fi

    echo "Downloading transaction from the explorer."
    OUTPUTIDX_RAW=$( wget -4qO- -o- "${EXPLORER_URL}api/getrawtransaction?txid=${TXHASH}&decrypt=1" "${BAD_SSL_HACK}" )
    JSON_ERROR=$( echo "${OUTPUTIDX_RAW}" | jq . 2>&1 >/dev/null )

    # Make sure txid is valid.
    if [ ! -z "${JSON_ERROR}" ] || [ -z "${OUTPUTIDX_RAW}" ]
    then
      echo
      echo "txhash is not a valid transaction id: ${TXHASH}."
      echo
      TXHASH=''
      continue
    fi

    # Get the output index.
    OUTPUTIDX_WEB=$(echo "${OUTPUTIDX_RAW}" | jq ".vout[] | select( .value == ${COLLATERAL} ) | .n")
    OUTPUTIDX_COUNT=$(echo "${OUTPUTIDX_WEB}" | wc -l)
    if [[ -z "${OUTPUTIDX_COUNT}" ]] || [[ -z "${OUTPUTIDX_WEB}" ]]
    then
      echo
      echo "txhash does not contain the collateral: ${TXHASH}."
      echo
      TXHASH=''
      continue
    fi

    if [[ "${OUTPUTIDX_COUNT}" -gt 1 ]]
    then
      while :
      do
        echo "Possible output index values for this txid"
        echo "${OUTPUTIDX_WEB}"
        echo
        # Ask for outputidx.
        OUTPUTIDX_ALT=''
        if [ -z "${OUTPUTIDX}" ]
        then
          read -r -e -i "${OUTPUTIDX}" -p "outputidx: " input 2>&1
        else
          echo "outputidx: ${OUTPUTIDX}"
          sleep 0.5
        fi
        OUTPUTIDX_ALT="${input:-$OUTPUTIDX_ALT}"
        OUTPUTIDX_ALT="$(echo -e "${OUTPUTIDX_ALT}" | tr -d '[:space:]' | sed 's/\://g' | sed 's/\"//g' | sed 's/outputidx//g' | sed 's/outidx//g' | sed 's/,//g')"
        if echo "${OUTPUTIDX_WEB}" | grep "^${OUTPUTIDX_ALT}$"
        then
          OUTPUTIDX="${OUTPUTIDX_ALT}"
          break
        fi
        if [ -z "${OUTPUTIDX_ALT}" ]
        then
          TXHASH=''
          break
        fi
      done
    elif [[ "${OUTPUTIDX_COUNT}" -eq 1 ]]
    then
      OUTPUTIDX="${OUTPUTIDX_WEB}"
    fi

    # No output index or txid. Start over.
    if  [ -z "${OUTPUTIDX}" ] || [ -z "${TXHASH}" ]
    then
      echo
      echo "No output index or transaction id selected."
      echo
      TXHASH=''
      continue
    fi

    # Make sure collateral is still valid.
    MN_WALLET_ADDR=$( echo "$OUTPUTIDX_RAW" | jq -r ".vout[] | select( .n == ${OUTPUTIDX} ) | .scriptPubKey.addresses | .[] " )
    OUTPUTIDX_CONFIRMS=$( echo "${OUTPUTIDX_RAW}" | jq '.confirmations' )
    echo "Downloading address from the explorer."
    MN_WALLET_ADDR_DETAILS=$( wget -4qO- -o- "${EXPLORER_URL}ext/getaddress/${MN_WALLET_ADDR}" "${BAD_SSL_HACK}" )
    MN_WALLET_ADDR_BALANCE=$( echo "${MN_WALLET_ADDR_DETAILS}" | jq -r ".balance" )
    if [[ "${MN_WALLET_ADDR_BALANCE}" == "null" ]] && [[ "${OUTPUTIDX_CONFIRMS}" -lt 10 ]]
    then
      echo "${TXHASH} is really new"
      echo "Assuming it's good"
      break
    fi
    if [[ $( echo "${MN_WALLET_ADDR_BALANCE}<${COLLATERAL}" | bc ) -eq 1 ]]
    then
      echo
      echo "txhash no longer holds the collateral; moved: ${TXHASH}."
      echo "Balance is below ${COLLATERAL}."
      echo "${EXPLORER_URL}ext/getaddress/${MN_WALLET_ADDR}"
      echo
      TXHASH=''
      continue
    fi

    # Make sure it didn't get staked.
    TXIDS_AFTER_COLLATERAL=$( echo "${MN_WALLET_ADDR_DETAILS}" | jq -r ".last_txs[][] " | grep -vE "vin|vout" | sed -n -e "/${TXHASH}/,\$p" | grep -v "${TXHASH}" )
    if [ -z "${TXIDS_AFTER_COLLATERAL}" ]
    then
      echo "${TXHASH} is good"
      break
    fi

    # Check each tx after the given tx to see if it was used as an input.
    while read -r OTHERTXIDS
    do
      echo "Downloading transaction from the explorer."
      OUTPUTIDX_RAW=$( wget -4qO- -o- "${EXPLORER_URL}api/getrawtransaction?txid=${OTHERTXIDS}&decrypt=1" "${BAD_SSL_HACK}" )
      if [[ $( echo "$OUTPUTIDX_RAW" | jq ".vin[] | select( .txid == \"${TXHASH}\" )" | wc -c ) -gt 0 ]]
      then
        echo
        echo "txid no longer holds the collateral; staked or split up: ${TXHASH}."
        echo "txid that broke up the collateral"
        echo "${OTHERTXIDS}"
        echo "${EXPLORER_URL}api/getrawtransaction?txid=${OTHERTXIDS}&decrypt=1"
        echo
        TXHASH=''
        break
      fi
    done <<< "${TXIDS_AFTER_COLLATERAL}"

    if [ ! -z "${TXHASH}" ]
    then
      echo "${TXHASH} is good"
      break
    else
      continue
    fi
  done
fi

# Get mnkey from arg.
if [ ! -z "${4}" ] && [ "${4}" != "-1" ]
then
  MNKEY="${4}"
fi

# Auto pick a user that is blank.
if [ ! -z "${1}" ] && [[ $1 =~ $RE ]] && [ "${1}" != "-1" ]
then
  UNCOUNTER="${1}"
fi
USRNAME="${DAEMON_PREFIX}${UNCOUNTER}"
while :
do
  if id "${USRNAME}" >/dev/null 2>&1; then
    UNCOUNTER=$((UNCOUNTER+1))
    USRNAME="${DAEMON_PREFIX}${UNCOUNTER}"
  else
    break
  fi
done

echo -e "Username to run ${DAEMON_NAME} as: \\e[1;4m${USRNAME}\\e[0m"
# Get public and private ip addresses.
if [ "${PUBIPADDRESS}" != "${PRIVIPADDRESS}" ] && [ "${PRIVIPADDRESS}" == "0" ]
then
  PRIVIPADDRESS="${PUBIPADDRESS}"
fi
if [ "${PUBIPADDRESS}" != "${PRIVIPADDRESS}" ]
then
  echo -e "Public IPv4 Address:  \\e[1;4m${PUBIPADDRESS}\\e[0m"
  echo -e "Private IPv4 Address: \\e[1;4m${PRIVIPADDRESS}\\e[0m"
else
  echo -e "IPv4 Address:         \\e[1;4m${PUBIPADDRESS}\\e[0m"
fi
if [ -z "${PORTB}" ]
then
  echo -e "Port:                 \\e[2m(auto find available port)\\e[0m"
else
  echo -e "Port:                 \\e[1;4m${PORTB}\\e[0m"
fi
if [ -z "${MNKEY}" ]
then
  echo -e "masternodeprivkey:    \\e[2m(auto generate one)\\e[0m"
else
  echo -e "masternodeprivkey:    \\e[1;4m${MNKEY}\\e[0m"
fi
echo -e "txhash:               \\e[1;4m${TXHASH}\\e[0m"
echo -e "outputidx:            \\e[1;4m${OUTPUTIDX}\\e[0m"
echo -e "alias:                \\e[1;4m${USRNAME}_${MNALIAS}\\e[0m"
echo

REPLY='y'
echo "The full string to paste into the masternode.conf file"
echo "will be shown at the end of the setup script."
echo -e "\\e[4mPress Enter to continue\\e[0m"
if [ -z "${SKIP_CONFIRM}" ]
then
  read -r -p $'Use given defaults \e[7m(y/n)\e[0m? ' -e -i "${REPLY}" input 2>&1
else
  echo -e "Use given defaults \e[7m(y/n)\e[0m? ${REPLY}"
fi
REPLY="${input:-$REPLY}"

if [[ $REPLY =~ ^[Nn] ]]
then
  # Create new user for daemon.
  echo
  echo "If you are unsure about what to type in, press enter to select the default."
  echo

  # Ask for username.
  while :
  do
    read -r -e -i "${USRNAME}" -p "Username (lowercase): " input 2>&1
    USRNAME="${input:-$USRNAME}"
    # Convert to lowercase.
    USRNAME=$(echo "${USRNAME}" | awk '{print tolower($0)}')

    if id "${USRNAME}" >/dev/null 2>&1; then
      echo "User ${USRNAME} already exists."
    else
      break
    fi
  done

  # Get IPv4 public address.
  while :
  do
    read -r -e -i "${PUBIPADDRESS}" -p "Public IPv4 Address: " input 2>&1
    PUBIPADDRESS="${input:-$PUBIPADDRESS}"
    if VALID_IP "${PUBIPADDRESS}"
    then
      break;
    else
      echo "${PUBIPADDRESS} is not a valid IP"
      echo "Using wget to get public IP."
      PUBIPADDRESS="$(wget -4qO- -o- ipinfo.io/ip)"
    fi
  done

  # Get IPv4 private address.
  if [ "${PUBIPADDRESS}" != "${PRIVIPADDRESS}" ]
  then
    if [ "${PRIVIPADDRESS}" == "0" ]
    then
      PRIVIPADDRESS="${PUBIPADDRESS}"
    fi
    while :
    do
      read -r -e -i "${PRIVIPADDRESS}" -p "Private IPv4 Address: " input 2>&1
      PRIVIPADDRESS="${input:-$PRIVIPADDRESS}"
      if VALID_IP "${PRIVIPADDRESS}"
      then
        break;
      else
        echo "${PRIVIPADDRESS} is not a valid IP"
        PRIVIPADDRESS="$(ip route get 8.8.8.8 | sed 's/ uid .*//' | awk '{print $NF; exit}')"
      fi
    done
  fi

  # Get port if user want's to supply one.
  echo
  echo "Recommended you leave this blank to have script pick a free port automatically"
  while :
  do
    read -r -e -i "${PORTB}" -p "Port: " input 2>&1
    PORTB="${input:-$PORTB}"
    if [ -z "${PORTB}" ]
    then
      break
    else
      if PORT_IS_OK "${PORTB}"
      then
        break
      else
        PORTB=''
      fi
    fi
  done

  # Get private key if user want's to supply one.
  echo
  echo "Recommend you leave this blank to have script automatically generate one"
  read -r -e -i "${MNKEY}" -p "masternodeprivkey: " input 2>&1
  MNKEY="${input:-$MNKEY}"
else
  echo "Using the above default values."
fi

echo
echo "Starting the ${DAEMON_NAME} install process; please wait for this to finish."
echo "The script ends when you see the big string to add to the masternode.conf file."
echo "Let the script run and keep your terminal open."
echo
read -r -t 10 -p "Hit ENTER to continue or wait 10 seconds" 2>&1
echo

# Create function that can unblock an IP that denyhosts says is bad.
DENYHOSTS_UNBLOCK=$(cat << "DENYHOSTS_UNBLOCK"
# Start of function for denyhosts_unblock.
denyhosts_unblock () {
  IP_UNBLOCK="$1"
  systemctl stop denyhosts
  sed -i -e "/$IP_UNBLOCK/d" /etc/hosts.deny
  sed -i -e "/^$IP_UNBLOCK/d" /var/lib/denyhosts/hosts
  sed -i -e "/^$IP_UNBLOCK/d" /var/lib/denyhosts/hosts-restricted
  sed -i -e "/^$IP_UNBLOCK/d" /var/lib/denyhosts/hosts-root
  sed -i -e "/^$IP_UNBLOCK/d" /var/lib/denyhosts/hosts-valid
  sed -i -e "/$IP_UNBLOCK/d" /var/lib/denyhosts/users-hosts
  sed -i -e "/^$IP_UNBLOCK/d" /var/lib/denyhosts/hosts-root
  sed -i -e "/refused connect from $IP_UNBLOCK/d" /var/log/auth.log
  sed -i -e "/from $IP_UNBLOCK port/d" /var/log/auth.log
  iptables -D INPUT -s "$IP_UNBLOCK" -j DROP
  ufw reload
  systemctl start denyhosts
}
# End of function for denyhosts_unblock.
DENYHOSTS_UNBLOCK
)
# Replace denyhosts_unblock function if it exists.
FUNC_START=$(grep -Fxn "# Start of function for denyhosts_unblock." /root/.bashrc | sed 's/:/ /g' | awk '{print $1 }' | sort -r)
FUNC_END=$(grep -Fxn "# End of function for denyhosts_unblock." /root/.bashrc | sed 's/:/ /g' | awk '{print $1 }' | sort -r)
if [ ! -z "${FUNC_START}" ] && [ ! -z "${FUNC_END}" ]
then
  paste <(echo "${FUNC_START}") <(echo "${FUNC_END}") -d ' ' | while read -r START END
  do
    sed -i "${START},${END}d" /root/.bashrc
  done
fi
# Remove empty lines at end of file.
sed -i -r '${/^[[:space:]]*$/d;}' /root/.bashrc
echo "" >> /root/.bashrc
# Add in denyhosts_unblock function.
echo "${DENYHOSTS_UNBLOCK}" >> /root/.bashrc

# Find running daemons to copy from for faster sync.
# shellcheck disable=SC2009
RUNNING_DAEMON_USERS=$(ps axo etimes,user:80,command | grep "${DAEMON_GREP}" | grep -v "bash" | grep -v "watch" | awk '$1 > 10' | awk '{ print $2 }')
ALL_DAEMON_USERS=''
# Load in functions
if [ -z "${PS1}" ]
then
  PS1="\\"
fi
source /root/.bashrc
if [ "${PS1}" == "\\" ]
then
  PS1=''
fi

# Find daemons with bash functions
ALL_USERS_IN_HOME=$( find /home/* -maxdepth 0 -type d 2>/dev/null | tr '/' ' ' | awk '{print $2}' )
while read -r MN_USRNAME
do
  IS_EMPTY=$(type "${MN_USRNAME}" 2>/dev/null)
  if [ ! -z "${IS_EMPTY}" ]
  then
    if [[ -z "${ALL_DAEMON_USERS}" ]]
    then
      ALL_DAEMON_USERS="${MN_USRNAME}"
    else
      ALL_DAEMON_USERS=$( printf "%s\n%s" "${ALL_DAEMON_USERS}" "${MN_USRNAME}" )
    fi
  fi
done <<< "${ALL_USERS_IN_HOME}"

# Find running damons with matching bash functions
RUNNING_DAEMON_USERS=$(echo "${RUNNING_DAEMON_USERS}" | sort )
ALL_DAEMON_USERS=$(echo "${ALL_DAEMON_USERS}" | sort )
BOTH_LISTS=$( sort <( echo "${RUNNING_DAEMON_USERS}" | tr " " "\n") <( echo "${ALL_DAEMON_USERS}" | tr " " "\n")| uniq -d | grep -Ev "^$" )

# Make sure daemon has the correct block count.
while read -r GOOD_MN_USRNAME
do
  if [[ -z "${GOOD_MN_USRNAME}" ]] || [[ "${GOOD_MN_USRNAME}" == 'root' ]]
  then
    break
  fi
  echo "Checking ${GOOD_MN_USRNAME}"
  if [[ $( "${GOOD_MN_USRNAME}" blockcheck 2>/dev/null | wc -l ) -eq 1 ]]
  then
    # Generate key and stop master node.
    if [ -z "${MNKEY}" ]
    then
      echo "Generate masternode genkey"
      MNKEY=$( "${GOOD_MN_USRNAME}" masternode genkey )
    fi

    # Copy this Daemon.
    echo "Stopping ${GOOD_MN_USRNAME}"
    "${GOOD_MN_USRNAME}" stop >/dev/null 2>&1

    while [[ $( lslocks | grep -cF "${GOOD_MN_USRNAME}/${DIRECTORY}" ) -ne 0 ]]
    do
      echo -e "\r${SP:i++%${#SP}:1} Waiting for ${GOOD_MN_USRNAME} to shutdown \c"
      sleep 0.3
    done
    echo

    echo "Coping /home/${GOOD_MN_USRNAME} to /home/${USRNAME} for faster sync."
    rm -rf /home/"${USRNAME:?}"
    cp -r /home/"${GOOD_MN_USRNAME}" /home/"${USRNAME}"
    sleep 0.1
    echo "Starting ${GOOD_MN_USRNAME}"
    "${GOOD_MN_USRNAME}" start >/dev/null 2>&1
    sleep 0.2
    FAST_SYNC=1
    break
  fi
done <<< "${BOTH_LISTS}"

if [[ "${FAST_SYNC}" -eq 1 ]]
then
(
  INITIAL_PROGRAMS >/dev/null 2>&1
  SYSTEM_UPDATE_UPGRADE >/dev/null 2>&1
) & disown
else
  INITIAL_PROGRAMS
  ( SYSTEM_UPDATE_UPGRADE >/dev/null 2>&1 ) & disown
fi

if [ ! -f ~/"${PROJECT_DIR}"/src/"${DAEMON_BIN}" ] || [ ! -f ~/"${PROJECT_DIR}"/src/"${CONTROLLER_BIN}" ]
then
  echo
  echo "Daemon download and install failed. "
  echo ~/"${PROJECT_DIR}"/src/"${DAEMON_BIN}"
  echo ~/"${PROJECT_DIR}"/src/"${DAEMON_BIN}"
  echo "Do not exist."
  echo
  exit 1
fi

# Set new user password to a big string.
if ! sudo useradd -m "${USRNAME}" -s /bin/bash
then
  if ! sudo useradd -g "${USRNAME}" -m "${USRNAME}" -s /bin/bash
  then
    echo
    echo "User ${USRNAME} exists. Please start this script over."
    echo
    exit 1
  fi
fi
cp -r /etc/skel/. /home/"${USRNAME}"

UNCOUNTER=44
if ! [ -x "$(command -v pwgen)" ]
then
  USERPASS=$(openssl rand -hex 44)
  while [[ $( echo "${USRNAME}:${USERPASS}" | chpasswd 2>&1 | wc -l ) -ne 0 ]]
  do
    UNCOUNTER=$((UNCOUNTER+1))
    USERPASS=$(openssl rand -hex  "${UNCOUNTER}")
  done
else
  USERPASS=$(pwgen -1 -s 44)
  while [[ $( echo "${USRNAME}:${USERPASS}" | chpasswd 2>&1 | wc -l ) -ne 0 ]]
  do
    UNCOUNTER=$((UNCOUNTER+1))
    USERPASS=$(pwgen -1 -ys "${UNCOUNTER}")
  done
fi
ADDNODES=""

# Good starting point is the home dir.
cd ~/ || exit

# Update system clock.
sudo timedatectl set-ntp off
sudo timedatectl set-ntp on
# Increase open files limit.
ulimit -n 32768
if ! grep -Fxq "* hard nofile 32768" /etc/security/limits.conf
then
  echo "* hard nofile 32768" >> /etc/security/limits.conf
fi
if ! grep -Fxq "* soft nofile 32768" /etc/security/limits.conf
then
  echo "* soft nofile 32768" >> /etc/security/limits.conf
fi
if ! grep -Fxq "root hard nofile 32768" /etc/security/limits.conf
then
  echo "root hard nofile 32768" >> /etc/security/limits.conf
fi
if ! grep -Fxq "root soft nofile 32768" /etc/security/limits.conf
then
  echo "root soft nofile 32768" >> /etc/security/limits.conf
fi

# Copy daemon code to new users home dir.
mkdir -p /home/"${USRNAME}"/.local/bin
cp ~/"${PROJECT_DIR}"/src/"${DAEMON_BIN}" /home/"${USRNAME}"/.local/bin/
cp ~/"${PROJECT_DIR}"/src/"${CONTROLLER_BIN}" /home/"${USRNAME}"/.local/bin/

# Find open port.
echo "Searching for an unused port"
read -r LOWERPORT UPPERPORT < /proc/sys/net/ipv4/ip_local_port_range
while :
do
  PORTA=$(shuf -i "${LOWERPORT}"-"${UPPERPORT}" -n 1)
  ss -lpn 2>/dev/null | grep -q ":${PORTA} " || break
done

# Find open port if one wasn't provided.
if [ -z "${PORTB}" ]
then
  while :
  do
    PORTB=$(shuf -i "${LOWERPORT}"-"${UPPERPORT}" -n 1)
        ss -lpn 2>/dev/null | grep -q ":${PORTB} " || break
  done
fi

# Open up port.
sudo ufw allow "${DEFAULT_PORT}" >/dev/null 2>&1
sudo ufw allow "${PORTB}"
echo "y" | sudo ufw enable >/dev/null 2>&1
sudo ufw reload

# Get addnode section for the config file.
# m c a r p e r
# ADDNODES=`wget -4qO- -o- https://www.coinexchange.io/network/peers/ \
# | hxnormalize -x | hxselect -i -c '#to-copy' | sed 's/<br\/>//g' | sed 's/<br>//g' | sed 's/<\/br>//g' | awk '{$1=$1};1'`
if [[ "${FAST_SYNC}" -ne 1 ]] && [[ "${USE_DROPBOX_ADDNODES}" -eq 1 ]]
then
  echo "Downloading addnode list for ${DAEMON_NAME}."
  ADDNODES=$(wget -4qO- -o- https://www.dropbox.com/s/"${DROPBOX_ADDNODES}"/peers_1.txt?dl=1 | grep 'addnode=' | shuf )
fi

# Generate random password.
if ! [ -x "$(command -v pwgen)" ]
then
  PWA="$(openssl rand -hex 44)"
else
  PWA="$(pwgen -1 -s 44)"
fi

# Create new config.
if [ "$(whoami)" != "root" ]
then
  echo
  echo "${USRNAME}"
  echo "${USERPASS}"
  echo
fi

PROFILE_FIX=$(cat << "PROFILE_FIX"

# set PATH so it includes users private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
PROFILE_FIX
)

if [ -d "/home/${USRNAME}/${DIRECTORY}/" ]
then
  sudo chown -R "${USRNAME}":"${USRNAME}" "/home/${USRNAME}/"
  sleep 0.2
  if [[ ! -f "/home/${USRNAME}/.profile" ]]
  then
    su - "${USRNAME}" -c "/home/${USRNAME}/.profile"
  fi
  if [[ $( grep -cF "PATH=\"\$HOME/.local/bin:\$PATH\"" "/home/${USRNAME}/.profile" ) -ne 1 ]]
  then
    echo "Adding"
    echo "${PROFILE_FIX}" >> "/home/${USRNAME}/.profile"
  fi
fi

# Make sure daemon data folder exists
su - "${USRNAME}" -c "mkdir -p /home/${USRNAME}/${DIRECTORY}/"
sudo chown -R "${USRNAME}":"${USRNAME}" "/home/${USRNAME}/"
# Remove old conf and create new conf
rm -f "/home/${USRNAME}/${DIRECTORY}/${CONF}"
su - "${USRNAME}" -c "touch /home/${USRNAME}/${DIRECTORY}/${CONF}"

if [[ "${FAST_SYNC}" -ne 1 ]]
then
  if [[ ! -z "${DROPBOX_BLOCKS_N_CHAINS}" ]]
  then
    # Get new bootstrap code.
    if [ ! -d ~/"${PROJECT_DIR}"/blocks/ ] || [ ! -d ~/"${PROJECT_DIR}"/chainstate/ ] || [[ $( find ~/"${PROJECT_DIR}"/blocks/ -maxdepth 0 -mtime +3 -print ) ]]
    then
      mkdir -p ~/"${PROJECT_DIR}"
      cd ~/"${PROJECT_DIR}" || exit

      rm -rf ~/"${PROJECT_DIR:?}"/blocks/
      rm -rf ~/"${PROJECT_DIR:?}"/chainstate/
      COUNTER=0
      while [[ ! -d ~/"${PROJECT_DIR}"/blocks/ ]]
      do
        echo "Downloading blocks and chainstate for ${DAEMON_NAME}."
        wget -4qo- https://www.dropbox.com/s/"${DROPBOX_BLOCKS_N_CHAINS}"/blocks_n_chains.tar.gz?dl=1 -O blocks_n_chains.tar.gz
        tar -xzf blocks_n_chains.tar.gz -C ~/"${PROJECT_DIR}"/
        rm blocks_n_chains.tar.gz
        echo -e "\r\c"

        COUNTER=$((COUNTER+1))
        if [[ "${COUNTER}" -gt 3 ]]
        then
          break;
        fi
      done
      cd ~/ || exit
    fi
    mkdir -p                              /home/"${USRNAME}"/"${DIRECTORY}"/blocks/
    mkdir -p                              /home/"${USRNAME}"/"${DIRECTORY}"/chainstate/
    touch -m ~/"${PROJECT_DIR}"/blocks/
    touch -m ~/"${PROJECT_DIR}"/chainstate/
    cp -r ~/"${PROJECT_DIR}"/blocks/*     /home/"${USRNAME}"/"${DIRECTORY}"/blocks/
    cp -r ~/"${PROJECT_DIR}"/chainstate/* /home/"${USRNAME}"/"${DIRECTORY}"/chainstate/
    chown -R "${USRNAME}:${USRNAME}"      /home/"${USRNAME}"/"${DIRECTORY}"/
  fi

  if [[ ! -d ~/"${PROJECT_DIR}"/blocks/ ]] && [[ ! -z "${DROPBOX_BOOTSTRAP}" ]] && [[ "${USE_DROPBOX_BOOTSTRAP}" -eq 1 ]]
  then
    # Get new bootstrap code.
    if [ ! -f ~/"${PROJECT_DIR}"/bootstrap.dat ] || [[ $(find ~/"${PROJECT_DIR}"/bootstrap.dat -mtime +1 -print) ]]
    then
      mkdir -p ~/"${PROJECT_DIR}"
      cd ~/"${PROJECT_DIR}" || exit

      rm -f ~/"${PROJECT_DIR:?}"/bootstrap.dat
      COUNTER=0
      while [[ ! -f ~/"${PROJECT_DIR}"/bootstrap.dat ]]
      do
        echo "Downloading bootstrap for ${DAEMON_NAME}."
        wget -4qo- https://www.dropbox.com/s/"${DROPBOX_BOOTSTRAP}"/bootstrap.dat.gz?dl=1 -O bootstrap.dat.gz
        gunzip -c bootstrap.dat.gz > ~/"${PROJECT_DIR}"/bootstrap.dat
        chmod 666 ~/"${PROJECT_DIR}"/bootstrap.dat
        rm bootstrap.dat.gz
        echo -e "\r\c"

        COUNTER=$((COUNTER+1))
        if [[ "${COUNTER}" -gt 3 ]]
        then
          break;
        fi
      done
      cd ~/ || exit
    fi
    cp ~/"${PROJECT_DIR}"/bootstrap.dat /home/"${USRNAME}"/"${DIRECTORY}"/bootstrap.dat
    chown -R "${USRNAME}:${USRNAME}"    /home/"${USRNAME}"/"${DIRECTORY}"/
  fi
fi

# Setup systemd to start masternode on restart.
TIMEOUT='30s'
if [[ "${SLOW_DAEMON_START}" -eq 1 ]]
then
  TIMEOUT='240s'
fi

echo "Creating systemd masternode service for ${DAEMON_NAME}"
cat << SYSTEMD_CONF >/etc/systemd/system/"${USRNAME}".service
[Unit]
Description=${DAEMON_NAME} Masternode for user ${USRNAME}
After=network.target

[Service]
Type=forking
User=${USRNAME}
WorkingDirectory=/home/${USRNAME}
PIDFile=/home/${USRNAME}/${DIRECTORY}/${DAEMON_BIN}.pid
ExecStart=/home/${USRNAME}/.local/bin/${DAEMON_BIN} --daemon
ExecStartPost=/bin/sleep 1
ExecStop=/home/${USRNAME}/.local/bin/${CONTROLLER_BIN} stop
Restart=always
RestartSec=${TIMEOUT}
TimeoutSec=${TIMEOUT}

[Install]
WantedBy=multi-user.target
SYSTEMD_CONF
systemctl daemon-reload

# Create function that can control any masternode daemon.
MN_DAEMON_MASTER_FUNC=$(cat << "MN_DAEMON_MASTER_FUNC"
# Start of function for _masternode_dameon_2.
_masternode_dameon_2 () {
  local TEMP_VAR_A
  local TEMP_VAR_B
  local TEMP_VAR_C
  local SP
  RE='^[0-9]+$'
  SP="/-\\|"
  TEMP_VAR_C="${6}"
  if [[ "${TEMP_VAR_C}" == '-1' ]]
  then
    TEMP_VAR_C=''
  fi

  if [ "${9}" == "ps" ]
  then
    # shellcheck disable=SC2009
    TEMP_VAR_A=$( ps axfo user:80,pid,command | grep "${1}\s" | grep "[${4:0:1}]${4:1}" | awk '{print $2 }' )
    ps -up "${TEMP_VAR_A}"

  elif [ "${9}" == "pid" ]
  then
    # shellcheck disable=SC2009
    ps axfo user:80,pid,command | grep "${1}\s" | grep "[${4:0:1}]${4:1}" | awk '{print $2 }'

  elif [ "${9}" == "daemon" ]
  then
    echo "${4}"

  elif [ "${9}" == "full_daemon" ] || [ "${9}" == "daemon_full" ]
  then
    DIR=$(dirname "${5}")
    echo "/home/${1}/.local/bin/${4}"

  elif [ "${9}" == "cli" ]
  then
    echo "${2}"

  elif [ "${9}" == "full_cli" ] || [ "${9}" == "cli_full" ]
  then
    echo "/home/${1}/.local/bin/${2}"

  elif [ "${9}" == "start" ]
  then
    systemctl start "${1}"
    sleep 1
    "${1}" status

  elif [ "${9}" == "forcestart" ]
  then
    if [[ "$( whoami )" == 'root' ]]
    then
      su - "${1}" -c " ${4} --forcestart --daemon "

    elif [[ "$( whoami )" == "${1}" ]]
    then
      DIR=$(dirname "${5}")
      "/home/${1}/.local/bin/${4}" "-datadir=${DIR}/" --forcestart --daemon
    fi

  elif [ "${9}" == "start-nosystemd" ]
  then
    if [[ "$( whoami )" == 'root' ]]
    then
      su - "${1}" -c " ${4} --daemon "

    elif [[ "$( whoami )" == "${1}" ]]
    then
      DIR=$(dirname "${5}")
      "/home/${1}/.local/bin/${4}" "-datadir=${DIR}/" --daemon
    fi

  elif [ "${9}" == "restart" ]
  then
    systemctl restart "${1}"
    sleep 1
    "${1}" status

  elif [ "${9}" == "stop" ]
  then
    TEMP_VAR_A=$( "${1}" pid )
    systemctl stop "${1}"
    if [[ "$( whoami )" == 'root' ]]
    then
      su - "${1}" -c " ${2} stop " >/dev/null 2>&1

    else
      DIR=$(dirname "${5}")
      "/home/${1}/.local/bin/${2}" "-datadir=${DIR}/ stop"
    fi

    if [[ ! -z "${TEMP_VAR_A}" ]]
    then
      kill "${TEMP_VAR_A}" >/dev/null 2>&1
    fi
    DIR=$(dirname "${5}")
    while [[ $( lslocks | grep -c "${DIR}" ) -ne 0 ]]
    do
      echo -e "\r${SP:i++%${#SP}:1} Waiting for ${1} to shutdown \c"
      sleep 0.3
    done
    "${1}" status

  elif [ "${9}" == "status" ]
  then
    systemctl status --no-pager --full "${1}"

  elif [ "${9}" == "remove_daemon" ] || [ "${9}" == "daemon_remove" ]
  then
    seconds=8; date1=$(( $(date +%s) + seconds));
    echo "User ${1} wil be deleted when this timer reaches 0"
    echo "Press ctrl-c to stop"
    while [ "${date1}" -ge "$(date +%s)" ]
    do
      echo -ne "$(date -u --date @$(( date1 - $(date +%s) )) +%H:%M:%S)\r";
    done

    systemctl disable "${1}" -f --now
    rm -f /etc/systemd/system/"${1}".service
    userdel -rfRZ "${1}" 2>/dev/null
    systemctl daemon-reload

  elif [ "${9}" == "reindex" ]
  then
    echo "Stopping ${1}"
    "${1}" stop >/dev/null 2>&1
    sleep 5
    echo "Remove local blockchain database"
    DIR=$(dirname "${5}")
    FILENAME=$(basename "${5}")
    if [ "${10}" == "remove_peers" ] || [ "${10}" == "peers_remove" ] || [ "${11}" == "remove_peers" ] || [ "${11}" == "peers_remove" ]
    then
      find "${DIR}" -maxdepth 1 | tail -n +2 | grep -vE "backups|wallet.dat|${FILENAME}" | xargs rm -r
    else
      find "${DIR}" -maxdepth 1 | tail -n +2 | grep -vE "backups|wallet.dat|${FILENAME}|peers.dat" | xargs rm -r
    fi
    if ([ "${10}" == "remove_addnode" ] || [ "${10}" == "addnode_remove" ] || [ "${11}" == "remove_addnode" ] || [ "${11}" == "addnode_remove" ]) && [ -f "${5}" ]
    then
      echo "${5}"
      sed -i '/addnode\=/d' "${5}"
    fi

    echo "Rebuild local blockchain database"
    if [[ "$( whoami )" == 'root' ]]
    then
      su - "${1}" -c " ${4} --reindex --forcestart --daemon "

    elif [[ "$( whoami )" == "${1}" ]]
    then
      DIR=$(dirname "${5}")
      "/home/${1}/.local/bin/${4}" "-datadir=${DIR}/" --reindex --forcestart --daemon
    fi

    TEMP_VAR_A=$( mpstat 8 1 | awk '$3 ~ /CPU/ { for(i=1;i<=NF;i++) { if ($i ~ /%idle/) field=i } } $3 ~ /all/ { printf("%d",100 - $field) }' )
    while [[ "${TEMP_VAR_A}" -ge 70 ]]
    do
      TEMP_VAR_B=$("${1}" getblockcount 2>/dev/null | tr -d '[:space:]')
      echo -e "\r${SP:i++%${#SP}:1} Blockcount: ${TEMP_VAR_B}\c"
      TEMP_VAR_A=$( mpstat 2 1 | awk '$3 ~ /CPU/ { for(i=1;i<=NF;i++) { if ($i ~ /%idle/) field=i } } $3 ~ /all/ { printf("%d",100 - $field) }' )
    done
    echo "Stopping ${1}"
    "${1}" stop >/dev/null 2>&1
    sleep 5
    "${1}" start

  elif [ "${9}" == "log_system" ] || [ "${9}" == "system_log" ]
  then
    journalctl -u "${1}"

  elif [ "${9}" == "log_daemon" ] || [ "${9}" == "daemon_log" ]
  then
    DIR=$(dirname "${5}")
    if [ "${10}" == "location" ] || [ "${10}" == "loc" ]
    then
      echo "${DIR}/debug.log"
    elif [ -f "${DIR}/debug.log" ]
    then
      cat "${DIR}/debug.log"
    else
      find "${DIR}" -maxdepth 1 -name \*.log  -not -empty -exec cat {} \;
    fi

  elif [ "${9}" == "remove_peers" ] || [ "${9}" == "peers_remove" ]
  then
    DIR=$(dirname "${5}")
    if [ -f "${DIR}/peers.dat" ]
    then
      "${1}" stop
      rm -f "${DIR}/peers.dat"
      sleep 5
      "${1}" start
    fi

  elif ([ "${9}" == "remove_addnode" ] || [ "${9}" == "addnode_remove" ]) && [ -f "${5}" ]
  then
    "${1}" stop
    sed -i '/addnode\=/d' "${5}"
    sleep 5
    "${1}" start

  elif [ "${9}" == "addnode_to_connect" ] && [ -f "${5}" ]
  then
    "${1}" stop
    sed -i -e 's/addnode\=/connect\=/g' "${5}"
    sleep 5
    "${1}" start

  elif [ "${9}" == "connect_to_addnode" ] && [ -f "${5}" ]
  then
    "${1}" stop
    sed -i -e 's/connect\=/addnode\=/g' "${5}"
    sleep 5
    "${1}" start

  elif [ "${9}" == "conf" ] && [ -f "${5}" ]
  then
    if [ "${10}" == "location" ] || [ "${10}" == "loc" ]
    then
      echo "${5}"
    else
      cat "${5}"
    fi

  elif [ "${9}" == "masternode.conf" ] && [ -f "${5}" ]
  then
    PART_A=$( hostname )
    PART_B1=$( grep 'externalip=' "${5}" | cut -d '=' -f2 )
    PART_B2=$( grep 'defaultport=' "${5}" | cut -d '=' -f2 )
    PART_C=$( grep 'masternodeprivkey=' "${5}" | cut -d '=' -f2 )
    PART_D=$( grep 'txhash=' "${5}" | cut -d '=' -f2 )
    PART_E=$( grep 'outputidx=' "${5}" | cut -d '=' -f2 )
    if [ ! -z "${PART_B2}" ]
    then
      PART_B1=$(echo "${PART_B1}" | cut -d ':' -f1)
      PART_B1="${PART_B1}:${PART_B2}"
    fi
    echo
    echo "${1}_${PART_A} ${PART_B1} ${PART_C} ${PART_D} ${PART_E} "
    echo

  elif [ "${9}" == "privkey" ] && [ -f "${5}" ]
  then
    if [ -z "${10}" ]
    then
      grep 'masternodeprivkey=' "${5}" | cut -d '=' -f2
    else
      echo "Stopping ${1}"
      "${1}" stop
      sleep 5
      echo "Reconfiguring ${1}"
      if [[ $(  grep -cF 'masternode=' "${5}") -eq 0 ]]
      then
        echo "masternode=1" >> "${5}"
      fi
      sed -i "/masternodeprivkey/c\masternodeprivkey\=${10}" "${5}"
      if [[ $(  grep -cF 'masternodeprivkey=' "${5}") -eq 0 ]]
      then
        echo "masternodeprivkey=${10}" >> "${5}"
      fi
      echo "Starting ${1}"
      "${1}" start
    fi

  elif [ "${9}" == "rename" ]
  then
    if [ -z "${10}" ]
    then
      (>&2 echo "Please supply the new name after the command.")
      return
    fi
    if id "${10}" >/dev/null 2>&1
    then
      (>&2 echo "Username ${10} already exists.")
      return
    fi

    echo "${1} will be transformed into ${10}"
    sleep 3
    systemctl disable "${1}" -f --now
    "${1}" stop
    sed -i "s/${1}/${10}/g" /etc/systemd/system/"${1}".service
    mv /etc/systemd/system/"${1}".service /etc/systemd/system/"${10}".service
    usermod --login "${10}" --move-home --home /home/"${10}" "${1}"
    groupmod -n "${10}" "${1}"
    sed -i "s/${1}\\//${10}\\//g" /root/.bashrc
    sed -i "s/\"${1}\"/\"${10}\"/g" /root/.bashrc
    sed -i "s/'${1}'/'${10}'/g" /root/.bashrc
    sed -i "s/${1} ()/${10} ()/g" /root/.bashrc
    sed -i "s/${1}\\./${10}\\./g" /root/.bashrc

    source /root/.bashrc
    systemctl daemon-reload 2>/dev/null
    sleep 1
    systemctl enable "${10}"

    sleep 3
    ${10} start
    echo

  elif [ "${9}" == "explorer" ]
  then
    echo "${3}"

  elif [ "${9}" == "explorer_blockcount" ] || [ "${9}" == "blockcount_explorer" ]
  then
    WEBBC=$( wget -4qO- -o- "${3}api/getblockcount" "${TEMP_VAR_C}" )
    echo "${WEBBC}"

  elif [ "${9}" == "chaincheck" ] || [ "${9}" == "checkchain" ]
  then
    WEBBCI=$( wget -4qO- -o- "${3}api/getblockchaininfo" "${TEMP_VAR_C}" | jq . |  grep -v "verificationprogress" )
    BCI=$( "${1}" "getblockchaininfo" 2>&1 | grep -v "verificationprogress" )
    BCI_DIFF=$( diff <( echo "${BCI}" | jq . ) <( echo "${WEBBCI}" | jq . ) )
    if [[ $( echo "${BCI_DIFF}" | tr -d '[:space:]' | wc -c ) -eq 0 ]]
    then
      echo "On the same chain as the explorer"
    else
      echo "Chains do not match"
      echo "${BCI_DIFF}"
      echo "Local blockchain info"
      echo "${BCI}" | jq .
      echo "Remote blockchain info"
      echo "${WEBBCI}" | jq .
    fi

  elif [ "${9}" == "blockcheck" ] || [ "${9}" == "checkblock" ]
  then
    WEBBC=$( wget -4qO- -o- "${3}api/getblockcount" "${TEMP_VAR_C}" )
    BC=$( "${1}" "getblockcount" 2>&1 )
    if ! [[ $WEBBC =~ $RE ]]
    then
      echo "Explorer is down."
      echo "Local blockcount"
      echo "${BC}"
    fi
    if [[ "${WEBBC}" -eq "${BC}" ]]
    then
      echo "On the same block count as the explorer: ${BC}"
    else
      echo "Block counts do not match"
      echo "Local blockcount"
      echo "${BC}"
      echo "Remote blockcount"
      echo "${WEBBC}"
      echo
      echo "If the explorer count is correct and problem persists try"
      echo "${1} remove_peers"
      echo "And after 15 minutes if that does not fix it try"
      echo "${1} reindex"
      echo
    fi

  elif [ "${9}" == "dl_bootstrap" ] || [ "${9}" == "dl_bootstrap_reindex" ]
  then
    DROPBOX_BOOTSTRAP=$( grep 'bootstrap=' "${5}" | cut -d '=' -f2 )
    if [ ! -z "${DROPBOX_BOOTSTRAP}" ]
    then
      echo "Downloading bootstrap."
      DIR=$(dirname "${5}")
      wget -4qo- https://www.dropbox.com/s/"${DROPBOX_BOOTSTRAP}"/bootstrap.dat.gz?dl=1 -O "${DIR}"/bootstrap.dat.gz
      echo "Stopping ${1}"
      "${1}" stop >/dev/null 2>&1
      gunzip -c "${DIR}"/bootstrap.dat.gz > "${DIR}"/bootstrap.dat
      chmod 666 "${DIR}"/bootstrap.dat
      rm -f "${DIR}"/bootstrap.dat.gz
    fi
    if [ "${9}" == "dl_bootstrap_reindex" ]
    then
      "${1}" reindex "${10}" "${11}"
    else
      sleep 5
      "${1}" start
    fi

  elif [ "${9}" == "dl_addnode" ]
  then
    DROPBOX_ADDNODES=$( grep 'nodelist=' "${5}" | cut -d '=' -f2 )
    if [ ! -z "${DROPBOX_ADDNODES}" ]
    then
      echo "Downloading addnode list."
      DIR=$(dirname "${5}")
      ADDNODES=$( wget -4qO- -o- https://www.dropbox.com/s/"${DROPBOX_ADDNODES}"/peers_1.txt?dl=1 | grep 'addnode=' | shuf )
      "${1}" stop
      sed -i '/addnode\=/d' "${5}"
      echo "${ADDNODES}" | tr " " "\\n" >> "${5}"
      sleep 5
      "${1}" start
    fi


  elif [ "${9}" == "addnode_list" ] || [ "${9}" == "list_addnode" ]
  then
    WEBBC=$( wget -4qO- -o- "${3}api/getblockcount" "${TEMP_VAR_C}" )
    LASTBLOCK=$("${1}" getblockcount 2>/dev/null)
    if ! [[ $WEBBC =~ $RE ]]
    then
      echo "Explorer is down."
      echo "Can not generate addnode list."
    elif [[ "${WEBBC}" -ne "${LASTBLOCK}" ]]
    then
      echo "Local blockcount ${LASTBLOCK} and Remote blockcount ${WEBBC} do not match."
      echo "Can not generate addnode list."
    else
      BLKCOUNTL=$((LASTBLOCK-1))
      BLKCOUNTH=$((LASTBLOCK+1))
      ADDNODE_LIST=$( "${1}" getpeerinfo | jq ".[] | select ( .synced_headers >= ${BLKCOUNTL} and .synced_headers <= ${BLKCOUNTH} and .banscore < 60 ) | .addr " | sed 's/\"//g' | sed 's/\:9797//g' | awk '{print "addnode="$1}' )
      if [ "${10}" == "ipv4" ]
      then
        echo "${ADDNODE_LIST}" | grep -v '\=\['
      elif [ "${10}" == "ipv6" ]
      then
        echo "${ADDNODE_LIST}" | grep '\=\[' | cat
      else
        echo "${ADDNODE_LIST}"
      fi
    fi

  elif [ "${9}" == "addnode_console" ] || [ "${9}" == "console_addnode" ]
  then
    WEBBC=$( wget -4qO- -o- "${3}api/getblockcount" "${TEMP_VAR_C}" )
    LASTBLOCK=$("${1}" getblockcount 2>/dev/null)
    if ! [[ $WEBBC =~ $RE ]]
    then
      echo "Explorer is down."
      echo "Can not generate addnode console list."
    elif [[ "${WEBBC}" -ne "${LASTBLOCK}" ]]
    then
      echo "Local blockcount ${LASTBLOCK} and Remote blockcount ${WEBBC} do not match."
      echo "Can not generate addnode console list."
    else
      BLKCOUNTL=$((LASTBLOCK-1))
      BLKCOUNTH=$((LASTBLOCK+1))
      ADDNODE_LIST=$( "${1}" getpeerinfo | jq ".[] | select ( .synced_headers >= ${BLKCOUNTL} and .synced_headers <= ${BLKCOUNTH} and .banscore < 60 ) | .addr " | sed 's/\"//g' | sed 's/\:9797//g' | awk '{print "addnode " $1 " add"}' )
      if [ "${10}" == "ipv4" ]
      then
        echo "${ADDNODE_LIST}" | grep -v '\s\[.*\sadd'
      elif [ "${10}" == "ipv6" ]
      then
        echo "${ADDNODE_LIST}" | grep '\s\[.*\sadd' | cat
      else
        echo "${ADDNODE_LIST}"
      fi
    fi

  else
    if [[ "$( whoami )" == 'root' ]]
    then
      JSON_STRING=$( su - "${1}" -c " ${2} ${9} ${10} ${11} ${12} ${13} ${14} ${15} ${16} ${17} " 2>&1 )
    else
      DIR=$(dirname "${5}")
      JSON_STRING=$( "/home/${1}/.local/bin/${2}" "-datadir=${DIR}/" "${9}" ${10} ${11} ${12} ${13} ${14} ${15} ${16} ${17} 2>&1 )
    fi

    if [ -x "$(command -v jq)" ]
    then
      JSON_ERROR=$( echo "${JSON_STRING}" | jq . 2>&1 >/dev/null )
      if [ -z "${JSON_ERROR}" ]
      then
        echo "${JSON_STRING}" | jq .
      else
        if [[ "${JSON_STRING:0:8}" == "error: {" ]]
        then
          echo "${JSON_STRING:6}" | jq . | sed 's/\\n/\n/g; s/\\t/\t/g; s/\\"/"/g'
        else
          echo "${JSON_STRING}"
        fi
      fi
    else
      echo "${JSON_STRING}"
    fi
  fi
}
# End of function for _masternode_dameon_2.
MN_DAEMON_MASTER_FUNC
)
# Remove double empty lines in the file.
sed -i '/^$/N;/^\n$/D' /root/.bashrc
# Replace _masternode_dameon_2 function if it exists.
# m c a r p e r
FUNC_START=$(grep -Fxn "# Start of function for _masternode_dameon_2." /root/.bashrc | sed 's/:/ /g' | awk '{print $1 }' | sort -r)
FUNC_END=$(grep -Fxn "# End of function for _masternode_dameon_2." /root/.bashrc | sed 's/:/ /g' | awk '{print $1 }' | sort -r)
if [ ! -z "${FUNC_START}" ] && [ ! -z "${FUNC_END}" ]
then
  paste <(echo "${FUNC_START}") <(echo "${FUNC_END}") -d ' ' | while read -r START END
  do
    sed -i "${START},${END}d" /root/.bashrc
  done
fi
# Remove empty lines at end of file.
sed -i -r '${/^[[:space:]]*$/d;}' /root/.bashrc
# Add in _masternode_dameon_2 function.
echo "${MN_DAEMON_MASTER_FUNC}" >> /root/.bashrc
echo "" >> /root/.bashrc

MN_DAEMON_COMP=$(cat << "MN_DAEMON_COMP"
# Start of function for _masternode_dameon_2_completions.
_masternode_dameon_2_completions() {
  LEVEL1=''
  if [[ "${COMP_WORDS[0]}" != 'all_mn_run' ]]
  then
    LEVEL1=$( "${COMP_WORDS[0]}" help | grep -v "\=\=" | awk '{print $1}' )
  fi
  LEVEL1_ALT=' start stop restart ps pid forcestart start-nosystemd status remove_daemon daemon_remove reindex log_system system_log log_daemon daemon_log remove_peers peers_remove remove_addnode addnode_remove addnode_to_connect connect_to_addnode conf masternode.conf privkey rename explorer explorer_blockcount blockcount_explorer chaincheck checkchain blockcheck checkblock dl_bootstrap dl_bootstrap_reindex dl_addnode addnode_list list_addnode addnode_console console_addnode daemon full_daemon daemon_full cli full_cli cli_full '
  LEVEL2=''
  LEVEL3=''

  # keep the suggestions in a local variable
  if [ "${#COMP_WORDS[@]}" == "2" ]
  then
    COMPREPLY=($( compgen -W "$LEVEL1 $LEVEL1_ALT" -- "${COMP_WORDS[1]}" ))
  elif [ "${#COMP_WORDS[@]}" -gt 2 ]
  then
    if [[ "${COMP_WORDS[1]}" == "daemon_log" ]] || \
      [[ "${COMP_WORDS[1]}" == "log_daemon" ]] || \
      [[ "${COMP_WORDS[1]}" == "conf" ]]
    then
      LEVEL2='loc location '

    elif [[ "${COMP_WORDS[1]}" == "addnode_list" ]] || \
      [[ "${COMP_WORDS[1]}" == "list_addnode" ]] || \
      [[ "${COMP_WORDS[1]}" == "addnode_console" ]] || \
      [[ "${COMP_WORDS[1]}" == "console_addnode" ]]
    then
      LEVEL2='ipv4 ipv6 '

    elif [[ "${COMP_WORDS[1]}" == "reindex" ]] || \
      [[ "${COMP_WORDS[1]}" == "dl_bootstrap_reindex" ]]
    then
      if [ "${COMP_WORDS[2]}" == "remove_peers" ] || [ "${COMP_WORDS[2]}" == "peers_remove" ]
      then
        LEVEL3='remove_addnode addnode_remove'
      elif  [ "${COMP_WORDS[2]}" == "remove_addnode" ] || [ "${COMP_WORDS[2]}" == "addnode_remove" ]
      then
        LEVEL3='remove_peers peers_remove'
      else
        LEVEL2='remove_peers peers_remove remove_addnode addnode_remove'
      fi
    fi

    if [[ ! -z "${LEVEL3}" ]] && [ "${#COMP_WORDS[@]}" -eq 4 ]
    then
      COMPREPLY=($( compgen -W "$LEVEL3" -- "${COMP_WORDS[3]}" ))

    elif [[ ! -z "${LEVEL2}" ]] && [ "${#COMP_WORDS[@]}" -eq 3 ]
    then
      COMPREPLY=($( compgen -W "$LEVEL2" -- "${COMP_WORDS[2]}" ))

    fi
  fi
  return 0
}
# End of function for _masternode_dameon_2_completions.
MN_DAEMON_COMP
)
# Replace masternode daemon completions function if it exists.
FUNC_START=$(grep -Fxn "# Start of function for _masternode_dameon_2_completions." /root/.bashrc | sed 's/:/ /g' | awk '{print $1 }' | sort -r)
FUNC_END=$(grep -Fxn "# End of function for _masternode_dameon_2_completions." /root/.bashrc | sed 's/:/ /g' | awk '{print $1 }' | sort -r)
if [ ! -z "${FUNC_START}" ] && [ ! -z "${FUNC_END}" ]
then
  paste <(echo "${FUNC_START}") <(echo "${FUNC_END}") -d ' ' | while read -r START END
  do
    sed -i "${START},${END}d" /root/.bashrc
  done
fi
# Remove empty lines at end of file.
sed -i -r '${/^[[:space:]]*$/d;}' /root/.bashrc
echo "" >> /root/.bashrc
# Add in new masternode daemon function.
echo "${MN_DAEMON_COMP}" >> /root/.bashrc

# Create function that can control the new masternode daemon.
MN_DAEMON_FUNC=$(cat << MN_DAEMON_FUNC
# Start of function for ${USRNAME}.
${USRNAME} () {
  _masternode_dameon_2 "${USRNAME}" "${CONTROLLER_BIN}" "${EXPLORER_URL}" "${DAEMON_BIN}" "/home/${USRNAME}/${DIRECTORY}/${CONF}" "${BAD_SSL_HACK}" "-1" "-1" "\${1}" "\${2}" "\${3}" "\${3}" "\${4}" "\${5}" "\${6}" "\${7}" "\${8}" "\${9}"
}
complete -F _masternode_dameon_2_completions ${USRNAME}
# End of function for ${USRNAME}.
MN_DAEMON_FUNC
)
# Replace new masternode daemon function if it exists.
FUNC_START=$(grep -Fxn "# Start of function for ${USRNAME}." /root/.bashrc | sed 's/:/ /g' | awk '{print $1 }' | sort -r)
FUNC_END=$(grep -Fxn "# End of function for ${USRNAME}." /root/.bashrc | sed 's/:/ /g' | awk '{print $1 }' | sort -r)
if [ ! -z "${FUNC_START}" ] && [ ! -z "${FUNC_END}" ]
then
  paste <(echo "${FUNC_START}") <(echo "${FUNC_END}") -d ' ' | while read -r START END
  do
    sed -i "${START},${END}d" /root/.bashrc
  done
fi
# Remove empty lines at end of file.
sed -i -r '${/^[[:space:]]*$/d;}' /root/.bashrc
echo "" >> /root/.bashrc
# Add in new masternode daemon function.
echo "${MN_DAEMON_FUNC}" >> /root/.bashrc

# Create function that will run the same command on all masternodes.
ALL_MN_RUN=$(cat << "ALL_MN_RUN"
# Start of function for all_mn_run.
all_mn_run () {
  local MN_USRNAME
  find /home/* -maxdepth 0 -type d | tr '/' ' ' | awk '{print $2}' | while read -r MN_USRNAME
  do
    IS_EMPTY=$(type "${MN_USRNAME}" 2>/dev/null)
    if [ ! -z "${IS_EMPTY}" ]
    then
      echo "${MN_USRNAME}"
      ${MN_USRNAME} "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
      echo
    fi
  done
}
# End of function for all_mn_run.
ALL_MN_RUN
)
# Replace all_mn_run. function if it exists.
FUNC_START=$(grep -Fxn "# Start of function for all_mn_run." /root/.bashrc | sed 's/:/ /g' | awk '{print $1 }' | sort -r)
FUNC_END=$(grep -Fxn "# End of function for all_mn_run." /root/.bashrc | sed 's/:/ /g' | awk '{print $1 }' | sort -r)
if [ ! -z "${FUNC_START}" ] && [ ! -z "${FUNC_END}" ]
then
  paste <(echo "${FUNC_START}") <(echo "${FUNC_END}") -d ' ' | while read -r START END
  do
    sed -i "${START},${END}d" /root/.bashrc
  done
fi
# Remove empty lines at end of file.
sed -i -r '${/^[[:space:]]*$/d;}' /root/.bashrc
echo "" >> /root/.bashrc
# Add in new masternode daemon function.
echo "${ALL_MN_RUN}" >> /root/.bashrc

# Load in the bash function into this instance.
if [ -z "${PS1}" ]
then
  PS1="\\"
fi
source /root/.bashrc
if [ "${PS1}" == "\\" ]
then
  PS1=''
fi

# Create conf file.
cat << COIN_CONF >> /home/"${USRNAME}"/"${DIRECTORY}"/"${CONF}"
rpcuser=${RPC_USERNAME}_rpc_${USRNAME}
rpcpassword=${PWA}
rpcallowip=127.0.0.1
rpcport=${PORTA}
server=1
daemon=1
externalip=${PUBIPADDRESS}:${PORTB}
bind=${PRIVIPADDRESS}:${PORTB}
${EXTRA_CONFIG}
# nodelist=${DROPBOX_ADDNODES}
# bootstrap=${DROPBOX_BOOTSTRAP}
COIN_CONF
echo "${ADDNODES}" | tr " " "\\n" >> /home/"${USRNAME}"/"${DIRECTORY}"/"${CONF}"
if [[ "${MULTI_IP_MODE}" -ne 0 ]]
then
  echo "# defaultport=${DEFAULT_PORT}" >> /home/"${USRNAME}"/"${DIRECTORY}"/"${CONF}"
fi
if [ ! -z "${TXHASH}" ]
then
  echo "# txhash=${TXHASH}" >> /home/"${USRNAME}"/"${DIRECTORY}"/"${CONF}"
fi
if [ ! -z "${OUTPUTIDX}" ]
then
  echo "# outputidx=${OUTPUTIDX}" >> /home/"${USRNAME}"/"${DIRECTORY}"/"${CONF}"
fi
if [ ! -z "${MNKEY}" ]
then
  # Add private key to config and make masternode.
  cat << COIN_CONF >> /home/"${USRNAME}"/"${DIRECTORY}"/"${CONF}"
masternode=1
masternodeprivkey=${MNKEY}
COIN_CONF
else
  # Use connect for sync that doesn't drop out.
  sed -i -e 's/addnode\=/connect\=/g' /home/"${USRNAME}"/"${DIRECTORY}"/"${CONF}"
fi

# Run daemon as the user mn1 and update block-chain.
if [ "$(whoami)" != "root" ]
then
  echo
  echo "${USRNAME}"
  echo "${USERPASS}"
  echo
fi
echo
echo -e "\r\c"
stty sane
echo "Starting the daemon."
"${USRNAME}" start >/dev/null 2>&1

DAEMON_LOCK_FILES "${USRNAME}"
DAEMON_CONNECTION_N_BLOCKS_COUNT "${USRNAME}"

# Generate key and stop master node.
if [ -z "${MNKEY}" ]
then
  echo "Generate masternode genkey"
  MNKEY=$( "${USRNAME}" masternode genkey )

  "${USRNAME}" stop >/dev/null 2>&1
  # Add private key to config and make masternode.
  cat << COIN_CONF >> /home/"${USRNAME}"/"${DIRECTORY}"/"${CONF}"
masternode=1
masternodeprivkey=${MNKEY}
COIN_CONF


  if [[ "${DAEMON_CYCLE}" -eq 1 ]]
  then
    echo "Cycling the daemon on and off."
    "${USRNAME}" restart >/dev/null 2>&1
    "${USRNAME}" stop >/dev/null 2>&1
  fi

  # Enable masternode to run on system start.
  systemctl enable "${USRNAME}" 2>&1
  sleep 0.2

  # Start daemon.
  sed -i -e 's/connect\=/addnode\=/g' /home/"${USRNAME}"/"${DIRECTORY}"/"${CONF}"
  echo "Starting the daemon."
  "${USRNAME}" start
  DAEMON_LOCK_FILES "${USRNAME}"

else
  if [[ "${DAEMON_CYCLE}" -eq 1 ]]
  then
    echo "Cycling the daemon on and off."
    "${USRNAME}" restart >/dev/null 2>&1
  fi

  # Enable masternode to run on system start.
  systemctl enable "${USRNAME}" 2>&1
  sleep 0.2
fi

# Wait for daemon.
if [[ "${SLOW_DAEMON_START}" -eq 1 ]]
then
  CPU_USAGE=$(mpstat 1 1 | awk '$3 ~ /CPU/ { for(i=1;i<=NF;i++) { if ($i ~ /%idle/) field=i } } $3 ~ /all/ { printf("%d",100 - $field) }')
  while [[ "${CPU_USAGE}" -gt 50 ]]
  do
    echo -e "\r${SP:i++%${#SP}:1} Waiting for the daemon to be ready \c"
    CPU_USAGE=$(mpstat 1 1 | awk '$3 ~ /CPU/ { for(i=1;i<=NF;i++) { if ($i ~ /%idle/) field=i } } $3 ~ /all/ { printf("%d",100 - $field) }')
    sleep 0.1
  done
fi

# Output firewall info.
echo
ufw status
sleep 1

if [[ ! -z "${MNSYNC_WAIT_FOR}" ]]
then
  while [[ $( "${USRNAME}" mnsync status | grep -cF "${MNSYNC_WAIT_FOR}" ) -eq 0 ]]
  do
    echo -e "\r${SP:i++%${#SP}:1} Waiting for mnsync status to be ${MNSYNC_WAIT_FOR} \c"
    sleep 0.5
  done
fi

# Output masternode info.
"${USRNAME}" masternode debug
sleep 1

SENTINEL_SETUP "${USRNAME}"

if [ ! -z "${TXHASH}" ]
then
  echo "Downloading transaction from the explorer."
  OUTPUTIDX_RAW=$( wget -4qO- -o- "${EXPLORER_URL}api/getrawtransaction?txid=${TXHASH}&decrypt=1" "${BAD_SSL_HACK}" )
  TXID_CONFIRMATIONS=$( echo "${OUTPUTIDX_RAW}" | jq ".confirmations" )
  echo
fi

if [[ "${MULTI_IP_MODE}" -eq 0 ]]
then
  DEFAULT_PORT="${PORTB}"
fi

# Output more info.
echo
echo "Password for ${USRNAME} is"
echo "${USERPASS}"
echo "Commands to control the daemon"
echo "${USRNAME} status"
echo "${USRNAME} start"
echo "${USRNAME} restart"
echo "${USRNAME} stop"
echo
RUNNING_PORTS=$(lslocks | tail -n +2 | awk '{print $2 "/"}' | sort -u | while read -r PID; do  netstat -tulpn | grep "${PID}" | grep -v -E 'tcp6|:25\s' | awk '{print $4}' | cut -d ':' -f2; done)
OPEN_PORTS=$(ufw status | grep -v '(v6)' | tail -n +5 | awk '{print $1}')
BOTH_LISTS=$( sort <( echo "$RUNNING_PORTS" | tr " " "\n") <( echo "$OPEN_PORTS" | tr " " "\n")| uniq -d )
MISSING_FIREWALL_RULES=$( sort <( echo "$RUNNING_PORTS" | tr " " "\n") <( echo "$BOTH_LISTS" | tr " " "\n")| uniq -u )
if [[ $(echo "${MISSING_FIREWALL_RULES}" | wc -w ) -ne 0 ]]
then
  echo "NOTICE: If you are running another masternode on the vps make sure to open any ports needed with this command:"
  lslocks | tail -n +2 | awk '{print $2 "/"}' | sort -u | while read -r PID
  do
    MISSING_FIREWALL_RULE=$( netstat -tulpn | grep "${PID}" | grep -v -E 'tcp6|:25\s' | grep ":${MISSING_FIREWALL_RULES}" | awk '{print $4 "\t\t" $7}' )
    if [ ! -z "${MISSING_FIREWALL_RULE}" ]
    then
      MISSING_PORT=$( echo "${MISSING_FIREWALL_RULE}" | awk '{print $1}' | cut -d ':' -f2 )
      echo "sudo ufw allow ${MISSING_PORT}"
    fi
  done
  echo
fi
echo
echo "Another way to issue commands via ${CONTROLLER_BIN}"
echo "/home/${USRNAME}/.local/bin/${CONTROLLER_BIN} -datadir=/home/${USRNAME}/${DIRECTORY}/"
echo
echo
echo "Check if master node started remotely"
echo "${USRNAME} masternode debug"
echo "${USRNAME} masternode status"
echo
echo "Keep this terminal open until you have started the masternode from your wallet. "
echo "If mn start was successful you should see this message displayed in this shell: "
echo "'masternode ${USRNAME} started remotely'. "
echo "If you do not see that message, then start it again from your wallet."
echo "IP and port daemon is using"
echo -e "${PUBIPADDRESS}:${PORTB}"
echo
echo "masternodeprivkey"
echo -e "\\e[4m${MNKEY}\\e[0m"
echo
if [ ! -z "${TXID_CONFIRMATIONS}" ] && [ "${TXID_CONFIRMATIONS}" -lt 16 ]
then
  echo -e "\\e[4mTXID: ${TXHASH} \\e[0m"
  echo -e "\\e[4mis only ${TXID_CONFIRMATIONS} bolcks old. \\e[0m"
  echo -e "\\e[1;4mWait until the txid is 16 blocks old before starting the mn. \\e[0m"
  echo
fi
echo "Command to start the masternode from the "
echo "desktop/hot/control wallet's debug console:"
echo -e "\\e[1mstartmasternode alias false ${USRNAME}_${MNALIAS}\\e[0m"
echo
# Print masternode.conf string.
if [ ! -z "${TXHASH}" ]
then
  echo "Full string to paste into masternode.conf (all on one line)."
  echo -e "\\e[1;4m${USRNAME}_${MNALIAS} ${PUBIPADDRESS}:${DEFAULT_PORT} ${MNKEY} ${TXHASH} ${OUTPUTIDX}\\e[0m"
  echo "${USRNAME}_${MNALIAS} ${PUBIPADDRESS}:${DEFAULT_PORT} ${MNKEY} ${TXHASH} ${OUTPUTIDX}" >> "${DAEMON_SETUP_INFO}"
else
  echo "There is almost a full string to paste into the masternode.conf file."
  echo -e "Run \\e[4mmasternode outputs\\e[0m and add the txhash and outputidx to the line below."
  echo "The values when done will be all on one line with 4 spaces total."
  echo -e "\\e[1;4m${USRNAME}_${MNALIAS} ${PUBIPADDRESS}:${DEFAULT_PORT} ${MNKEY}\\e[0m"
  echo "${USRNAME}_${MNALIAS} ${PUBIPADDRESS}:${DEFAULT_PORT} ${MNKEY} " >> "${DAEMON_SETUP_INFO}"
fi
echo

if [ -z "${SKIP_CONFIRM}" ] && [[ "${MINI_MONITOR_RUN}" -ne 0 ]]
then
  # Start sub process mini monitor that will exit once masternode has started.
  (
  source /root/.bashrc
  COUNTER=0
  while :
  do
    # Break out of loop if daemon gets deleted.
    if [ ! -f /home/"${USRNAME}"/.local/bin/"${DAEMON_BIN}" ]
    then
      break
    fi

    # Additional checks if the txhash and output index are here.
    if [ ! -z "${TXHASH}" ] && [ ! -z "${OUTPUTIDX}" ]
    then
      # Check the collateral once every 2 minutes.
      COUNTER=$(( COUNTER - 1 ))
      if [[ ${COUNTER} =~ ${RE} ]] && [[ "${COUNTER}" -eq 24 ]]
      then
        COUNTER=0
        OUTPUTIDX_RAW=$( wget -4qO- -o- "${EXPLORER_URL}api/getrawtransaction?txid=${TXHASH}&decrypt=1" "${BAD_SSL_HACK}" )
        MN_WALLET_ADDR=$( echo "$OUTPUTIDX_RAW" | jq -r ".vout[] | select( .n == ${OUTPUTIDX} ) | .scriptPubKey.addresses | .[] " )
        MN_WALLET_ADDR_DETAILS=$( wget -4qO- -o- "${EXPLORER_URL}ext/getaddress/${MN_WALLET_ADDR}" "${BAD_SSL_HACK}" )
        MN_WALLET_ADDR_BALANCE=$( echo "${MN_WALLET_ADDR_DETAILS}" | jq -r ".balance" )

        if [[ $( echo "${MN_WALLET_ADDR_BALANCE}<${COLLATERAL}" | bc ) -eq 1 ]]
        then
          echo
          echo "txhash no longer holds the collateral; moved: ${TXHASH}."
          echo
          TXHASH=''
          OUTPUTIDX=''
          continue
        fi

        # Make sure it didn't get staked.
        TXIDS_AFTER_COLLATERAL=$( echo "${MN_WALLET_ADDR_DETAILS}" | jq -r ".last_txs[][] " | grep -vE "vin|vout" | sed -n -e "/${TXHASH}/,\$p" | grep -v "${TXHASH}" )
        if [ ! -z "${TXIDS_AFTER_COLLATERAL}" ]
        then
          # Check each tx after the given tx to see if it was used as an input.
          while read -r OTHERTXIDS
          do
            OUTPUTIDX_RAW=$( wget -4qO- -o- "${EXPLORER_URL}api/getrawtransaction?txid=${OTHERTXIDS}&decrypt=1" "${BAD_SSL_HACK}" )
            if [[ $( echo "$OUTPUTIDX_RAW" | jq ".vin[] | select( .txid == \"${TXHASH}\" )" | wc -c ) -gt 0 ]]
            then
              echo
              echo "txid no longer holds the collateral; staked: ${TXHASH}."
              echo
              TXHASH=''
              OUTPUTIDX=''
              break
            fi
          done <<< "${TXIDS_AFTER_COLLATERAL}"
        fi
      fi

      # Check txhash and output index for negative active time.
      if [[ "${MINI_MONITOR_MN_LIST}" -eq 1 ]]
      then
        MNACTIVETIME=$( "${USRNAME}" masternode list 2>/dev/null | \
          jq --arg OUTPUTIDX "${OUTPUTIDX}" --arg TXHASH "${TXHASH}" \
          ".[] | select( .txhash == \"${TXHASH}\" and .outidx == ${OUTPUTIDX} ) | .activetime" )
        if [ ! -z "${MNACTIVETIME}" ] && [ "${MNACTIVETIME}" -lt "0" ]
        then
          echo "${USRNAME}_${MNALIAS}"
          echo "Start masternode again from desktop wallet."
          echo "Please wait for your transaction to be older than 16 blocks and try again."
          echo "You might need to restart the daemon by running this on the vps"
          echo
          echo "systemctl restart ${USRNAME}"
          echo
          echo "Activetime for the masternode was negative ${MNACTIVETIME}"
           "${USRNAME}" masternode list 2>/dev/null | \
            jq --arg OUTPUTIDX "${OUTPUTIDX}" --arg TXHASH "${TXHASH}" \
            ".[] | select( .txhash == \"${TXHASH}\" and .outidx == ${OUTPUTIDX} )"
          echo
          sleep 60
        fi
      fi
    fi

    # Check status number.
    MNSTATUS=$("${USRNAME}" masternode status 2>/dev/null | jq -r '.status' 2>/dev/null)
    if [ ! -z "${MNSTATUS}" ] && [ "${MNSTATUS}" == "${MINI_MONITOR_MN_STATUS}" ]
    then
      MNCOUNT=$( "${USRNAME}" masternode count 2>/dev/null )
      if [[ "${MINI_MONITOR_MN_COUNT_JSON}" -eq 1 ]]
      then
        MNCOUNT=$( echo "${MNCOUNT}" | jq -r '.total' 2>/dev/null )
      fi
      echo
      "${USRNAME}" masternode status
      echo
      echo -e "\\e[1;4m Masternode ${USRNAME} successfully started! \\e[0m"
      echo "This is masternode number ${MNCOUNT} in the network."
      if [[ "${MINI_MONITOR_MN_QUEUE}" -eq 1 ]]
      then
        MNHOURS=$( echo "${MNCOUNT} * 0.051" | bc )
        printf "First payout will be in approximately %.*f hours\\n" 1 "${MNHOURS}"
      fi
      echo
      echo "Press Enter to continue"
      echo
      break
    fi
    sleep 5

  done
  exit
  ) & disown
fi
stty sane
sleep 1
# End of masternode setup script.


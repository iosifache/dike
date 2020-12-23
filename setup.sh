#!/bin/bash

# Requirements:
# - a server SSH key added on the GitHub repository, for this server
# - a user under which the infrastructure will be create

# Check if script was ran as root
if [ `whoami` != root ]; then
    echo "[!] Please run this script as root or using sudo"
    exit 1
fi

# Check number of arguments
if [ "$#" -ne 1 ]; then
  echo "[+] Usage for script: $0 USERNAME" >&2
  exit 1
fi

# Check if given users exists
grep -c "^$1:" /etc/passwd &>/dev/null
RES=$?
if [ $RES -eq 1 ]; then
    echo "[!] The given username does't correspond to an existent user on this machine"
    exit 1
fi

# Clone the repository inside user home
cd /home/$1
git clone git@github.com:iosifache/dike.git

# Create the infrastructure
cd /home/$1/infrastructure
sudo docker-compose -p dike build --force-rm --no-cache && sudo docker-compose -p dike up --detach

# Add alias for running the app from leader container
echo -e "\n\n# Alias for running dike's app from the leader server\nalias dike=\"sudo docker exec -w /dike/dike/master -it dike_master_1 python app.py\"" >> /home/$1/.bashrc
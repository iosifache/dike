#!/bin/bash

# Script for setting up, update or destroy dike's infrastructure

print_help_and_exit(){

    echo -e "[+] The script's help is listed below.\n\n\
Usage:\n\
\t$0 ACTION_OPTION USERNAME\n\n\
Available action options (for parameter ACTION_OPTION) are:\n\
- build;\n\
- update; and\n\
- destroy.\n\n\
Requirements are:\n\
- a SSH key added on the GitHub repository, generated on this server; and\n\
- a user under which the infrastructure will be created this script." >&2

    exit 1

}

build_infrastructure(){

    # Clone the repository inside user home
    cd /home/$1
    git clone git@github.com:iosifache/dike.git

    # Create the infrastructure
    cd /home/$1/dike/infrastructure
    sudo docker-compose -p dike build --force-rm --no-cache && \
sudo docker-compose -p dike up --detach

    # Add alias for running the app from leader container
    echo -e "\n\n# Alias for running dike's app from the leader server\n\
alias dike=\"sudo docker exec -w /dike/dike/master \
-it dike_master_1 python app.py\"" >> /home/$1/.bashrc

}

destroy_infrastructure(){

    # Put down the infrastructure
    cd /home/$1/infrastructure
    sudo docker-compose down

    # Remove all files used by the platform
    # TODO(@iosifache): Backup the important files and folder before removing
    # the whole infrastructure
    cd /
    rm -rf /home/$1/dike

}

update_infrastructure(){

    destroy_infrastructure
    build_infrastructure

}

# Check if script is run as root
if [ `whoami` != root ]; then
    echo "[!] Please run this script as root or using sudo."
    print_help_and_exit
fi

# Check number of arguments
if [ "$#" -ne 2 ]; then
    echo "[!] Invalid number of arguments."
    print_help_and_exit
fi

# Check if given user exists
grep -c "^$2:" /etc/passwd &>/dev/null
RES=$?
if [ $RES -eq 1 ]; then

    echo "[!] The given username does't correspond to an existent user on \
this machine."

    print_help_and_exit

fi

# Check the given option
if [ $1 == "build" ]; then
    build_infrastructure
elif [ $1 == "update" ]; then
    update_infrastructure
elif [ $1 == "destroy" ]; then
    destroy_infrastructure
else
    echo "[!] Invalid action to run."
    print_help_and_exit
fi

# If this point is reached, the option was valid and the operation successful
echo "[+] Operation finished successfully!"
#!/bin/bash
#
# Script for setting up, updating, or destroying the dike's infrastructure

# Constant
readonly DIKE_HOME=/opt/dike
readonly GHIDRA_HOME=/opt/ghidra
readonly BACKUP_LOCATION=/var/backups/dike-data.tar.gz
readonly FONT_COLOR_BLUE="\e[0;94m"
readonly FONT_COLOR_GREEN="\e[0;92m"
readonly FONT_COLOR_RED="\e[0;91m"
readonly FONT_RESET="\e[0m"

# Function for logging an information
log_info(){
  local message="$1"

  echo -ne "${FONT_COLOR_BLUE}[i]${FONT_RESET} $message"
}

# Function for logging a success message
log_success(){
  local message="$1"

  echo -ne "${FONT_COLOR_GREEN}[+]${FONT_RESET} $message"
}

# Function for logging an error message
log_error(){
  local message="$1"

  echo -ne "${FONT_COLOR_RED}[!]${FONT_RESET} $message"
}

# Function for loggins an error message and exiting
log_error_and_exit(){
  log_error "An error occured. The script is exiting."

  exit 1
}

# Function for data folder backup
backup_data(){
  tar -czvf $BACKUP_LOCATION $DIKE_HOME/data
}

# Function for restoring the data folder backup
restore_data_backup(){
  if [ -e $BACKUP_LOCATION ]
  then
    tar -xzf $BACKUP_LOCATION -C $DIKE_HOME/data
  else
    log_error "A backup file for the data folder does not exists.\n"
  fi
}

# Function for installing the required software
install_required_software(){
  # Check if Docker is installed
  if ! docker --version &> /dev/null
  then
    log_info "Docker will be installed."

    # Install Docker
    apt-get install apt-transport-https ca-certificates curl gnupg lsb-release
    curl -fsSL https://download.docker.com/linux/debian/gpg \
      | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-\
archive-keyring.gpg] https://download.docker.com/linux/debian\
$(lsb_release -cs) stable" \
      | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
      apt-get update
      apt-get install docker-ce docker-ce-cli containerd.io

      log_success "Docker was installed.\n"
  else
    log_success "Docker is already installed.\n"
  fi

  # Check if Docker Compose is installed
  if ! docker-compose --version &> /dev/null
  then
    log_info "Docker Compose will be installed.\n"

    # Install Docker Compose
    curl -s --output /dev/null -L "https://github.com/docker/compose/releases/\
download/1.29.0/docker-compose-$(uname -s)-$(uname -m)"\
 -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose

    log_success "Docker Compose was installed.\n"
  else
    log_success "Docker Compose is already installed.\n"
  fi

  # Check if Ghidra is installed
  if [ ! -d "$GHIDRA_HOME" ]
  then
    log_info "Ghidra will be installed.\n"

    # Install Ghidra
    wget https://ghidra-sre.org/ghidra_9.2.2_PUBLIC_20201229.zip\
 -O /tmp/ghidra.zip
    unzip /tmp/ghidra.zip -d /opt/
    mv /opt/ghidra* $GHIDRA_HOME

    log_success "Ghidra was installed.\n"
  else
    log_success "Ghidra is already installed.\n"
  fi

}

# Function for building the infrastructure
build_infrastructure(){

  local username="$1"

  # Clone the repository inside the user home and create a symbolic link
  cd /home/"$username" || log_error_and_exit
  git clone --recurse-submodules git@github.com:iosifache/dike.git
  ln -s DIKE_HOME/dike $DIKE_HOME

  # Create the required files and folders
  mkdir $DIKE_HOME/data/dataset/files/collected
  mkdir $DIKE_HOME/data/dataset/labels/custom
  touch $DIKE_HOME/data/dataset/others/malware_hashes.txt

  # Read the VirusTotal API key
  log_info "The VirusTotal API key is: "
  read -r vt_api_key
  echo "vt_api_key: $vt_api_key" > $DIKE_HOME/data/configuration/_secrets.yaml

  # Get the archive containing the subordinate data
  log_info "The URL where the subordinate data archive will be downloaded\
 from is: "
  read -r archive_url
  wget -q -O /tmp/subordinate-data.tar.gz "$archive_url"
  tar -xzf /tmp/subordinate-data.tar.gz -C $DIKE_HOME/data/subordinate

  # Modify the OpenSSL configuration to support TLS 1.0/1.1
  sed -i "1s/^/openssl_conf = default_conf\n\n/" /etc/ssl/openssl.cnf
  echo -e "\n\n[ default_conf ]\nssl_conf = ssl_sect\n\n[ssl_sect]\n\
system_default = ssl_default_sect\n\n[ssl_default_sect]\nMinProtocol = None\n\
CipherString = DEFAULT:@SECLEVEL=1\n" >> /etc/ssl/openssl.cnf

  # Create a certificate
  su "$username" -c "openssl req -x509 -newkey rsa:4096 -nodes\
 -out $DIKE_HOME/data/keystore/certificate.pem\
 -keyout $DIKE_HOME/data/keystore/key.pem -days 365\
 -subj \"/C=/ST=/L=/O=/OU=/CN=dike\"" &> /dev/null
  log_success "A certificate and its corresponding key were generated.\n"

  # Install the required software
  install_required_software

  # Create the infrastructure
  cd $DIKE_HOME/infrastructure || log_error_and_exit
  sudo docker-compose -p dike build -q --force-rm --no-cache && \
sudo docker-compose -p dike up --detach > /dev/null 2>&1
  log_success "The infrastructure was set up.\n"

  # Add a cronjob for periodically updating the platform
  log_info "The crontab schedule expression that indicates the interval of\
 updating the platform is: "
  read -r crontab_string
  echo "$crontab_string sudo $DIKE_HOME/infrastructure/manage.sh update\
 $username" | sudo crontab -

  # Add an alias for running the app from the leader container
  echo -e "\n# Alias for running dike's app from the leader server\n\
alias dike=\"sudo docker exec -w /opt/dike/codebase \
-it leader python servers/leader/app.py\"" >> /home/"$username"/.profile
  source ~/.profile

  # Redo the backup data folder if it exists
  restore_data_backup "$username"

  # Add the leader server IP to hosts
  sed -i "1s/^/192.168.0.100\tdike\n/" /etc/hosts

}

# Function for destroying the infrastructure
destroy_infrastructure(){

  local username="$1"

  # Put down the infrastructure
  cd $DIKE_HOME/infrastructure || log_error_and_exit
  sudo docker-compose -p dike down
  cd /

  # Backup
  backup_data "$username"

  # Delete the symbolic link and the cloned folder
  rm -rf $DIKE_HOME
  rm -rf /home/"$1"/dike


}

# Function for updating the infrastructure
update_infrastructure(){

  local username="$1"

  # Fetch the remote repository
  cd $DIKE_HOME || log_error_and_exit
  git fetch

  # Check if an update is available
  if [ "$(git rev-parse HEAD)" != "$(git rev-parse @{u})" ]
  then
    destroy_infrastructure "$username"
    build_infrastructure "$username"
  else
    log_info "No update is available.\n"
  fi

}

# Function for printing the manual and exiting the script
print_manual_and_exit(){

  log_info "The script's manual is listed below.\n
Usage:
\t$0 ACTION USERNAME\n
Available actions (for parameter ACTION) are:
- build;
- update; and
- destroy.\n
Requirements are:
- a pair of a private and an SSH key, the last one being added on the GitHub \
repository as a deploy key;
- a user (for parameter USERNAME) under which the infrastructure will be \
created; and
- a web server, serving the subordinate-data.tar.gz archive (containing a \
Ghidra project created by the root user and a Windows dump of the DLLs and \
the Registry).\n" >&2

  exit 1

}

main(){

  # Check if the script is run as root
  if [ "$(whoami)" != root ]; then
    log_error "The required permissions are not offered. Please run the script\
 as root.\n"
    print_manual_and_exit
  fi

  # Check the number of and get the arguments
  if [ "$#" -ne 2 ]; then
    log_error "The number of arguments is invalid.\n"
    print_manual_and_exit
  fi
  local action="$1"
  local username="$2"

  # Check if given user exists
  grep -c "^$username:" /etc/passwd &> /dev/null
  RES=$?
  if [ $RES -eq 1 ]; then
    log_error "The given username does not correspond to an existent user on\
 this machine.\n"
    print_manual_and_exit
  fi

  # Check the given option
  if [ "$action" == "build" ]
  then
    build_infrastructure "$username"
  elif [ "$action" == "update" ]
  then
    update_infrastructure "$username"
  elif [ "$action" == "destroy" ]
  then
    destroy_infrastructure "$username"
  else
    log_error "The action to run is invalid.\n"
    print_manual_and_exit
  fi

  # If this point is reached, the option was valid and the operation successful
  log_success "The operation was completed successfully.\n"

}

main "$@"
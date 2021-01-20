#!/usr/bin/env python3
"""Script running dike's software for subordinate servers on this machine

The scrips uses the user configuration to create a threaded server. This is used
to wait for and respond to RPC calls from the master.
"""

# Libraries
from rpyc.utils.server import ThreadPoolServer
from subordinate.services import SubordinateService
import os
import sys
from utils.configuration import ConfigurationWorker, ConfigurationSpace

# Add parent folder to path
current_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Configuration for RPyC's ThreadPoolServer
CONFIGURATION = {
    "allow_public_attrs": True,
}


def main():

    # Get configuration
    config = ConfigurationWorker("../configuration/user/config.yaml")
    server_config = config.get_configuration_space(
        ConfigurationSpace.SUBORDINATE_SERVER)

    # Create new server and start service
    server = ThreadPoolServer(SubordinateService,
                              hostname=server_config["hostname"],
                              port=server_config["port"],
                              protocol_config=CONFIGURATION)
    server.service.ALIASES.append(server_config["service_name"])
    server.start()


main()
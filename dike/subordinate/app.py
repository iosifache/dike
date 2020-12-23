#!/usr/bin/env python3

# Add parent folder to path
import os
import sys
current_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Libraries
from rpyc.utils.server import ThreadPoolServer
from services import ModelBuilderService
import sys
from utils.configuration import ConfigurationWorker, ConfigurationSpace

CONFIGURATION = {
    "allow_public_attrs": True,
}


def main():

    # Get configuration
    config = ConfigurationWorker("../config.yaml")
    server_config = config.get_configuration_space(
        ConfigurationSpace.SUBORDINATE_SERVER)

    # Create new server and start service
    server = ThreadPoolServer(ModelBuilderService,
                              hostname=server_config["hostname"],
                              port=server_config["port"],
                              protocol_config=CONFIGURATION)
    server.service.ALIASES.append(server_config["service_name"])
    server.start()


main()
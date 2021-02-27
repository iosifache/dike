#!/usr/bin/env python3
"""Script running dike's software for subordinate servers on this machine.

The scrips uses the user configuration to create a threaded server. This is
used to wait for and respond to RPC calls from the master.
"""

from rpyc.modules.utils.helpers import classpartial
from rpyc.modules.utils.server import ThreadPoolServer
from subordinate.services import SubordinateService
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker

# Configuration for RPyC's ThreadPoolServer
CONFIGURATION = {
    "allow_public_attrs": True,
}


def main():
    """Main function"""

    # Get configuration
    config = ConfigurationWorker("../configuration/user/config.yaml")
    server_config = config.get_configuration_space(
        ConfigurationSpace.SUBORDINATE_SERVER)
    dataset_builder_config = config.get_configuration_space(
        ConfigurationSpace.DATASET_BUILDER)

    # Create new service, server and start the server
    service = classpartial(SubordinateService, server_config["service_name"],
                           dataset_builder_config["malware_families"],
                           dataset_builder_config["malware_benign_vote_ratio"],
                           dataset_builder_config["min_ignored_percent"])
    server = ThreadPoolServer(service,
                              hostname=server_config["hostname"],
                              port=server_config["port"],
                              protocol_config=CONFIGURATION)
    server.start()


main()

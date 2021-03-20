#!/usr/bin/env python3
"""Script running dike's software for subordinate servers on this machine.

The scrips uses the user configuration to create a threaded server. This is
used to wait for and respond to RPC calls from the master.
"""

from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker
from modules.utils.logger import Logger
from rpyc import ThreadPoolServer
from servers.subordinate.services import SubordinateService

# Configuration for RPyC's ThreadPoolServer
CONFIGURATION = {
    "allow_all_attrs": True,
}


def main():
    """Runs the server."""
    # Enable the logger and set it for internal buffering
    Logger().set_enable(enable=True)
    Logger().set_internal_buffering()

    # Get configuration
    config = ConfigurationWorker()
    server_config = config.get_configuration_space(
        ConfigurationSpace.SUBORDINATE_SERVER)

    # Create new service, server and start the server
    server = ThreadPoolServer(SubordinateService,
                              hostname=server_config["hostname"],
                              port=server_config["port"],
                              protocol_config=CONFIGURATION)
    server.start()


main()

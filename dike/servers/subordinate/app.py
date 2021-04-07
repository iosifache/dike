#!/usr/bin/env python3
"""Subordinate server main script.

Usage:
    ./app.py
"""
from modules.configuration.folder_structure import Files
from modules.utils.configuration_manager import ConfigurationManager
from modules.utils.logger import Logger
from modules.utils.types import ConfigurationSpaces
from rpyc import ThreadPoolServer
from rpyc.utils.authenticators import SSLAuthenticator
from servers.subordinate.services import SubordinationService

RPYC_CONFIGURATION = {
    "allow_all_attrs": True,
}


def main():
    """Main function."""
    Logger().enable(is_enabled=True)
    Logger().set_internal_buffering()

    configuration = ConfigurationManager()
    server_config = configuration.get_space(
        ConfigurationSpaces.SUBORDINATE_SERVER)
    hostname = server_config["hostname"]
    port = server_config["port"]

    authenticator = SSLAuthenticator(Files.SSL_PRIVATE_KEY,
                                     Files.SSL_CERTIFICATE)
    server = ThreadPoolServer(SubordinationService,
                              hostname=hostname,
                              port=port,
                              protocol_config=RPYC_CONFIGURATION,
                              authenticator=authenticator)
    server.start()


if __name__ == "__main__":
    main()

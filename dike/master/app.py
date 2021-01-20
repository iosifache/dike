#!/usr/bin/env python3
"""Script running dike's software for master server on this machine"""

from riposte import Riposte
import emojis
import sys
from subordinate_leader import SubordinateLeader
from utils.configuration import ConfigurationWorker, ConfigurationSpace

# Check if a cold run is needed
if (len(sys.argv) > 1 and sys.argv[1] == "exit"):
    sys.exit(0)

# Get configuration
config = ConfigurationWorker("../configuration/user/config.yaml")
master_config = config.get_configuration_space(
    ConfigurationSpace.MASTER_SERVER)
subordinate_config = config.get_configuration_space(
    ConfigurationSpace.SUBORDINATE_SERVER)

# Create command-line interface
banner = master_config["cli"]["banner"]
prompt = master_config["cli"]["prompt"] + emojis.encode(" :wavy_dash: ")
cli = Riposte(prompt=prompt, banner=banner)

# Initialize of the subordinate leader
leader = SubordinateLeader(subordinate_config["port"],
                           subordinate_config["service_name"],
                           master_config["answers_checking_interval"])


@cli.command("connect_to_server")
def connect_to_server(host: str, port: int):
    """Functionality and parameters detailed in
    SubordinateLeader.connect_to_server method"""
    leader.connect_to_server(host, port)


@cli.command("connect_to_all_servers")
def connect_to_all_servers(network: str):
    """Functionality and parameters detailed in
    SubordinateLeader.connect_to_all_servers method"""
    leader.connect_to_all_servers(network)


@cli.command("disconnect_from_server")
def disconnect_from_server(host: str, port: int):
    """Functionality and parameters detailed in
    SubordinateLeader.disconnect_from_server method"""
    leader.disconnect_from_server(host, port)


@cli.command("disconnect_from_all_servers")
def disconnect_from_all_servers():
    """Functionality and parameters detailed in
    SubordinateLeader.disconnect_from_all_servers method"""
    leader.disconnect_from_all_servers()


@cli.command("list_connections")
def list_connections():
    """Functionality and parameters detailed in
    SubordinateLeader.list_connections method"""
    leader.list_connections()


@cli.command("train_model_by_skeleton")
def train_model_by_skeleton():
    """Functionality and parameters detailed in
    SubordinateLeader.train_model_by_skeleton method"""
    leader.train_model_by_skeleton()


@cli.command("quit")
def quit():
    """Exits the command-line interface.
    """
    if leader:
        leader.disconnect_from_all_servers()
    exit(0)


# Run the CLI
cli.run()
#!/usr/bin/env python3

from riposte import Riposte
import emojis
import sys
from subordinate_leader import SubordinateLeader
from utils.configuration import ConfigurationWorker, ConfigurationSpace

# Check if a cold run is needed
if (len(sys.argv) > 1 and sys.argv[1] == "exit"):
    sys.exit(0)

# Get configuration
config = ConfigurationWorker("../configuration/config.yaml")
master_config = config.get_configuration_space(
    ConfigurationSpace.MASTER_SERVER)
subordinate_config = config.get_configuration_space(
    ConfigurationSpace.SUBORDINATE_SERVER)

# Create command line interface
banner = master_config["cli"]["banner"]
prompt = master_config["cli"]["prompt"] + emojis.encode(" :wavy_dash: ")
cli = Riposte(prompt=prompt, banner=banner)

# Initialize of the subordinate leader
leader = SubordinateLeader(subordinate_config["port"],
                           subordinate_config["service_name"],
                           master_config["answers_checking_interval"])


# Define CLI command for connecting to a specific server
@cli.command("connect_to_server")
def connect_to_server(host: str, port: int):
    leader.connect_to_server(host, port)


# Define CLI command for connecting to all available servers
@cli.command("connect_to_all_servers")
def connect_to_all_servers(network: str):
    leader.connect_to_all_servers(network)


# Define CLI command for disconnecting to a specific server
@cli.command("disconnect_from_server")
def disconnect_from_server(host: str, port: int):
    leader.disconnect_from_server(host, port)


# Define CLI command for disconnecting to all available servers
@cli.command("disconnect_from_all_servers")
def disconnect_from_all_servers():
    leader.disconnect_from_all_servers()


# Define CLI command for listing all connections
@cli.command("list_connections")
def list_connections():
    leader.list_connections()


# Define CLI command for training a model
@cli.command("train_model_by_skeleton")
def train_model_by_skeleton():
    leader.train_model_by_skeleton()


# Define CLI command for exitting the program
@cli.command("quit")
def quit():
    if leader:
        leader.disconnect_from_all_servers()
        leader.stop()
    exit(0)


# Run the CLI
cli.run()
#!/usr/bin/env python3
"""Leader server main script.

Usage:
    ./app.py
"""
import os
import sys
import typing
import warnings

import emojis
import mydocstring
import pandas
from modules.configuration.parameters import Servers
from modules.utils.configuration_manager import ConfigurationManager
from modules.utils.errors import Error
from modules.utils.logger import Logger
from modules.utils.types import ConfigurationSpaces, LoggedMessageTypes
from riposte import Riposte
from servers.leader.dispatcher import Dispatcher
from tabulate import tabulate

LEADER_CONFIG = Servers.Leader

# The variables are global, not constants. pylint: disable=invalid-name
configuration = ConfigurationManager()
leader_config = configuration.get_space(ConfigurationSpaces.LEADER_SERVER)
subordinate_config = configuration.get_space(
    ConfigurationSpaces.SUBORDINATE_SERVER)

# Create the banner by indenting the join of the logo and of the description
banner = leader_config["cli"]["banner"].replace("\\n", "")
banner = " " + " ".join(banner.splitlines(True))

# Get the other elements required by the CLI
prompt = emojis.encode(leader_config["cli"]["prompt"])
log_line_prefix = leader_config["cli"]["log_line_prefix"]
max_string_len = leader_config["cli"]["max_string_len"]
overflow_replacement = leader_config["cli"]["overflow_replacement"]

# Disable all warnings
warnings.filterwarnings("ignore")

# Create the command-line interface
cli = Riposte(prompt=prompt, banner=banner)

# Initialize the dispatcher
leader = Dispatcher()

# Enable the logging
Logger().enable()


def wrapped_command(start_log: str = None,
                    end_log: str = None) -> typing.Callable:
    """Ensures the healthy lifecycle of a CLI command.

    It performs the following operations:
    - logging the beginning and the finish of execution;
    - calling the method from the corresponding Dispatcher object;
    - returning the result to the decorated function for further processing (
    for example, prints); and
    - catching errors.

    Args:
        start_log (str): Logging message for execution start. Defaults to None.
        end_log (str): Logging message for execution finish. Defaults to None.

    Returns:
        typing.Callable: Decorator
    """

    def inner_decorator(function: typing.Callable):

        def wrapper(*args, **kwargs):
            try:
                # Log the beginning of the execution
                if start_log:
                    Logger().log(start_log, LoggedMessageTypes.BEGINNING)

                # Get the function from the Dispatcher and execute it with the
                # given parameter
                result = getattr(leader, function.__name__)(*args, **kwargs)

                # Log the end of the execution
                if end_log:
                    Logger().log(end_log, LoggedMessageTypes.END)

                # After having the result from the Dispatcher, pass the result
                # to the function on which the decorator is applied
                function_result = function(*args, **kwargs, result=result)

                return function_result

            except Error as error:

                # Log error
                Logger().log(str(error), LoggedMessageTypes.ERROR)

                return None

            except TypeError:

                # Log error
                Logger().log(("The number of parameters is invalid. "
                              "Verify the command manual."),
                             LoggedMessageTypes.ERROR)

                return None

        return wrapper

    return inner_decorator


# The arguments of all following functions are passed by riposte and processed
# into the decorator by calling the corresponding function from the dispatcher.
# pylint: disable=unused-argument


@cli.command(LEADER_CONFIG.CLICommands.CREATE_CONNECTION)
@wrapped_command()
def create_connection(host: str, port: int, result: bool = None) -> None:
    """Creates a connection with a subordinate server.

    Args:
        host (str): IP address
        port (int): Port
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log(
                "A new connection with the subordinate server was established.",
                LoggedMessageTypes.SUCCESS)
        else:
            Logger().log(("The connection with the subordinate "
                          "server could not be established."),
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.CREATE_CONNECTIONS)
@wrapped_command()
def create_connections(network: str, port: int, result: int = None) -> None:
    """Creates connections with all subordinate servers found in a network.

    Args:
        network (str): Network's CIDR notation
        port (int): Port
        result (int): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result != 0:
            Logger().log(
                "{} new connections with subordinate servers were established."
                .format(result), LoggedMessageTypes.SUCCESS)
        else:
            Logger().log(("No new connection with subordinate "
                          "servers could be established."),
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.LIST_CONNECTIONS)
@wrapped_command()
def list_connections(result: typing.List[typing.List] = None) -> None:
    """Lists the connections with the subordinate servers.

    Args:
        result (typing.List[typing.List]): Result received from the decorator.
            Defaults to None.
    """
    if result is not None:
        if len(result) != 0:
            headers = ["ID", "Host", "Port", "Employment State"]
            table = tabulate(result, headers=headers, tablefmt="grid")

            Logger().log(
                ("The active connections with "
                 "the subordinate servers are:\n\n{}\n").format(table),
                LoggedMessageTypes.INFORMATION)
        else:
            Logger().log(
                "No connection with subordinate servers has been set so far.",
                LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.REMOVE_CONNECTION)
@wrapped_command()
def remove_connection(connection_id: int, result: bool = None) -> None:
    """Remove a connection with a subordinate server.

    Args:
        connection_id (int): Connection ID
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log(
                "The connection with the subordinate server was broken.",
                LoggedMessageTypes.SUCCESS)
        else:
            Logger().log(("The connection with the subordinate "
                          "server could not be broken."),
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.REMOVE_ALL_CONNECTIONS)
@wrapped_command()
def remove_all_connections(result: int = None) -> None:
    """Removes all connections with the subordinate servers.

    Args:
        result (int): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result != 0:
            Logger().log(
                "{} connections with subordinate servers were broken.".format(
                    result), LoggedMessageTypes.SUCCESS)
        else:
            Logger().log("No connection could be broken.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.GET_LOGS)
@wrapped_command()
def get_logs(connection_id: int, result: str = None) -> None:
    """Gets the messages logged by a subordinate server.

    Args:
        connection_id (int): Connection ID
        result (str): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            logs = log_line_prefix + log_line_prefix.join(
                result.splitlines(True))
            Logger().log(
                "The logs from the subordinate server are:\n\n{}".format(logs),
                LoggedMessageTypes.SUCCESS)
        else:
            Logger().log(
                "No message on the subordinate servers has been logged so far.",
                LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.REMOVE_LOGS)
@wrapped_command()
def remove_logs(connection_id: int, result: bool = None) -> None:
    """Remove the messages logged by a subordinate server.

    Args:
        connection_id (int): Connection ID
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log("The logs from the subordinate server were cleared.",
                         LoggedMessageTypes.BEGINNING)
        else:
            Logger().log(
                "The logs from the subordinate server could not be cleared.",
                LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.START_DATA_SCAN)
@wrapped_command()
def start_data_scan(malware_folder: bool,
                    folder_watch_interval: int,
                    vt_scan_interval: int = 0,
                    result: bool = None) -> None:
    """Starts a new scan of a data folder.

    Args:
        malware_folder (bool): Boolean indicating if the scanning should be
            for the folder with benign files or the one with malware samples
        folder_watch_interval (int): Number of seconds between two
            consecutive scans of the given folder
        vt_scan_interval (int): Number of seconds between two consecutive
            scans of a malware hash with VirusTotal. Only for malware folder
            scanning and useful to respect the quota of the used account
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log("The scanning of the data folder started.",
                         LoggedMessageTypes.BEGINNING)
        else:
            Logger().log(
                "The scanning of the data folder could not be started.",
                LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.LIST_DATA_SCANS)
@wrapped_command()
def list_data_scans(result: typing.List[typing.List] = None) -> None:
    """Lists all scans of data folders across all subordinate servers.

    Args:
        result (typing.List[typing.List]): Result received from the decorator.
            Defaults to None.
    """
    if result is not None:
        if len(result) != 0:
            for entry in result:
                if entry[1] is None:
                    continue
                entry[1] = "Malicious" if entry[1] else "Benign"

            headers = [
                "Connection ID", "Target Folder", "Folder Watch Interval",
                "VirusTotal Scan Interval"
            ]
            table = tabulate(result, headers=headers, tablefmt="grid")

            Logger().log("The active scannings are:\n\n{}\n".format(table),
                         LoggedMessageTypes.INFORMATION)
        else:
            Logger().log("The scannings details could not be retrieved.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.STOP_DATA_SCAN)
@wrapped_command()
def stop_data_scan(connection_id: int, result: bool = None) -> None:
    """Stops a scan of a data folder.

    Args:
        connection_id (int): Connection ID
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log("The scanning of the data folder was stopped.",
                         LoggedMessageTypes.END)
        else:
            Logger().log(
                "The scanning of the data folder could not be stopped.",
                LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.UPDATE_MALWARE_LABELS)
@wrapped_command()
def update_malware_labels(result: bool = None) -> None:
    """Updates the labels of the malware samples from the dataset.

    Args:
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log("The update of malware labels started.",
                         LoggedMessageTypes.BEGINNING)
        else:
            Logger().log("The update of malware labels could not be started.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.CREATE_DATASET)
@wrapped_command()
def create_dataset(configuration_filename: str, result: bool = None) -> None:
    """Creates a dataset based on a configuration file.

    Args:
        configuration_filename (str): Name of the configuration file
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log("The creation of the dataset started.",
                         LoggedMessageTypes.BEGINNING)
        else:
            Logger().log("The creation of the dataset could not be started.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.LIST_DATASETS)
@wrapped_command()
def list_datasets(result: typing.List[typing.List] = None) -> None:
    """Lists the datasets.

    Args:
        result (typing.List[typing.List]): Result received from the decorator.
            Defaults to None.
    """

    def _preprocess_long_text(raw_text: str):
        if len(raw_text) > max_string_len:
            raw_text = raw_text[:max_string_len] + overflow_replacement

        return raw_text

    def _preprocess_long_list(raw_list: list):
        return _preprocess_long_text(", ".join(raw_list))

    if result is not None:
        if len(result) != 0:
            result_df = pandas.DataFrame(result[1:], columns=result[0])
            result_df["description"] = result_df["description"].apply(
                _preprocess_long_text)
            result_df["desired_families"] = result_df[
                "desired_families"].apply(_preprocess_long_list)
            result_df = result_df.reindex(columns=[
                "filename", "description", "extension", "desired_families",
                "entries_count", "benign_ratio", "min_malice"
            ])

            headers = [
                "Filename", "Description", "Extension", "Desired Families",
                "Samples Count", "Benign Samples Ratio", "Minimum Malice"
            ]
            table = tabulate(result_df.values,
                             headers=headers,
                             tablefmt="grid")

            Logger().log("The datasets are:\n\n{}\n".format(table),
                         LoggedMessageTypes.INFORMATION)
        else:
            Logger().log("The datasets could not be retrieved.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.REMOVE_DATASET)
@wrapped_command()
def remove_dataset(dataset_filename: str, result: bool = None) -> None:
    """Removes a dataset.

    Args:
        dataset_filename (str): Name of the dataset file
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log("The dataset was removed.",
                         LoggedMessageTypes.SUCCESS)
        else:
            Logger().log("The dataset could not be removed.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.CREATE_MODEL)
@wrapped_command()
def create_model(configuration_filename: str, result: bool = None) -> None:
    """Creates a model via training, based on a configuration file.

    Args:
        configuration_filename (str): Name of the configuration file.
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log("The training of the model started.",
                         LoggedMessageTypes.BEGINNING)
        else:
            Logger().log("The training of the model could not be started.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.UPDATE_MODEL)
@wrapped_command()
def update_model(model_name: str,
                 parameter_name: str,
                 parameter_value: float,
                 result: bool = None) -> None:
    """Updates the prediction parameters of a model.

    Args:
        model_name (str): Name of the model
        parameter_name (str): Name of the parameter
        parameter_value (float): New value of the parameter
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log(
                "The parameter of the prediction configuration was changed.",
                LoggedMessageTypes.BEGINNING)
        else:
            Logger().log(("The parameter of the prediction configuration "
                          "could not be changed."), LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.LIST_MODELS)
@wrapped_command()
def list_models(result: typing.List[typing.List] = None) -> None:
    """Lists all models.

    Args:
        result (typing.List[typing.List]): Result received from the decorator.
            Defaults to None.
    """
    if result is not None:
        if result:
            headers = [
                "Name", "Content of the Training Configuration File",
                "Content of the Prediction Configuration File"
            ]
            table = tabulate(result,
                             headers=headers,
                             tablefmt="grid",
                             colalign=("center", "left", "left"))

            Logger().log("The trained models are:\n\n{}\n".format(table),
                         LoggedMessageTypes.INFORMATION)
        else:
            Logger().log("The trained models details could not be retrieved.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.REMOVE_MODEL)
@wrapped_command()
def remove_model(model_name: str, result: bool = None) -> None:
    """Removes a model.

    Args:
        model_name (str): Name of the model
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log("The model was removed.", LoggedMessageTypes.SUCCESS)
        else:
            Logger().log("The model could not be removed.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.CREATE_RETRAINING)
@wrapped_command()
def create_retraining(model_name: str, result: bool = None) -> None:
    """Creates instant retraining of a model.

    Args:
        model_name (str): Name of the model
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log("The retraining of the model started.",
                         LoggedMessageTypes.BEGINNING)
        else:
            Logger().log("The retraining of the model could not be started.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.START_RETRAINING)
@wrapped_command()
def start_retraining(model_name: str, result: bool = None) -> None:
    """Starts a periodical retraining of a model.

    Args:
        model_name (str): Name of the model
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log("The model was added to retraining.",
                         LoggedMessageTypes.SUCCESS)
        else:
            Logger().log("The model could not be added to retraining.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.LIST_RETRAININGS)
@wrapped_command()
def list_retrainings(result: typing.List[typing.List] = None) -> None:
    """Lists the periodical retraining of the models.

    Args:
        result (typing.List[typing.List]): Result received from the decorator.
            Defaults to None.
    """
    if result is not None:
        if len(result) != 0:
            header = ["Model Name", "Connection ID"]
            table = tabulate(result, headers=header, tablefmt="grid")

            Logger().log("The retrained models are:\n\n{}\n".format(table),
                         LoggedMessageTypes.INFORMATION)
        else:
            Logger().log(
                "The details about retrained models could not be retrieved.",
                LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.STOP_RETRAINING)
@wrapped_command()
def stop_retraining(model_name: str,
                    result: typing.List[typing.List] = None) -> None:
    """Stops a periodical retraining of a model.

    Args:
        model_name (str): Name of the model
        result (typing.List[typing.List], optional): Result received from the
            decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log("The retraining of the model was stopped.",
                         LoggedMessageTypes.SUCCESS)
        else:
            Logger().log("The retraining of the model could not be stopped.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.CREATE_TICKET)
@wrapped_command()
def create_ticket(model_name: str,
                  sample_filename: str,
                  similarity_analysis: bool = False,
                  similar_count: int = 0,
                  result: str = None) -> None:
    """Creates a ticket for predicting a result for a file.

    Args:
        model_name (str): Name of the model
        sample_filename (str): Name of the sample, stored locally
        similarity_analysis (bool): Boolean indicating if a similarity analysis
            needs to be done. Defaults to False.
        similar_count (int): Number of similar samples to return. Defaults to 0,
            if the similarity analysis is disabled.
        result (str): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log(("The prediction for the sample started."
                          "The result can be retrieved via the ticket {}"
                          ).format(result), LoggedMessageTypes.SUCCESS)
        else:
            Logger().log("The prediction for the sample could not be started.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.LIST_TICKETS)
@wrapped_command()
def list_tickets(result: typing.List[typing.List] = None) -> None:
    """Lists the tickets created on this session.

    Args:
        result (typing.List[typing.List]): Result received from the decorator.
            Defaults to None.
    """
    if result is not None:
        if len(result) != 0:
            headers = ["Name", "Connection ID"]
            table = tabulate(result, headers=headers, tablefmt="grid")

            Logger().log("The active tickets are:\n\n{}\n".format(table),
                         LoggedMessageTypes.INFORMATION)
        else:
            Logger().log("No tickets were opened yet.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.GET_TICKET)
@wrapped_command()
def get_ticket(ticket_name: str, result: dict = None) -> None:
    """Gets the prediction results attached to a ticket.

    Args:
        ticket_name (str): Name of the ticket
        result (dict): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            if "malice" in result.keys():
                Logger().log(
                    "The predicted malice for the scanned file is: {:.2f}".
                    format(result["malice"]), LoggedMessageTypes.SUCCESS)
            elif "memberships" in result.keys():
                memberships = [[key, value]
                               for key, value in result["memberships"].items()]

                headers = ["Family", "Membership Score"]
                table = tabulate(memberships, headers=headers, tablefmt="grid")

                Logger().log(
                    "The memberships to malware families are:\n\n{}\n".format(
                        table), LoggedMessageTypes.INFORMATION)

            if "similar" in result.keys():
                similar_samples = [[sample["hash"], sample["similarity"]]
                                   for sample in result["similar"]]

                headers = ["Hash", "Similarity Score"]
                table = tabulate(similar_samples,
                                 headers=headers,
                                 tablefmt="grid")

                Logger().log(
                    "The most similar {} sampes are:\n\n{}\n".format(
                        len(similar_samples), table),
                    LoggedMessageTypes.INFORMATION)
        else:
            Logger().log("The content of the ticket could not be retrieved.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.REMOVE_TICKET)
@wrapped_command()
def remove_ticket(ticket_name: str, result: bool = None) -> None:
    """Removes a ticket.

    Args:
        ticket_name (str): Name of the ticket.
        result (bool): Result received from the decorator. Defaults to None.
    """
    if result is not None:
        if result:
            Logger().log("The ticket was removed.",
                         LoggedMessageTypes.BEGINNING)
        else:
            Logger().log("The ticket could not be removed.",
                         LoggedMessageTypes.FAIL)


@cli.command(LEADER_CONFIG.CLICommands.MANUAL)
def manual(command_name: str) -> None:
    """Helps the user with using a specific command.

    Args:
        command_name (str): The name of the command
    """
    source_content = open(__file__, "r").read()

    # Extract and parse the function docstring
    try:
        extracted_command = mydocstring.extract.PyExtract(
            source_content).extract(command_name)
    except NameError:
        Logger().log("The requested command does not exists.",
                     LoggedMessageTypes.FAIL)
        return
    documentation = mydocstring.parse.GoogleDocString(
        extracted_command['docstring'],
        signature=extracted_command['parsed_signature']).parse()

    # Create a string holding the usage of the command
    command_usage = command_name

    # Extract the function description
    command_description = documentation[0]['text'].replace('\n', '')

    # Extract the details about each arguments
    arguments_description = []
    for argument in documentation[1]['args']:
        name = argument['field']

        # Skip the argument if it is the result one
        if name == 'result':
            continue

        # Process the description by trimming the whitespaces and the default
        # value part. pylint: disable=no-member
        description = argument['description']
        description = description.replace("\n", "")
        description = description.replace("    ", " ")
        description = description.split("Defaults")[0]
        description = description.split(". ")[0]

        # Process the argument signature
        signature = argument['signature']
        is_optional = "=" in signature
        if is_optional:
            signature = signature.split(" =")[0] + ", optional"

        arguments_description.append([
            name,
            description,
            signature,
        ])

        name = name.upper()
        if is_optional:
            command_usage += " [" + name + "]"
        else:
            command_usage += " " + name

    Logger().log(("The manual of the command is:\n\n"
                  "Description:\n\t{}\n\nUsage:\n\t{}\n").format(
                      command_description, command_usage),
                 LoggedMessageTypes.INFORMATION)
    if len(arguments_description) > 0:
        headers = ["Name", "Description", "Type"]
        table = tabulate(arguments_description,
                         headers=headers,
                         tablefmt="grid")

        Logger().log(("The details about each argument are "
                      "listed in the table below.\n\n{}\n").format(table))


@cli.command(LEADER_CONFIG.CLICommands.CLEAR)
def clear() -> None:
    """Clears the output of the command-line interface."""
    os.system("cls" if os.name == "nt" else "clear")  # nosec


@cli.command(LEADER_CONFIG.CLICommands.EXIT)
# pylint: disable=redefined-builtin
def exit() -> None:
    """Exits the command-line interface."""
    Logger().log("The platform will exit soon.", LoggedMessageTypes.END)

    if leader:
        leader.remove_all_connections()
        leader.stop()

    sys.exit(0)


def main():
    """Main function."""
    cli.run()


if __name__ == "__main__":
    main()

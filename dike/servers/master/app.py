#!/usr/bin/env python3
"""Script running dike's software for master server on this machine"""

import os
import sys
import typing

import emojis
import pandas
from configuration.dike import DikeConfig
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker
from modules.utils.errors import Error
from modules.utils.logger import LoggedMessageType, Logger
from riposte import Riposte
from servers.master.subordinate_leader import SubordinateLeader
from tabulate import tabulate

# Get the configuration
config = ConfigurationWorker()
master_config = config.get_configuration_space(
    ConfigurationSpace.MASTER_SERVER)
subordinate_config = config.get_configuration_space(
    ConfigurationSpace.SUBORDINATE_SERVER)

# Create the banner by indenting the join of the logo and of the description
banner = master_config["cli"]["banner"].replace("\\n", "")
banner = " " + " ".join(banner.splitlines(True))

# Get the other elements required by the CLI
prompt = emojis.encode(master_config["cli"]["prompt"])
citation_line_prefix = master_config["cli"]["citation_line_prefix"]
max_string_len = master_config["cli"]["max_string_len"]
string_part_hidden = master_config["cli"]["string_part_hidden"]

# Create the command-line interface
cli = Riposte(prompt=prompt, banner=banner)

# Initialize of the subordinate leader
leader = SubordinateLeader()

# Enable the logging
Logger().set_enable(enable=True)


def wrapped_command(start_log: str = None, end_log: str = None):
    """Ensures the healthy lifecycle of a CLI command.

    It performs the following operations:
    - logging the beginning and the finish of execution;
    - calling the method from the corresponding SubordinateLeader object;
    - returning the result to the decorated function for further processing (
    for example, prints); and
    - catching errors.

    Args:
        start_log (str, optional): Logging message for execution start.
            Defaults to None.
        end_log (str, optional): Logging message for execution finish. Defaults
            to None.
    """
    def inner_decorator(function: typing.Callable):
        def wrapper(*args, **kwargs):
            try:
                # Log the beginning of the execution
                if start_log:
                    Logger().log(start_log, LoggedMessageType.BEGINNING)

                # Get the function from the SubordinateLeader and execute it
                # with the given parameter
                result = getattr(leader, function.__name__)(*args, **kwargs)

                # Log the end of the execution
                if end_log:
                    Logger().log(end_log, LoggedMessageType.END)

                # After having the result from the SubordinateLeader, pass the
                # result to the function on which the decorator is applied
                function_result = function(*args, **kwargs, result=result)

                return function_result

            except Error as error:

                # Log error
                Logger().log(str(error), LoggedMessageType.ERROR)

                return None

            except TypeError:

                # Log error
                Logger().log(
                    "The number of parameters is invalid. Verify the command manual.",
                    LoggedMessageType.ERROR)

                return None

        return wrapper

    return inner_decorator


@cli.command(DikeConfig.CLICommands.CREATE_CONNECTION.value)
@wrapped_command()
# pylint: disable=unused-argument
def create_connection(host: str, port: int, result: bool = None) -> None:
    """See the SubordinateLeader.create_connection() method."""
    if result is not None:
        if result:
            Logger().log(
                "A new connection with the subordinate server was established.",
                LoggedMessageType.SUCCESS)
        else:
            Logger().log(
                "The connection with the subordinate server could not be established.",
                LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.CREATE_CONNECTIONS.value)
@wrapped_command()
# pylint: disable=unused-argument
def create_connections(network: str, result: int = None) -> None:
    """See the SubordinateLeader.create_connections() method."""
    if result is not None:
        if (result != 0):
            Logger().log(
                "{} new connections with subordinate servers were established."
                .format(result), LoggedMessageType.SUCCESS)
        else:
            Logger().log(
                "No new connection with subordinate servers could be established.",
                LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.LIST_CONNECTIONS.value)
@wrapped_command()
# pylint: disable=unused-argument
def list_connections(result: typing.List[typing.List] = None) -> None:
    """See the SubordinateLeader.list_connections() method."""
    if result is not None:
        if (len(result) != 0):
            headers = ["ID", "Host", "Port", "Employment State"]
            table = tabulate(result, headers=headers, tablefmt="grid")

            Logger().log(
                "The active connections with the subordinate servers are:\n\n{}\n"
                .format(table), LoggedMessageType.INFORMATION)
        else:
            Logger().log(
                "No connection with subordinate servers has been set so far.",
                LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.REMOVE_CONNECTION.value)
@wrapped_command()
# pylint: disable=unused-argument
def remove_connection(connection_id: int, result: bool = None) -> None:
    """See the SubordinateLeader.remove_connection() method."""
    if result is not None:
        if result:
            Logger().log(
                "The connection with the subordinate server was broken.",
                LoggedMessageType.SUCCESS)
        else:
            Logger().log(
                "The connection with the subordinate server could not be broken.",
                LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.REMOVE_ALL_CONNECTIONS.value)
@wrapped_command()
# pylint: disable=unused-argument
def remove_all_connections(result: int = None) -> None:
    """See the SubordinateLeader.remove_all_connections() method."""
    if result is not None:
        if (result != 0):
            Logger().log(
                "{} connections with subordinate servers were broken.".format(
                    result), LoggedMessageType.SUCCESS)
        else:
            Logger().log("No connection could be broken.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.GET_LOGS.value)
@wrapped_command()
# pylint: disable=unused-argument
def get_logs(connection_id: int, result: str = None) -> None:
    """See the SubordinateLeader.get_logs() method."""
    if result is not None:
        if result:
            logs = citation_line_prefix + citation_line_prefix.join(
                result.splitlines(True))
            Logger().log(
                "The logs from the subordinate server are:\n\n{}".format(logs),
                LoggedMessageType.SUCCESS)
        else:
            Logger().log(
                "No message on the subordinate servers has been logged so far.",
                LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.REMOVE_LOGS.value)
@wrapped_command()
# pylint: disable=unused-argument
def remove_logs(connection_id: int, result: bool = None) -> None:
    """See the SubordinateLeader.remove_logs() method."""
    if result is not None:
        if result:
            Logger().log("The logs from the subordinate server were cleared.",
                         LoggedMessageType.BEGINNING)
        else:
            Logger().log(
                "The logs from the subordinate server could not be cleared.",
                LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.START_DATA_SCAN.value)
@wrapped_command()
# pylint: disable=unused-argument
def start_data_scan(malware_folder: bool,
                    folder_watch_interval: int,
                    vt_scan_interval: int = 0,
                    result: bool = None) -> None:
    """See the SubordinateLeader.start_data_scan() method."""
    if result is not None:
        if result:
            Logger().log("The scanning of the data folder started.",
                         LoggedMessageType.BEGINNING)
        else:
            Logger().log(
                "The scanning of the data folder could not be started.",
                LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.LIST_DATA_SCANS.value)
@wrapped_command()
# pylint: disable=unused-argument
def list_data_scans(result: typing.List[typing.List] = None) -> None:
    """See the SubordinateLeader.list_data_scans() method."""
    if result is not None:
        if (len(result) != 0):
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
                         LoggedMessageType.INFORMATION)
        else:
            Logger().log("The scannings details could not be retrieved.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.STOP_DATA_SCAN.value)
@wrapped_command()
# pylint: disable=unused-argument
def stop_data_scan(malware_folder: bool,
                   folder_watch_interval: int,
                   vt_scan_interval: int = 0,
                   result: bool = None) -> None:
    """See the SubordinateLeader.stop_data_scan() method."""
    if result is not None:
        if result:
            Logger().log("The scanning of the data folder was stopped.",
                         LoggedMessageType.END)
        else:
            Logger().log(
                "The scanning of the data folder could not be stopped.",
                LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.UPDATE_MALWARE_LABELS.value)
@wrapped_command()
# pylint: disable=unused-argument
def update_malware_labels(result: bool = None) -> None:
    """See the SubordinateLeader.update_malware_labels() method."""
    if result is not None:
        if result:
            Logger().log("The update of malware labels started.",
                         LoggedMessageType.BEGINNING)
        else:
            Logger().log("The update of malware labels could not be started.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.CREATE_DATASET.value)
@wrapped_command()
# pylint: disable=unused-argument
def create_dataset(extension: str,
                   min_malice: float,
                   desired_categories: typing.List[bool],
                   enties_count: int,
                   benign_ratio: float,
                   output_filename: str,
                   description: str = "",
                   result: bool = None) -> None:
    """See the SubordinateLeader.create_dataset() method."""
    if result is not None:
        if result:
            Logger().log("The creation of the dataset started.",
                         LoggedMessageType.BEGINNING)
        else:
            Logger().log("The creation of the dataset could not be started.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.LIST_DATASETS.value)
@wrapped_command()
# pylint: disable=unused-argument
def list_datasets(result: typing.List[typing.List] = None) -> None:
    """See the SubordinateLeader.list_datasets() method."""
    def _preprocess_long_text(raw_text: str):
        if (len(raw_text) > max_string_len):
            raw_text = raw_text[:max_string_len] + string_part_hidden

        return raw_text

    def _preprocess_long_list(raw_list: list):
        return _preprocess_long_text(", ".join(raw_list))

    if result is not None:
        if (len(result) != 0):
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
                         LoggedMessageType.INFORMATION)
        else:
            Logger().log("The datasets could not be retrieved.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.REMOVE_DATASET.value)
@wrapped_command()
# pylint: disable=unused-argument
def remove_dataset(dataset_filename: str, result: bool = None) -> None:
    """See the SubordinateLeader.remove_dataset() method."""
    if result is not None:
        if result:
            Logger().log("The dataset was removed.", LoggedMessageType.SUCCESS)
        else:
            Logger().log("The dataset could not be removed.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.CREATE_MODEL.value)
@wrapped_command()
# pylint: disable=unused-argument
def create_model(configuration_filename: str, result: bool = None) -> None:
    """See the SubordinateLeader.create_modelcreate_model() method."""
    if result is not None:
        if result:
            Logger().log("The training of the model started.",
                         LoggedMessageType.BEGINNING)
        else:
            Logger().log("The training of the model could not be started.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.UPDATE_MODEL.value)
@wrapped_command()
# pylint: disable=unused-argument
def update_model(model_name: str,
                 parameter_name: str,
                 parameter_value: float,
                 result: bool = None) -> None:
    """See the SubordinateLeader.update_model() method."""
    if result is not None:
        if result:
            Logger().log(
                "The parameter of the prediction configuration was changed.",
                LoggedMessageType.BEGINNING)
        else:
            Logger().log(
                "The parameter of the prediction configuration could not be changed.",
                LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.LIST_MODELS.value)
@wrapped_command()
# pylint: disable=unused-argument
def list_models(result: typing.List[typing.List] = None) -> None:
    """See the SubordinateLeader.list_models() method."""
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
                         LoggedMessageType.INFORMATION)
        else:
            Logger().log("The trained models details could not be retrieved.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.REMOVE_MODEL.value)
@wrapped_command()
# pylint: disable=unused-argument
def remove_model(model_name: str, result: bool = None) -> None:
    """See the SubordinateLeader.remove_model() method."""
    if result is not None:
        if result:
            Logger().log("The model was removed.", LoggedMessageType.SUCCESS)
        else:
            Logger().log("The model could not be removed.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.START_RETRAINING.value)
@wrapped_command()
# pylint: disable=unused-argument
def start_retraining(model_name: str, result: bool = None) -> None:
    """See the SubordinateLeader.start_retraining() method."""
    if result is not None:
        if result:
            Logger().log("The model was added to retraining.",
                         LoggedMessageType.SUCCESS)
        else:
            Logger().log("The model could not be added to retraining.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.LIST_RETRAININGS.value)
@wrapped_command()
# pylint: disable=unused-argument
def list_retrainings(result: typing.List[typing.List] = None) -> None:
    """See the SubordinateLeader.list_retrainings() method."""
    if result is not None:
        if (len(result) != 0):
            result = [[name] for name in result]

            header = ["Name"]
            table = tabulate(result, headers=header, tablefmt="grid")

            Logger().log("The retrained models are:\n\n{}\n".format(table),
                         LoggedMessageType.INFORMATION)
        else:
            Logger().log(
                "The details about retrained models could not be retrieved.",
                LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.STOP_RETRAINING.value)
@wrapped_command()
# pylint: disable=unused-argument
def stop_retraining(model_name: str,
                    result: typing.List[typing.List] = None) -> None:
    """See the SubordinateLeader.stop_retraining() method."""
    if result is not None:
        if result:
            Logger().log("The retraining of the model was stopped.",
                         LoggedMessageType.SUCCESS)
        else:
            Logger().log("The retraining of the model could not be stopped.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.CREATE_TICKET.value)
@wrapped_command()
# pylint: disable=unused-argument
def create_ticket(model_name: str,
                  sample_filename: str,
                  similarity_analysis: bool = False,
                  similar_count: int = 0,
                  result: bool = None) -> None:
    """See the SubordinateLeader.create_ticket() method."""
    if result is not None:
        if result:
            Logger().log(
                "The prediction for the sample started. The result can be retrieved via the ticket {}"
                .format(result), LoggedMessageType.SUCCESS)
        else:
            Logger().log("The prediction for the sample could not be started.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.LIST_TICKETS.value)
@wrapped_command()
# pylint: disable=unused-argument
def list_tickets(result: typing.List[typing.List] = None) -> None:
    """See the SubordinateLeader.list_tickets() method."""
    if result is not None:
        if (len(result) != 0):
            headers = ["Name", "Connection ID"]
            table = tabulate(result, headers=headers, tablefmt="grid")

            Logger().log("The active tickets are:\n\n{}\n".format(table),
                         LoggedMessageType.INFORMATION)
        else:
            Logger().log("No tickets were opened yet.", LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.GET_TICKET.value)
@wrapped_command()
# pylint: disable=unused-argument
def get_ticket(ticket_name: str, result: dict = None) -> None:
    """See the SubordinateLeader.get_ticket() method."""
    if result is not None:
        if (result and result["status"] == "ok"):
            if "malice" in result.keys():
                Logger().log(
                    "The predicted malice for the scanned file is: {:.2f}".
                    format(result["malice"]), LoggedMessageType.SUCCESS)
            elif "membership" in result.keys():
                memberships = [[key, value]
                               for key, value in result["membership"].items()]

                headers = ["Family", "Membership Score"]
                table = tabulate(memberships, headers=headers, tablefmt="grid")

                Logger().log(
                    "The memberships to malware families are:\n\n{}\n".format(
                        table), LoggedMessageType.INFORMATION)

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
                    LoggedMessageType.INFORMATION)
        else:
            Logger().log("The content of the ticket could not be retrieved.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.REMOVE_TICKET.value)
@wrapped_command()
# pylint: disable=unused-argument
def remove_ticket(ticket_name: str, result: bool = None) -> None:
    """See the SubordinateLeader.remove_ticket() method."""
    if result is not None:
        if result:
            Logger().log("The ticket was removed.",
                         LoggedMessageType.BEGINNING)
        else:
            Logger().log("The ticket could not be removed.",
                         LoggedMessageType.FAIL)


@cli.command(DikeConfig.CLICommands.CLEAR.value)
def clear() -> None:
    """Clears the output of the command-line interface."""
    os.system("cls" if os.name == "nt" else "clear")


@cli.command(DikeConfig.CLICommands.EXIT.value)
# pylint: disable=redefined-builtin
def exit() -> None:
    """Exits the command-line interface."""
    Logger().log("The platform will exit soon.", LoggedMessageType.END)

    if leader:
        leader.remove_all_connections()
        leader.stop()

    sys.exit(0)


# Run the CLI
cli.run()

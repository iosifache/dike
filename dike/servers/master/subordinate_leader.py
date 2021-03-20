import ipaddress
import os
import threading
import time
import typing

import modules.utils.errors as errors
import rpyc
from modules.dataset_building.types import AnalyzedFileTypes
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker
from pypattyrn.creational.singleton import Singleton
from servers.subordinate.types import Employment, Endpoint


class _Connection:
    """Class for encapsulating details about an active connection"""
    host: str
    port: int
    effective_connection: rpyc.Connection
    employment: Employment

    def __init__(self, host: str, port: int,
                 connection: rpyc.Connection) -> None:
        """Initializes the _Connection instance.

        Args:
            host (str): Hostname or IP address
            port (int): Port number
            connection (rpyc.Connection): RPyC connection
        """
        self.host = host
        self.port = port
        self.effective_connection = connection

        # Default value of members
        self.employment = Employment.AVAILABLE


class SubordinateLeader(object, metaclass=Singleton):
    """Class controlling subordinate servers"""
    _default_port_number: int
    _connections: typing.List[_Connection]
    _answers: typing.List[rpyc.AsyncResult]
    _answers_thread: threading.Thread
    _stop_needed: bool
    _malware_families: list
    _created_tickets: list

    def __init__(self) -> None:
        """Initializes the SubordinateLeader instance."""
        # Get the configuration and its required spaces
        config = ConfigurationWorker()
        subordinate_config = config.get_configuration_space(
            ConfigurationSpace.SUBORDINATE_SERVER)
        master_config = config.get_configuration_space(
            ConfigurationSpace.MASTER_SERVER)
        dataset_config = config.get_configuration_space(
            ConfigurationSpace.DATASET_BUILDER)

        # Initialize the members based on the configuration
        self._default_port_number = subordinate_config["port"]
        self._malware_families = dataset_config["malware_families"].keys()
        self._malware_families = [
            family.lower() for family in self._malware_families
        ]

        # Default value of members
        self._connections = []
        self._answers = []
        self._stop_needed = False
        self._created_tickets = []

        # Create the answer checking thread
        answers_checking_interval = master_config["answers_checking_interval"]
        self._answers_thread = threading.Thread(
            target=self._check_answers, args=(answers_checking_interval, ))
        self._answers_thread.start()

    def stop(self):
        """Stops the answer checking thread before exiting."""
        self._stop_needed = True
        self._answers_thread.join()

    def _check_answers(self, sleep_seconds: int):
        while (not self._stop_needed):
            for answer in self._answers:
                # pylint: disable=pointless-statement
                answer.ready

            time.sleep(sleep_seconds)

    def _refresh_connections_states(self) -> None:
        for connection in self._connections:
            connection.employment = connection.effective_connection.root.get_employment(
            )

    def _get_connection_by_id(self, connection_id: int) -> _Connection:
        if (connection_id < 0 or connection_id >= len(self._connections)):
            raise errors.InvalidConnectionIDError()

        return self._connections[connection_id]

    def _get_first_free_server(self) -> typing.Tuple[int, _Connection]:
        self._refresh_connections_states()

        for index, connection in enumerate(self._connections):
            if (connection.employment.value == Employment.AVAILABLE.value):
                connection.employment = Employment.GENERIC_EMPLOYMENT

                return (index, connection)

        raise errors.NoFreeServerFoundError()

    @staticmethod
    def _consume_new_result(async_result: rpyc.AsyncResult) -> None:
        # Get the singleton instance
        global_instance = SubordinateLeader()

        # pylint: disable=protected-access
        for connection in global_instance._connections:
            # pylint: disable=protected-access
            if (connection.effective_connection == async_result._conn):
                # The availability results from previous delegated tasks and
                # received response. For example, if a task was delegated to a
                # specific subordinate server and it responds with the result
                # of the task, that means it becomes available and can execute
                # new tasks.
                connection.employment = Employment.AVAILABLE
                break

    def _delegate_task(self,
                       method: Endpoint,
                       arguments: tuple = (),
                       connection_id: int = -1,
                       return_connection_id: bool = False) -> typing.Any:
        # Get the connection
        if (connection_id == -1):
            connection_id, connection = self._get_first_free_server()
        else:
            connection = self._get_connection_by_id(connection_id)

        # Get the method of the service
        method_name = method.value[0]
        wanted_function = getattr(connection.effective_connection.root,
                                  method_name)

        # Call the function
        is_async = method.value[1]
        if (not is_async):
            result = wanted_function(*arguments)
        else:
            async_result = rpyc.async_(wanted_function)(*arguments)

            # Add a callback and the result, to be checked later
            async_result.add_callback(SubordinateLeader._consume_new_result)
            self._answers.append(async_result)

            result = True

        if return_connection_id:
            return (result, connection_id)
        else:
            return result

    def create_connection(self, host: str, port: int) -> bool:
        """Connects to a subordinate server.

        Args:
            host (str): Hostname or IP of the subordinate server
            port (int): Port number on which the RPyC service listens

        Returns:
            bool: Boolean indicating if the connection was successfully created
        """
        port = int(port)

        # Check if a connection with the server is already established
        for connection in self._connections:
            if (connection.host == host and connection.port == port):
                return False

        try:
            connection = rpyc.connect(host, port)
        except:
            return False

        self._connections.append(_Connection(host, port, connection))

        return True

    def create_connections(self, network: str) -> int:
        """Connects to all subordinates servers found in a given network.

        Args:
            network (str): Network CIDR notation

        Returns:
            int: Number of new connections
        """
        try:
            addresses = ipaddress.IPv4Network(network)
        except:
            raise errors.InvalidNetworkError()

        new_connections = 0
        for ip in addresses:
            if (self.create_connection(
                    str(ip),
                    self._default_port_number,
            )):
                new_connections += 1

        return new_connections

    def list_connections(self) -> typing.List[typing.List]:
        """Lists active connections with subordinate servers."""
        self._refresh_connections_states()

        informations = []
        for connection_id, connection in enumerate(self._connections):
            informations.append([
                connection_id, connection.host, connection.port,
                connection.employment.name
            ])

        return informations

    def remove_connection(self, connection_id: int) -> bool:
        """Removes a connection with a subordinate server.

        Args:
            connection_id (int): Connection ID

        Returns:
            bool: Boolean indicating if the connection was removed
        """
        connection_id = int(connection_id)

        connection = self._get_connection_by_id(connection_id)
        if (not connection):
            return False

        del connection.effective_connection
        del self._connections[connection_id]

        return True

    def remove_all_connections(self) -> int:
        """Disconnects from all connected subordinate servers.

        Returns:
            int: Number of broken connections
        """
        disconnections = 0
        for connection in self._connections:
            del connection.effective_connection
            disconnections += 1

        self._connections.clear()

        return disconnections

    def get_logs(self, connection_id: int) -> str:
        """See the SubordinateService.get_logs() method."""
        connection_id = int(connection_id)

        result = self._delegate_task(Endpoint.GET_LOGS,
                                     connection_id=connection_id)

        return result

    def remove_logs(self, connection_id: int) -> bool:
        """See the SubordinateService.remove_logs() method."""
        connection_id = int(connection_id)

        result = self._delegate_task(Endpoint.REMOVE_LOGS,
                                     connection_id=connection_id)

        return result

    def start_data_scan(self,
                        malware_folder: bool,
                        folder_watch_interval: int,
                        vt_scan_interval: int = 0) -> bool:
        """See the SubordinateService.start_data_scan() method."""
        arguments = (malware_folder, folder_watch_interval, vt_scan_interval)
        result = self._delegate_task(Endpoint.START_DATA_SCAN, arguments)

        return result

    def list_data_scans(self) -> typing.List[typing.List]:
        """See the SubordinateService.list_data_scans() method."""
        result = []
        for connection_id, connection in enumerate(self._connections):
            details = connection.effective_connection.root.is_scanning_active()
            if details[0]:
                result.append(connection_id, *details[1])

        return result

    def stop_data_scan(self, connection_id: int) -> bool:
        """See the SubordinateService.stop_data_scan() method."""
        connection_id = int(connection_id)

        result = self._delegate_task(Endpoint.STOP_DATA_SCAN,
                                     connection_id=connection_id)

        return result

    def update_malware_labels(self) -> bool:
        """See the SubordinateService.update_malware_labels() method."""
        result = self._delegate_task(Endpoint.UPDATE_MALWARE_LABELS)

        return result

    def create_dataset(self,
                       extension: str,
                       min_malice: float,
                       desired_categories: str,
                       entries_count: int,
                       benign_ratio: float,
                       output_filename: str,
                       description: str = "") -> bool:
        """Creates a new dataset.

        Args:
            desired_categories (str): Comma separated names of the malware
                families to include in the dataset

        See the SubordinateService.create_dataset() method.
        """
        # Preprocess the parameters
        families = desired_categories.split(",")
        processed_desired_categories = 9 * [False]
        for family in families:
            try:
                index = self._malware_families.index(family)
                processed_desired_categories[index] = True
            except:
                pass
        file_type_id = AnalyzedFileTypes.map_extension_to_type(
            extension).value.ID
        min_malice = float(min_malice)
        entries_count = int(entries_count)
        benign_ratio = float(benign_ratio)

        arguments = (file_type_id, min_malice, processed_desired_categories,
                     entries_count, benign_ratio, output_filename, description)
        result = self._delegate_task(Endpoint.CREATE_DATASET, arguments)

        return result

    def list_datasets(self) -> typing.List[typing.List]:
        """See the SubordinateService.list_datasets() method."""
        result = self._delegate_task(Endpoint.LIST_DATASETS)

        return result

    def remove_dataset(self, dataset_filename: str) -> bool:
        """See the SubordinateService.remove_dataset() method."""
        arguments = (dataset_filename, )
        result = self._delegate_task(Endpoint.REMOVE_DATASET, arguments)

        return result

    def create_model(self, configuration_filename: str) -> bool:
        """Creates a new model.

        Args:
            configuration_filename (str): Name of the local configuration file
                used for model creation

        See the SubordinateService.create_model() method.
        """
        if not os.path.isfile(configuration_filename):
            return False
        configuration_file = open(configuration_filename, "rb")
        configuration = configuration_file.read()

        arguments = (configuration, )
        result = self._delegate_task(Endpoint.CREATE_MODEL, arguments)

        return result

    def list_models(self) -> typing.List[typing.List]:
        """See the SubordinateService.list_models() method."""
        result = self._delegate_task(Endpoint.LIST_MODELS)

        return result

    def update_model(self, model_name: str, parameter_name: str,
                     parameter_value: float) -> bool:
        """See the SubordinateService.update_model() method."""
        parameter_value = float(parameter_value)

        arguments = (model_name, parameter_name, parameter_value)
        result = self._delegate_task(Endpoint.UPDATE_MODEL,
                                     arguments)

        return result

    def remove_model(self, model_name: str) -> bool:
        """See the SubordinateService.remove_model() method."""
        arguments = (model_name, )
        result = self._delegate_task(Endpoint.REMOVE_MODEL, arguments)

        return result

    def start_retraining(self, model_name: str) -> bool:
        """See the SubordinateService.start_retraining() method."""
        arguments = (model_name, )
        result = self._delegate_task(Endpoint.START_RETRAINING, arguments)

        return result

    def list_retrainings(self) -> typing.List[str]:
        """See the SubordinateService.list_retrainings() method."""
        result = self._delegate_task(Endpoint.LIST_RETRAININGS)

        return result

    def stop_retraining(self, model_name: str) -> bool:
        """See the SubordinateService.stop_retraining() method."""
        arguments = (model_name, )
        result = self._delegate_task(Endpoint.STOP_RETRAINING, arguments)

        return result

    def create_ticket(self,
                      model_name: str,
                      sample_filename: str,
                      similarity_analysis: bool = False,
                      similar_count: int = 0) -> str:
        """Creates a new prediction ticket.

        Args:
            sample_filename (str): Name of the local file to analyze

        See the SubordinateService.create_ticket() method.
        """

        similarity_analysis = bool(similarity_analysis)
        similar_count = int(similar_count)

        if not os.path.isfile(sample_filename):
            return False
        sample_file = open(sample_filename, "rb")
        sample = sample_file.read()

        arguments = (model_name, sample, None, similarity_analysis,
                     similar_count)
        result, connection_id = self._delegate_task(Endpoint.CREATE_TICKET,
                                                    arguments,
                                                    return_connection_id=True)

        # Add the ticket into the list
        self._created_tickets.append([result, connection_id])

        return result

    def list_tickets(self) -> typing.List[typing.List]:
        """See the SubordinateService.list_tickets() method."""
        return self._created_tickets

    def get_ticket(self, ticket_name: str) -> dict:
        """Get the prediction result corresponding to a ticket.

        Args:
            ticket_name (str): Ticket name

        Returns:
            dict: Result of the prediction
        """
        # Get the connection ID
        connection_id = None
        for ticket in self._created_tickets:
            if (ticket[0] == ticket_name):
                connection_id = ticket[1]

        if connection_id is None:
            raise errors.TicketNotFoundError()

        arguments = (ticket_name, )
        result = self._delegate_task(Endpoint.GET_TICKET, arguments,
                                     connection_id)

        return result

    def remove_ticket(self, ticket_name: str) -> bool:
        """Removes a prediction ticket.

        Args:
            ticket_name (str): Ticket name

        Returns:
            bool: Boolean indicating if the ticket was removed
        """
        if ticket_name not in self._created_tickets:
            return False

        self._created_tickets = [
            ticket for ticket in self._created_tickets
            if ticket[0] != ticket_name
        ]

        return True

"""Subordinate servers dispatcher.

Usage example:

    # Create a dispatcher
    dispatcher = Dispatcher()

    # Connect to a subordinate server
    dispatcher.create_connection("127.0.0.1", 1234)

    # List all models
    models = dispatcher.list_models()

    # Disconnects from all servers
    dispatcher.remove_all_connections()
"""
import ipaddress
import os
import threading
import time
import typing

import rpyc
import servers.errors as errors
from modules.configuration.folder_structure import Files
from modules.utils.configuration_manager import ConfigurationManager
from modules.utils.types import ConfigurationSpaces
from pypattyrn.creational.singleton import Singleton
from servers.subordinate.types import Employment, Endpoint


class _Connection:
    """Class for encapsulating details about an active connection."""

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

        self.employment = Employment.AVAILABLE


class Dispatcher(object, metaclass=Singleton):
    """Class controlling subordinate servers.

    If the debugging mode is activated from the user configuration file, the
    dispatcher will return random valid results.
    """

    _connections: typing.List[_Connection]
    _answers: typing.List[rpyc.AsyncResult]
    _answers_thread: threading.Thread
    _stop_needed: bool
    _malware_families: list
    _created_tickets: list
    _model_retrainings: dict
    _is_debug: bool

    def __init__(self) -> None:
        """Initializes the Dispatcher instance."""
        configuration = ConfigurationManager()
        leader_config = configuration.get_space(
            ConfigurationSpaces.LEADER_SERVER)
        dataset_config = configuration.get_space(ConfigurationSpaces.DATASET)

        self._malware_families = dataset_config["malware_families"].keys()
        self._malware_families = [
            family.lower() for family in self._malware_families
        ]
        self._is_debug = leader_config["is_debug"]

        self._connections = []
        self._answers = []
        self._stop_needed = False
        self._created_tickets = []
        self._model_retrainings = dict()

        # Create the answer checking thread
        answers_checking_interval = leader_config["answers_checking_interval"]
        self._answers_thread = threading.Thread(
            target=self._check_answers, args=(answers_checking_interval, ))
        self._answers_thread.start()

    def stop(self):
        """Stops the answer checking thread before exiting."""
        self._stop_needed = True
        self._answers_thread.join()

    def _check_answers(self, sleep_seconds: int):
        while not self._stop_needed:
            for answer in self._answers:
                # pylint: disable=pointless-statement
                answer.ready

            time.sleep(sleep_seconds)

    def _refresh_connections_states(self) -> None:
        for connection in self._connections:
            connection_root = connection.effective_connection.root
            connection.employment = connection_root.get_employment()

    def _refresh_retrainings(self) -> None:
        self._model_retrainings.clear()

        for connection_id, connection in enumerate(self._connections):
            models = connection.effective_connection.root.list_retrainings()
            if models:
                for model in models:
                    self._model_retrainings[model] = connection_id

    def _get_connection_by_id(self, connection_id: int) -> _Connection:
        if (connection_id < 0 or connection_id >= len(self._connections)):
            raise errors.InvalidConnectionIDError()

        return self._connections[connection_id]

    def _get_first_free_server(self) -> typing.Tuple[int, _Connection]:
        self._refresh_connections_states()

        for index, connection in enumerate(self._connections):
            if connection.employment.value == Employment.AVAILABLE.value:
                connection.employment = Employment.GENERIC_EMPLOYMENT

                return (index, connection)

        raise errors.NoFreeServerFoundError()

    @staticmethod
    def _consume_new_result(async_result: rpyc.AsyncResult) -> None:
        # Get the singleton instance
        global_instance = Dispatcher()

        # pylint: disable=protected-access
        for connection in global_instance._connections:
            # pylint: disable=protected-access
            if connection.effective_connection == async_result._conn:
                # The availability results from previous delegated tasks and
                # received responses. For example, if a task was delegated to a
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
        if connection_id == -1:
            connection_id, connection = self._get_first_free_server()
        else:
            connection = self._get_connection_by_id(connection_id)

        # Get the method of the service
        method_name = method.value[0]
        wanted_function = getattr(connection.effective_connection.root,
                                  method_name)

        # Call the function
        is_async = method.value[1]
        if not is_async:
            result = wanted_function(*arguments)
        else:
            async_result = rpyc.async_(wanted_function)(*arguments)

            # Add a callback and the result, to be checked later
            async_result.add_callback(Dispatcher._consume_new_result)
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
            connection = rpyc.ssl_connect(host,
                                          port,
                                          keyfile=Files.SSL_PRIVATE_KEY,
                                          certfile=Files.SSL_CERTIFICATE)
        except Exception:
            return False

        self._connections.append(_Connection(host, port, connection))

        return True

    def create_connections(self, network: str, port: int) -> int:
        """Connects to all subordinate servers found in a given network.

        Args:
            network (str): Network CIDR notation
            port (int): Port number on which the RPyC service listens

        Raises:
            InvalidNetworkError: The given network, in CIDR notation, is
                invalid.

        Returns:
            int: Number of new connections
        """
        port = int(port)
        try:
            ip_addresses = ipaddress.IPv4Network(network)
        except Exception:
            raise errors.InvalidNetworkError()

        new_connections = 0
        for ip_address in ip_addresses:
            if (self.create_connection(
                    str(ip_address),
                    port,
            )):
                new_connections += 1

        return new_connections

    def list_connections(self) -> typing.List[typing.List]:
        """Lists the active connections with subordinate servers.

        Returns:
            typing.List[typing.List]: List of active connections, each one
                described by the connection ID, the host, and its port and the
                name of the employment state
        """
        self._refresh_connections_states()

        details = []
        for connection_id, connection in enumerate(self._connections):
            details.append([
                connection_id, connection.host, connection.port,
                connection.employment.name
            ])

        return details

    def remove_connection(self, connection_id: int) -> bool:
        """Removes a connection with a subordinate server.

        Args:
            connection_id (int): Connection ID

        Returns:
            bool: Boolean indicating if the connection was removed
        """
        connection_id = int(connection_id)

        connection = self._get_connection_by_id(connection_id)
        if not connection:
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
        """See the SubordinationService.get_logs() method.

        # noqa
        """
        connection_id = int(connection_id)

        result = self._delegate_task(Endpoint.GET_LOGS,
                                     connection_id=connection_id)

        return result

    def remove_logs(self, connection_id: int) -> bool:
        """See the SubordinationService.remove_logs() method.

        # noqa
        """
        connection_id = int(connection_id)

        result = self._delegate_task(Endpoint.REMOVE_LOGS,
                                     connection_id=connection_id)

        return result

    def start_data_scan(self,
                        malware_folder: bool,
                        folder_watch_interval: int,
                        vt_scan_interval: int = 0) -> bool:
        """See the SubordinationService.start_data_scan() method.

        # noqa
        """
        malware_folder = malware_folder == str(True)
        folder_watch_interval = int(folder_watch_interval)
        vt_scan_interval = int(vt_scan_interval)

        arguments = (malware_folder, folder_watch_interval, vt_scan_interval)
        result = self._delegate_task(Endpoint.START_DATA_SCAN, arguments)

        return result

    def list_data_scans(self) -> typing.List[typing.List]:
        """See the SubordinationService.list_data_scans() method.

        # noqa
        """
        result = []
        for connection_id, connection in enumerate(self._connections):
            details = connection.effective_connection.root.is_data_scan_active(
            )
            if details[0]:
                result.append([connection_id, *details[1]])

        return result

    def stop_data_scan(self, connection_id: int) -> bool:
        """See the SubordinationService.stop_data_scan() method.

        # noqa
        """
        connection_id = int(connection_id)

        result = self._delegate_task(Endpoint.STOP_DATA_SCAN,
                                     connection_id=connection_id)

        return result

    def update_malware_labels(self) -> bool:
        """See the SubordinationService.update_malware_labels() method.

        # noqa
        """
        result = self._delegate_task(Endpoint.UPDATE_MALWARE_LABELS)

        return result

    def create_dataset(self, configuration_filename: str) -> bool:
        """See the SubordinationService.create_dataset() method.

        # noqa
        """
        if not os.path.isfile(configuration_filename):
            return False
        configuration_file = open(configuration_filename, "rb")
        configuration = configuration_file.read()

        arguments = (configuration, )
        result = self._delegate_task(Endpoint.CREATE_DATASET, arguments)

        return result

    def list_datasets(self) -> typing.List[typing.List]:
        """See the SubordinationService.list_datasets() method.

        # noqa
        """
        result = self._delegate_task(Endpoint.LIST_DATASETS)

        return result

    def remove_dataset(self, dataset_filename: str) -> bool:
        """See the SubordinationService.remove_dataset() method.

        # noqa
        """
        arguments = (dataset_filename, )
        result = self._delegate_task(Endpoint.REMOVE_DATASET, arguments)

        return result

    def create_model(self, configuration_filename: str) -> bool:
        """Creates a new model.

        Args:
            configuration_filename (str): Name of the local configuration file
                used for model creation

        See the SubordinationService.create_model() method.

        # noqa
        """
        if not os.path.isfile(configuration_filename):
            return False
        configuration_file = open(configuration_filename, "rb")
        configuration = configuration_file.read()

        arguments = (configuration, )
        result = self._delegate_task(Endpoint.CREATE_MODEL, arguments)

        return result

    def list_models(self) -> typing.List[typing.List]:
        """See the SubordinationService.list_models() method.

        # noqa
        """
        result = self._delegate_task(Endpoint.LIST_MODELS)

        return result

    def update_model(self, model_name: str, parameter_name: str,
                     parameter_value: float) -> bool:
        """See the SubordinationService.update_model() method.

        # noqa
        """
        parameter_value = float(parameter_value)

        arguments = (model_name, parameter_name, parameter_value)
        result = self._delegate_task(Endpoint.UPDATE_MODEL, arguments)

        return result

    def remove_model(self, model_name: str) -> bool:
        """See the SubordinationService.remove_model() method.

        # noqa
        """
        arguments = (model_name, )
        result = self._delegate_task(Endpoint.REMOVE_MODEL, arguments)

        return result

    def create_retraining(self, model_name: str) -> bool:
        """See the SubordinationService.start_retraining() method.

        # noqa
        """
        arguments = (model_name, )
        result = self._delegate_task(Endpoint.CREATE_RETRAINING, arguments)

        return result

    def start_retraining(self, model_name: str) -> bool:
        """See the SubordinationService.start_retraining() method.

        # noqa
        """
        arguments = (model_name, )
        result = self._delegate_task(Endpoint.START_RETRAINING, arguments)

        return result

    def list_retrainings(self) -> typing.List[typing.List]:
        """See the SubordinationService.list_retrainings() method.

        # noqa
        """
        self._refresh_retrainings()

        result = []
        for model_name, connection_id in self._model_retrainings.items():
            result.append([model_name, connection_id])

        return result

    def stop_retraining(self, model_name: str) -> bool:
        """See the SubordinationService.stop_retraining() method.

        # noqa
        """
        self._refresh_retrainings()

        if model_name not in self._model_retrainings:
            return False
        connection_id = self._model_retrainings[model_name]

        arguments = (model_name, )
        result = self._delegate_task(Endpoint.STOP_RETRAINING, arguments,
                                     connection_id)

        return result

    def create_ticket(self,
                      model_name: str,
                      sample_filename: str,
                      analyst_mode: bool = False,
                      similar_count: int = 0) -> str:
        """Creates a new prediction ticket.

        Args:
            sample_filename (str): Name of the local file to analyze

        See the SubordinationService.create_ticket() method.

        #noqa
        """
        analyst_mode = analyst_mode == str(True)
        similar_count = int(similar_count)

        if not os.path.isfile(sample_filename):
            return False
        sample_file = open(sample_filename, "rb")
        sample = sample_file.read()

        arguments = (model_name, sample, None, analyst_mode, similar_count)
        result, connection_id = self._delegate_task(Endpoint.CREATE_TICKET,
                                                    arguments,
                                                    return_connection_id=True)

        # Add the ticket to the list
        self._created_tickets.append([result, connection_id])

        return result

    def list_tickets(self) -> typing.List[typing.List]:
        """See the SubordinationService.list_tickets() method.

        # noqa
        """
        return self._created_tickets

    def get_ticket(self, ticket_name: str) -> dict:
        """Get the prediction result corresponding to a ticket.

        Args:
            ticket_name (str): Ticket name

        Raises:
            TicketNotFoundError: The ticket was not found in the session of the
                server.

        Returns:
            dict: Result of the prediction
        """
        # Get the connection ID
        connection_id = None
        for ticket in self._created_tickets:
            if ticket[0] == ticket_name:
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
        names = [ticket[0] for ticket in self._created_tickets]
        if ticket_name not in names:
            return False

        self._created_tickets = [
            ticket for ticket in self._created_tickets
            if ticket[0] != ticket_name
        ]

        return True

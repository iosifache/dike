import ipaddress
import threading
import time
import typing

import rpyc
import tqdm
from pypattyrn.creational.singleton import Singleton
from modules.utils.logger import LoggedMessageType, Logger


class _Connection:
    """Class for encapsulating details about an active connection"""
    host: str = None
    port: int = None
    connection: rpyc.Connection = None
    is_busy: bool = False

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


class SubordinateLeader(object, metaclass=Singleton):
    """Class controlling subordinate servers"""
    _service_name: str = None
    _default_port_number: int = -1
    _connections: typing.List[_Connection] = []
    _answers: typing.List[rpyc.AsyncResult] = []
    _answers_thread: threading.Thread = None
    _stop_needed: bool = False

    def __init__(self, default_port_number: int, service_name: str,
                 answers_checking_interval: int) -> None:
        """Initializes the SubordinateLeader instance.

        Args:
            default_port_number (int): Number of the port on which all
                                       subordinate servers listen
            service_name (str): Name of the RPyC service used by all subordinate
                                servers
            answers_checking_interval (int): Interval in seconds between two
                                             consecutive checks of received
                                             answers from subordinate servers
        """
        self._default_port_number = default_port_number
        self._service_name = service_name
        self._answers_thread = threading.Thread(
            target=self._check_answers, args=(answers_checking_interval, ))
        self._answers_thread.start()

    def __del__(self):
        """Destroys the SubordinateLeader instance."""
        self._stop_needed = True

    def _check_answers(self, sleep_seconds: int):
        while (not self._stop_needed):
            for answer in self._answers:
                # pylint: disable=pointless-statement
                answer.ready

            time.sleep(sleep_seconds)

    def connect_to_server(self,
                          host: str,
                          port: int,
                          service_name: str = None,
                          are_info_logged: bool = True) -> bool:
        """Connects to a subordinate server.

        Args:
            host (str): Hostname or IP of the subordinate server
            port (int): Port number on which the RPyC service listens
            service_name (str, optional): RPyC service name. Defaults to None.
            are_info_logged (bool, optional): Boolean indicating if informations
                                              are logged. Used in calls from
                                              other class methods, where logging
                                              is not desired. Defaults to True.

        Returns:
            bool: Boolean indicating if the connection was successfully created
        """

        try:
            connection = rpyc.connect(host, port)
            if (service_name and service_name.upper()
                    not in connection.root.get_service_aliases()):
                return False

            self._connections.append(_Connection(host, port, connection))
            if (are_info_logged):
                Logger.log(
                    "Successfully connected to server {}:{}".format(
                        host, port), LoggedMessageType.SUCCESS)
            return True

        except:
            if (are_info_logged):
                Logger.log(
                    "Error on connection to server {}:{}".format(host, port),
                    LoggedMessageType.FAIL)
            return False

    def connect_to_all_servers(self, network: str) -> None:
        """Connects to all subordinates found in a given network.

        Args:
            network (str): Network CIDR notation
        """
        try:
            new_connections = 0
            addresses = ipaddress.IPv4Network(network)
            Logger.log("Starting to scan the given network",
                       LoggedMessageType.WORK)
            progress_bar = tqdm.tqdm(total=len(list(addresses)))
            for ip in addresses:
                if (self.connect_to_server(str(ip), self._default_port_number,
                                           self._service_name, False)):
                    new_connections += 1
                progress_bar.update(1)
            progress_bar.close()
            if (new_connections > 0):
                Logger.log(
                    "Successfully connected to {} servers".format(
                        new_connections), LoggedMessageType.SUCCESS)

            Logger.log("No server to connect to", LoggedMessageType.FAIL)
        except:
            Logger.log("Invalid network", LoggedMessageType.FAIL)

    def disconnect_from_server(self,
                               host: str,
                               port: int,
                               delete_host: bool = True,
                               are_info_logged: bool = True) -> bool:
        """Disconnects from a subordinate server.

        Args:
            host (str): Hostname or IP of the subordinate server
            port (int): Port number on which the RPyC service listens
            delete_host (bool, optional): Boolean indicating if the removed
                                          connection is deleted from from
                                          connection list too. Used when all
                                          connections are removed by a single
                                          RPyC method. Defaults to True.
            are_info_logged (bool, optional): Boolean indicating if informations
                                              are logged. Used in calls from
                                              other class methods, where logging
                                              is not desired. Defaults to True.

        Returns:
            bool: Boolean indicating if the disconnection was successfully
                  executed
        """
        for connection in self._connections:
            if (connection.host == host and connection.port == port):
                del connection.effective_connection
                if delete_host:
                    self._connections = [
                        connection for connection in self._connections
                        if connection.host != host and connection.port != port
                    ]
                if (are_info_logged):
                    Logger.log(
                        "Successfully disconnection from server {}:{}".format(
                            host, port), LoggedMessageType.SUCCESS)
                return True
        if (are_info_logged):
            Logger.log("No connection with server {}:{}".format(host, port),
                       LoggedMessageType.FAIL)
        return False

    def disconnect_from_all_servers(self):
        """Disconnects from all connected subordinate servers.
        """
        if (len(self._connections) > 0):
            disconnections = 0
            for connection in self._connections:
                if (self.disconnect_from_server(connection.host,
                                                connection.port, False,
                                                False)):
                    disconnections += 1
            self._connections.clear()
            Logger.log(
                "Successfully disconnected from {} servers".format(
                    disconnections), LoggedMessageType.SUCCESS)

        Logger.log("No server to disconnect from", LoggedMessageType.FAIL)

    def _get_server_status(self, is_busy: bool):
        return "BUSY" if is_busy else "AVAILABLE"

    def list_connections(self):
        """Lists active connections with subordinate servers.
        """
        if (len(self._connections) > 0):
            Logger.log("Active connections are:",
                       LoggedMessageType.CONNECTIONS)
            for connection in self._connections:
                Logger.log("\t- {}:{} with status {}".format(
                    connection.host, connection.port,
                    self._get_server_status(connection.is_busy)))

        Logger.log("No connection at the moment", LoggedMessageType.FAIL)

    def _get_first_free_server(self) -> _Connection:
        for connection in self._connections:
            if (not connection.is_busy):
                connection.is_busy = True
                return connection
        return None

    def _delegate_task_to_server(self, connection: _Connection,
                                 method_name: str, callback: typing.Callable,
                                 *arguments) -> bool:
        wanted_function = getattr(connection.effective_connection.root,
                                  method_name)
        async_result = rpyc.async_(wanted_function)(*arguments)
        async_result.add_callback(callback)
        self._answers.append(async_result)

    def train_model_by_skeleton(self):
        """Mimics the training of a machine learning model.

        This method will be removed soon.
        """
        connection = self._get_first_free_server()
        if (connection):
            Logger.log(
                "Successfully found free server {}:{}".format(
                    connection.host, connection.port),
                LoggedMessageType.NEW_MESSAGE)
            self._delegate_task_to_server(connection, "train_new_model",
                                          SubordinateLeader._consume_new_model)

        Logger.log("No free server can execute the task",
                   LoggedMessageType.FAIL)

    def _consume_new_model_from_instance(
            self, async_result: rpyc.AsyncResult) -> None:
        for connection in self._connections:
            # pylint: disable=protected-access
            if (connection.effective_connection == async_result._conn):
                # The availability results from previous delegated tasks and
                # received response. For example, if a task was delegated to a
                # specific subordinate server and it responds with the result
                # of the task, that means it becomes available and can execute
                # new tasks.
                connection.is_busy = False
                break

    @staticmethod
    def _consume_new_model(async_result: rpyc.AsyncResult) -> None:
        # Get the singleton instance
        global_instance = SubordinateLeader(0, "", 0)
        # pylint: disable=protected-access
        global_instance._consume_new_model_from_instance(async_result)

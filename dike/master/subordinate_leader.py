import rpyc
import ipaddress
import threading
import os
import tqdm
import time
import typing
from pypattyrn.creational.singleton import Singleton
from utils.configuration import ConfigurationWorker, ConfigurationSpace
from utils.logger import Logger


class _Connection:
    host: str = None
    port: int = None
    connection: rpyc.Connection = None
    is_busy: bool = False

    def __init__(self, host, port, connection):
        self.host = host
        self.port = port
        self.effective_connection = connection


class SubordinateLeader(object, metaclass=Singleton):
    _service_name: str = None
    _default_port_number: int = -1
    _connections: typing.List[_Connection] = []
    _answers: typing.List[rpyc.AsyncResult] = []
    _answers_thread: threading.Thread = None
    _stop_needed: bool = False

    def __init__(self,
                 default_port_number: int = -1,
                 service_name: str = None,
                 answers_checking_interval: int = 0):
        self._default_port_number = default_port_number
        self._service_name = service_name
        self._answers_thread = threading.Thread(
            target=self._check_answers, args=(answers_checking_interval, ))
        self._answers_thread.start()

    def stop(self):
        self._stop_needed = True

    def _check_answers(self, sleep_seconds: int):
        while (not self._stop_needed):
            for answer in self._answers:
                answer.ready

            time.sleep(sleep_seconds)

    def connect_to_server(self,
                          host: str,
                          port: int,
                          service_name: str = None,
                          are_info_logged: bool = True) -> bool:
        try:
            connection = rpyc.connect(host, port)
            if (service_name.upper() in connection.root.get_service_aliases()):
                self._connections.append(_Connection(host, port, connection))
                if (are_info_logged):
                    Logger.print_on_screen(
                        ":white_check_mark: Successfully connected to server {}:{}"
                        .format(host, port))
                return True
            else:
                return False
        except:
            if (are_info_logged):
                Logger.print_on_screen(
                    ":x: Error on connection to server {}:{}".format(
                        host, port))
            return False

    def connect_to_all_servers(self, network: str) -> None:
        try:
            new_connections = 0
            addresses = ipaddress.IPv4Network(network)
            Logger.print_on_screen(
                ":clock830: Starting to scan the given network")
            progress_bar = tqdm.tqdm(total=len(list(addresses)))
            for ip in addresses:
                if (self.connect_to_server(str(ip), self._default_port_number,
                                           self._service_name, False)):
                    new_connections += 1
                progress_bar.update(1)
            progress_bar.close()
            if (new_connections > 0):
                Logger.print_on_screen(
                    ":white_check_mark: Successfully connected to {} servers".
                    format(new_connections))
            else:
                Logger.print_on_screen(
                    ":no_entry_sign: No server to connect to")
        except:
            Logger.print_on_screen(":x: Invalid network")

    def disconnect_from_server(self,
                               host: str,
                               port: int,
                               delete_host: bool = True,
                               are_info_logged: bool = True) -> bool:
        for connection in self._connections:
            if (connection.host == host and connection.port == port):
                del connection.effective_connection
                if delete_host:
                    self._connections = [
                        connection for connection in self._connections
                        if connection.host != host and connection.port != port
                    ]
                if (are_info_logged):
                    Logger.print_on_screen(
                        ":white_check_mark: Successfully disconnection from server {}:{}"
                        .format(host, port))
                return True
        if (are_info_logged):
            Logger.print_on_screen(
                ":x: No connection with server {}:{}".format(host, port))
        return False

    def disconnect_from_all_servers(self):
        if (len(self._connections) > 0):
            disconnections = 0
            for connection in self._connections:
                if (self.disconnect_from_server(connection.host,
                                                connection.port, False,
                                                False)):
                    disconnections += 1
            self._connections.clear()
            Logger.print_on_screen(
                ":white_check_mark: Successfully disconnected from {} servers".
                format(disconnections))
        else:
            Logger.print_on_screen(
                ":no_entry_sign: No server to disconnect from")

    def _get_server_status(self, is_busy: bool):
        return "BUSY" if is_busy else "AVAILABLE"

    def list_connections(self):
        if (len(self._connections) > 0):
            Logger.print_on_screen(":link: Active connections are:")
            for connection in self._connections:
                Logger.print_on_screen("\t- {}:{} with status {}".format(
                    connection.host, connection.port,
                    self._get_server_status(connection.is_busy)))
        else:
            Logger.print_on_screen(
                ":no_entry_sign: No connection at the moment")

    def get_first_free_server(self) -> _Connection:
        for connection in self._connections:
            if (not connection.is_busy):
                connection.is_busy = True
                return connection
        return None

    def delegate_task_to_server(self, connection: _Connection,
                                method_name: str, callback: typing.Callable,
                                *arguments) -> bool:
        wanted_function = getattr(connection.effective_connection.root,
                                  method_name)
        async_result = rpyc.async_(wanted_function)(*arguments)
        async_result.add_callback(callback)
        self._answers.append(async_result)

    def train_model_by_skeleton(self):
        connection = self.get_first_free_server()
        if (connection):
            Logger.print_on_screen(
                ":email: Successfully found free server {}:{}".format(
                    connection.host, connection.port))
            self.delegate_task_to_server(connection, "train_new_model",
                                         SubordinateLeader.consume_new_model)
        else:
            Logger.print_on_screen(
                ":no_entry_sign: No free server can execute the task")

    def _consume_new_model(self, async_result: rpyc.AsyncResult) -> None:
        for connection in self._connections:
            if (connection.effective_connection == async_result._conn):
                connection.is_busy = False
                break

    @staticmethod
    def consume_new_model(async_result: rpyc.AsyncResult) -> None:
        SubordinateLeader()._consume_new_model(async_result)
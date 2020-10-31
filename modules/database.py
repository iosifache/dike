""" Database functionality """

import pymongo


class DatabaseWorker:

    _host: str = None
    _port: str = None
    _client: pymongo.MongoClient = None
    _username: str = None
    _password: str = None
    _database: pymongo.database.Database = None
    _database_name: str = None
    _collection: pymongo.database.Collection = None
    _collection_name: str = None

    def __init__(self, host: str, port: int, username: str, password: str,
                 database: str):
        if (host is None or (port < 0 or port > 65535) or username is None
                or password is None or database is None):
            return None
        try:
            self._client = pymongo.MongoClient(host,
                                               port,
                                               username=username,
                                               password=password,
                                               authSource="admin",
                                               authMechanism="SCRAM-SHA-256")
            self._database = self._client[database]
            self._host = host
            self._port = port
            self._username = username
            self._password = password
        except Exception:
            return None

    def use_collection(self, collection: str) -> bool:
        """Sets a collection to be used in next operations

        Args:
            collection: The name of the collection

        Returns:
            A boolean that indicates if the collection could be used
        """
        if (collection == self._collection):
            return True
        if (collection not in self._database.collection_names()):
            return False
        self._collection = self._database[collection]
        self._collection_name = collection
        return True

    def query_all(self) -> pymongo.cursor.Cursor:
        """Query all collections from current collection
        
        Returns:
            Cursor to the iterate through Mongo query results
        """
        return self._collection.find({})

    def query_one(self, query: dict) -> dict:
        """Queries the current collection using a specific query

        Args:
            query: The query used to filter the collection entries
        
        Returns:
            The first object finded with the given query
        """
        return self._collection.find_one(query)

    def insert_one(self, new: dict) -> bool:
        """Inserts an object into current collection

        Args:
            new: The inserted object
        
        Returns:
            The status of the insertion operation
        """
        return self._collection.insert_one(new).acknowledged

    def insert_many(self, many: list) -> bool:
        """Inserts multiple values into current collection

        Args:
            many: List of inserted objects
        
        Returns:
            The status of the insertion operation
        """
        return self._collection.insert_many(many).acknowledged

    def delete_all(self) -> bool:
        """Deletes all values from the current collection

        Returns:
            The status of the deletion operation
        """
        return self._collection.delete_many({}).acknowledged

    def update(self, selector: dict, modifier: dict) -> bool:
        """Updates documents from current collection

        Args:
            selector: The query used to filter the updated documents
        
        Returns:
            The status of the update operation
        """
        return (self._collection.update(selector, modifier)["ok"] == 1)
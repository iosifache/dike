#!/usr/bin/env python3

from modules import database
from modules import utils

database_config = utils.ConfigurationWorker(
    "config.yaml").get_configuration_space(utils.ConfigurationSpace.DATABASE)

database_worker = database.DatabaseWorker(host=database_config["host"],
                                          port=database_config["port"],
                                          username=database_config["username"],
                                          password=database_config["password"],
                                          database=database_config["database"])

if (database_worker.use_collection("collection")):
    records = database_worker.query_all()
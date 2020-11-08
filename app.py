#!/usr/bin/env python3

from modules.extractors import core
from modules.extractors import extractors
from modules import database
from modules import utils

config = utils.ConfigurationWorker("config.yaml")

# Test connection to database

if False:

    database_config = config.get_configuration_space(
        utils.ConfigurationSpace.DATABASE)

    database_worker = database.DatabaseWorker(
        host=database_config["host"],
        port=database_config["port"],
        username=database_config["username"],
        password=database_config["password"],
        database=database_config["database"])

    if (database_worker.use_collection("collection")):
        records = database_worker.query_all()

# Test extraction of features
extractors_config = config.get_configuration_space(
    utils.ConfigurationSpace.EXTRACTORS)
extractor_master = core.ExtractorMaster(extractors_config,
                                        "tests/files/hello.exe")
extractor_master.attach(extractors.StringsExtractor())
extractor_master.attach(extractors.OpcodesExtractor())
extractor_master.attach(extractors.OpcodesExtractor())
extractor_master.squeeze()
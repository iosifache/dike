#!/usr/bin/env python3

from modules import extractors
from modules import database
from modules import utils

config = utils.ConfigurationWorker("config.yaml")

# Test connection to database

database_config = config.get_configuration_space(
    utils.ConfigurationSpace.DATABASE)

database_worker = database.DatabaseWorker(host=database_config["host"],
                                          port=database_config["port"],
                                          username=database_config["username"],
                                          password=database_config["password"],
                                          database=database_config["database"])

if (database_worker.use_collection("collection")):
    records = database_worker.query_all()

# Test extraction of features from static analysis

extractors_config = config.get_configuration_space(
    utils.ConfigurationSpace.EXTRACTORS)

master = extractors.ExtractorMaster("tests/files/hello.exe")

string_extractor = extractors.Strings(
    extractors_config["strings"]["minimum_string_length"],
    extractors_config["strings"]["minimum_occurances"])
pe_extractor = extractors.PECharacteristics()

master.extract(string_extractor)
master.extract(pe_extractor)
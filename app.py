#!/usr/bin/env python3

from modules import utils

database_config = utils.ConfigurationWorker(
    "config.yaml").get_configuration_space(utils.ConfigurationSpace.DATABASE)
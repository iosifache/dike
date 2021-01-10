#!/usr/bin/env python3

import json
import os
import sys
import typing
import subordinate.modules.core as extraction_core
import subordinate.modules.extractors as extractors
from utils.configuration import ConfigurationWorker, ConfigurationSpace
from utils.logger import Logger

# Define usages
HELP = """
The corect usage of this script is the following:
    {} EXECUTABLE_FILE CONFIGURATION_FILE EXTRACTORS

The parameter EXTRACTORS is a sequence of letters that denote the extractors 
used for file analysis. These letters can be:
- "S" for strings;
- "P" for PE characteristics;
- "O" for opcodes; and
- "A" for API calls."""


def check_extractors_string(string: str) -> bool:
    for char in string:
        if char not in "SPOA":
            return False
    return True


def main():

    # Check arguments
    if not (len(sys.argv) == 4 and os.path.isfile(sys.argv[1])
            and os.path.isfile(sys.argv[2])
            and check_extractors_string(sys.argv[3])):
        Logger.log_fail("Invalid (number of) arguments")
        Logger.log(HELP.format(sys.argv[0]))
        exit(1)

    # Get parameters
    executable_file = os.path.abspath(sys.argv[1])
    configuration_file = os.path.abspath(sys.argv[2])
    extractors_string = sys.argv[3]

    # Read configuration
    all_config = ConfigurationWorker(configuration_file)
    config = all_config.get_configuration_space(ConfigurationSpace.EXTRACTORS)

    # Create master and attach extractors
    master = extraction_core.ExtractorMaster(config, executable_file)
    for extractor_id in extractors_string:
        # Create the extractor
        if extractor_id == "S":
            extractor = extractors.StringsExtractor()
        elif extractor_id == "P":
            extractor = extractors.PECharacteristicsExtractor()
        elif extractor_id == "O":
            extractor = extractors.OpcodesExtractor()
        elif extractor_id == "A":
            extractor = extractors.APIsExtractor()

        # Attach the extractor
        master.attach(extractor)

    # Squeeze and log attributes
    attributes = master.squeeze()
    Logger.log_success(
        "Extracted attributes from file are: \n{}".format(attributes))


if __name__ == "__main__":
    main()
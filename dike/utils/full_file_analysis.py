#!/usr/bin/env python3

import json
import os
import sys
import subordinate.modules.extractors.core as extraction_core
import subordinate.modules.extractors.extractors as extractors
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


def _check_extractors_string(string: str) -> bool:
    for char in string:
        if char not in "SPOA":
            return False
    return True


def main():

    # Check arguments
    if not (len(sys.argv) == 4 and os.path.isfile(sys.argv[1])
            and os.path.isfile(sys.argv[2])
            and _check_extractors_string(sys.argv[3])):
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
    if "S" in extractors_string:
        master.attach(extractors.StringsExtractor())
    if "P" in extractors_string:
        master.attach(extractors.PECharacteristicsExtractor())
    if "O" in extractors_string:
        master.attach(extractors.OpcodesExtractor())
    if "A" in extractors_string:
        master.attach(extractors.APIsExtractor())

    # Squeeze and log attributes
    attributes = master.squeeze()
    formatted_attributes = json.dumps(attributes, indent=4)
    Logger.log_success("Extracted attributes from file are: \n{}".format(
        formatted_attributes))


if __name__ == "__main__":
    main()
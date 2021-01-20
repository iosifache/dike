#!/usr/bin/env python3
"""Script for applying extractors to a given file

Usage:
    full_file_analysis.py EXECUTABLE_FILE CONFIGURATION_FILE EXTRACTORS

The parameter EXTRACTORS is a sequence of letters that denote the extractors 
used for file analysis. These letters can be:
- "S" for strings;
- "P" for PE characteristics;
- "O" for opcodes; and
- "A" for API calls.
"""

import os
import sys
import subordinate.modules.features_extraction.core as extraction_core
import subordinate.modules.features_extraction.extractors as extractors
from utils.configuration import ConfigurationWorker, ConfigurationSpace
from utils.logger import Logger, LoggerMessageType


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
        Logger.log("Invalid (number of) arguments", LoggerMessageType.FAIL)
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
        extractor = None
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
    Logger.log("Extracted attributes from file are: \n{}".format(attributes),
               LoggerMessageType.SUCCESS)


if __name__ == "__main__":
    main()
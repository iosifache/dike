#!/usr/bin/env python3
"""Script for applying extractors to a given file.

Usage:
    full_file_analysis.py EXECUTABLE_FILE CONFIGURATION_FILE EXTRACTORS

The parameter EXTRACTORS is a sequence of letters that denote the extractors
used for file analysis. These letters can be:
- static analysis
    - "S" for strings
    - "P" for PE characteristics
- dynamic analysis
    - "O" for opcodes
    - "A" for API calls.
"""

import os
import sys

import subordinate.modules.features_extraction.core as extraction_core
from subordinate.modules.features_extraction.types import ExtractorsType
from utils.configuration import ConfigurationSpace, ConfigurationWorker
from utils.logger import LoggedMessageType, Logger


def _check_extractors_string(string: str) -> bool:
    for char in string:
        if char not in "SPOA":
            return False
    return True


def main():
    """Main function
    """

    # Check arguments
    if not (len(sys.argv) == 4 and os.path.isfile(sys.argv[1])
            and os.path.isfile(sys.argv[2])
            and _check_extractors_string(sys.argv[3])):
        Logger.log("Invalid (number of) arguments", LoggedMessageType.FAIL)
        exit(1)

    # Get parameters
    executable_file = os.path.abspath(sys.argv[1])
    configuration_file = os.path.abspath(sys.argv[2])
    extractors_string = sys.argv[3]

    # Read configuration
    all_config = ConfigurationWorker(configuration_file)
    config = all_config.get_configuration_space(ConfigurationSpace.EXTRACTORS)

    # Create master and attach extractors
    master = extraction_core.ExtractionCore(config, executable_file)
    for extractor_id in extractors_string:
        # Get the extractor type
        extractor_type = None
        if extractor_id == "S":
            extractor_type = ExtractorsType.STATIC_STRINGS
        elif extractor_id == "P":
            extractor_type = ExtractorsType.STATIC_PE_CHARACTERISTICS
        elif extractor_id == "O":
            extractor_type = ExtractorsType.DYNAMIC_OPCODES
        elif extractor_id == "A":
            extractor_type = ExtractorsType.DYNAMIC_APIS

        # Attach an extractor by type
        master.attach(extractor_type)

    # Squeeze and log attributes
    attributes = master.squeeze()
    Logger.log("Extracted attributes from file are: \n{}".format(attributes),
               LoggedMessageType.SUCCESS)


if __name__ == "__main__":
    main()

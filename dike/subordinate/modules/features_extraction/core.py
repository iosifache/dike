"""Feature extractors for files"""

import pefile
import qiling
import qiling.const
import capstone
import os
from pypattyrn.creational.singleton import Singleton
import typing
import subordinate.modules.features_extraction.extractors as extractors
import subordinate.modules.features_extraction.carriers as carriers
from configuration.dike import DikeConfig


class ExtractorMaster(object, metaclass=Singleton):
    """Class managing the process of extracting features from file by applying
    extractors"""
    _filename: str = None
    _configuration: typing.Any = None
    _static_bucket: carriers._StaticBucket = carriers._StaticBucket()
    _dynamic_bucket: carriers._DynamicBucket = carriers._DynamicBucket()
    _extractors: typing.List[extractors._Extractor] = []

    def __init__(self, configuration: typing.Any, filename: str):
        """Initializes the ExtractorMaster instance.

        Args:
            configuration (typing.Any): User configuration of the platform
            filename (str): Name of the target file
        """
        self._configuration = configuration
        self._filename = filename

    def attach(self, extractor: extractors._Extractor) -> None:
        """Attaches an extractor to the master.

        Args:
            extractor (extractors._Extractor): Extractor instance being attached
        """
        self._extractors.append(extractor)

    @staticmethod
    def _hook_instruction(qiling_instance: qiling.Qiling, address: int,
                          size: int, others: tuple) -> None:
        # Read current instruction and the parameters
        instructions = qiling_instance.mem.read(address, size)
        disassembler = others[0]
        list_of_opcodes = others[1]

        # Append the disassembled instructions to the list
        for instruction in disassembler.disasm(instructions, address):
            list_of_opcodes.append(instruction.mnemonic)

    @staticmethod
    def _check_extractor_type(extractor: extractors._Extractor,
                              class_instance: extractors._Extractor) -> bool:
        return (type(extractor).__name__ == type(class_instance).__name__)

    def squeeze(self) -> list:
        """Returns a list of all features, resulted from the process of applying
        each extractor.

        The list of returned features varies depending on the attached
        extractors.

        Returns:
            list: List of extracted features
        """
        content_needed = False
        pe_file_needed = False
        disassembler_needed = False
        emulator_needed = False

        # Verify what elements are needed and set the configuration for each of them
        pe_characteristics_present = False
        for extractor in self._extractors:
            if ExtractorMaster._check_extractor_type(
                    extractor, extractors.StringsExtractor()):
                extractor.set_configuration(
                    self._configuration["strings"]["minimum_string_length"],
                    self._configuration["strings"]["minimum_occurances"])

                # Content needed for string extraction
                content_needed = True
            else:
                # PE file parser needed for all extractor, except the string one
                pe_file_needed = True
                if not ExtractorMaster._check_extractor_type(
                        extractor, extractors.PECharacteristicsExtractor()):
                    # Emulator and disassembler needed for extractors based on
                    # dynamic analysis
                    emulator_needed = True
                    disassembler_needed = True
                else:
                    pe_characteristics_present = True

                # Initialize the extractor for API calls
                if ExtractorMaster._check_extractor_type(
                        extractor, extractors.APIsExtractor()):
                    extractor.set_configuration(
                        self._configuration["apis"]["ignored_prefixes"],
                        self._configuration["apis"]["ignored_suffixes"])

        # Initialize needed elements
        if content_needed or emulator_needed:
            self._static_bucket.content = open(self._filename, "rb").read()
        if pe_file_needed:
            self._static_bucket.pe_file = pefile.PE(self._filename)
        if disassembler_needed:
            # Member exists in the pefile structure pylint: disable=no-member
            if self._static_bucket.pe_file.FILE_HEADER.Machine == 0x14c:
                rootfs = "x86_windows"
                capstone_mode = capstone.CS_MODE_32
            else:
                rootfs = "x8664_windows"
                capstone_mode = capstone.CS_MODE_64

            # Create disassemble
            disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone_mode)
            disassembler.detail = True
            self._static_bucket.disassembler = disassembler

            # Check the Qiling rootfs folder and create the emulator
            qiling_rootfs = os.path.join(DikeConfig.QILING_ROOTFS_FOLDER,
                                         rootfs)
            emulator = qiling.Qiling([self._filename],
                                     qiling_rootfs,
                                     ostype="windows",
                                     console=False,
                                     log_dir=DikeConfig.QILING_LOGS_FOLDER)

            # Set the log file to be processed by the API extractors
            _, filename = os.path.split(self._filename)
            self._dynamic_bucket.log_file = os.path.join(
                DikeConfig.QILING_LOGS_FOLDER,
                filename + "." + DikeConfig.QILING_LOG_EXTENSION)

            # Hook on each executed instruction and API call
            emulator.hook_code(ExtractorMaster._hook_instruction,
                               (disassembler, self._dynamic_bucket.opcodes))

            # Run emulator
            self._dynamic_bucket.emulator = emulator
            try:
                self._dynamic_bucket.emulator.run()
            except:
                pass

        # Apply each extractor
        for extractor in self._extractors:
            extractor.extract(self._static_bucket, self._dynamic_bucket)

        # Remove from strings the imported libraries/functions if an
        # PECharacteristicExtractor was used
        if pe_characteristics_present:
            self._static_bucket.strings = [
                found_string for found_string in self._static_bucket.strings if
                (found_string not in self._static_bucket.imported_libraries and
                 found_string not in self._static_bucket.imported_functions)
            ]

        # Squeeze data from each extractor
        extracted_features = []
        for extractor in self._extractors:
            extractor_features = extractor.squeeze(self._static_bucket,
                                                   self._dynamic_bucket)
            extracted_features.extend(extractor_features)

        return extracted_features
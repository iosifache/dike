"""Feature extractors for files"""

import os
import typing

import capstone
import pefile
import qiling
import qiling.const
import modules.features_extraction.carriers as carriers
import modules.features_extraction.extractors as extractors
from configuration.dike import DikeConfig
from pypattyrn.creational.singleton import Singleton
from modules.features_extraction.ghidra_wrapper import \
    GhidraWrapper
from modules.types import AnalyzedFileTypes, ExtractorsType
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker


class ExtractionCore(object, metaclass=Singleton):
    """Class managing the process of extracting features from file by applying
    extractors"""
    _configuration: typing.Any = None
    _static_bucket: carriers.StaticBucket = None
    _dynamic_bucket: carriers.DynamicBucket = None
    _document_bucket: carriers.DocumentBucket = None
    _analyzed_file_types: typing.Set[AnalyzedFileTypes] = {}
    _extractors: typing.List[extractors.Extractor] = []

    def __init__(self) -> None:
        """Initialized the ExtractionCore instance."""
        # Read the extractors configuration
        full_config = ConfigurationWorker()
        self._configuration = full_config.get_configuration_space(
            ConfigurationSpace.EXTRACTORS)

    @staticmethod
    def load_extractor_by_name(name: str) -> extractors.Extractor:
        """Creates an instance of an extractor.

        Args:
            name (str): Name of the extractor

        Returns:
            extractors.Extractor: Extractor being request
        """
        return getattr(extractors, name, None)

    def attach(self, extractor_type: ExtractorsType) -> None:
        """Attaches an extractor to the master.

        Args:
            extractor (extractors.Extractor): Extractor instance being attached
        """
        extractor = ExtractionCore.load_extractor_by_name(extractor_type.value)
        file_types = extractor.get_analyzed_file_types()
        if not self._extractors:
            self._analyzed_file_types = file_types
            self._extractors.append(extractor())
        if file_types.issubset(self._analyzed_file_types):
            self._extractors.append(extractor())

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
    def _check_extractor_type(extractor: extractors.Extractor,
                              class_instance: extractors.Extractor) -> bool:
        return (type(extractor).__name__ == type(class_instance).__name__)

    def squeeze(self, filename: str) -> list:
        """Returns a list of all features, resulted from the process of applying
        each extractor.

        The list of returned features varies depending on the attached
        extractors.

        Args:
            filename (str): Name of the target file

        Returns:
            list: List of extracted features
        """
        # Create new buckets for data
        self._static_bucket = carriers.StaticBucket()
        self._dynamic_bucket = carriers.DynamicBucket()
        self._document_bucket = carriers.DocumentBucket()

        # Verify what elements are needed and set the configuration for each of
        # them
        content_needed = False
        pe_file_needed = False
        pe_characteristics_present = False
        decompiler_needed = False
        emulator_needed = False
        disassembler_needed = False
        for extractor in self._extractors:
            apis_present = False

            if ExtractionCore._check_extractor_type(
                    extractor, extractors.StaticStrings()):
                # Set the configuration
                extractor.set_configuration(
                    self._configuration["strings"]["minimum_string_length"],
                    self._configuration["strings"]["minimum_occurances"])

                content_needed = True
            elif ExtractionCore._check_extractor_type(
                    extractor, extractors.StaticPECharacteristics()):
                pe_file_needed = True
                pe_characteristics_present = True
            elif ExtractionCore._check_extractor_type(
                    extractor, extractors.StaticOpcodes()):
                decompiler_needed = True
            elif ExtractionCore._check_extractor_type(extractor,
                                                      extractors.StaticAPIs()):
                apis_present = True
                decompiler_needed = True
            elif ExtractionCore._check_extractor_type(
                    extractor, extractors.DynamicOpcodes()):
                pe_file_needed = True
                emulator_needed = True
                disassembler_needed = True
            elif ExtractionCore._check_extractor_type(
                    extractor, extractors.DynamicAPIs()):
                apis_present = True
                pe_file_needed = True
                emulator_needed = True
                disassembler_needed = True

            # If needed, set the configuration for APIs
            if apis_present:
                extractor.set_configuration(
                    self._configuration["apis"]["ignored_prefixes"],
                    self._configuration["apis"]["ignored_suffixes"])

        # Initialize needed elements
        if content_needed or emulator_needed:
            self._static_bucket.content = open(filename, "rb").read()
        if pe_file_needed:
            self._static_bucket.pe_file = pefile.PE(filename)
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
            emulator = qiling.Qiling([filename],
                                     qiling_rootfs,
                                     ostype="windows",
                                     console=False,
                                     log_dir=DikeConfig.QILING_LOGS_FOLDER)

            # Set the log file to be processed by the API extractors
            _, filename = os.path.split(filename)
            self._dynamic_bucket.log_file = os.path.join(
                DikeConfig.QILING_LOGS_FOLDER,
                filename + "." + DikeConfig.QILING_LOG_EXTENSION)

            # Hook on each executed instruction and API call
            emulator.hook_code(ExtractionCore._hook_instruction,
                               (disassembler, self._dynamic_bucket.opcodes))

            # Run emulator
            self._dynamic_bucket.emulator = emulator
            try:
                self._dynamic_bucket.emulator.run()
            except:
                pass
        if decompiler_needed:
            result = GhidraWrapper.analyse_file(filename, True, True)
            self._static_bucket.opcodes = result[0]
            self._static_bucket.apis = result[1]

        # Save the filename if it is a document
        if (AnalyzedFileTypes.OLE in self._analyzed_file_types):
            self._document_bucket.filename = filename

        # Apply each extractor
        for extractor in self._extractors:
            extractor.extract(self._static_bucket, self._dynamic_bucket,
                              self._document_bucket)

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
                                                   self._dynamic_bucket,
                                                   self._document_bucket)
            extracted_features.extend(extractor_features)

        return extracted_features

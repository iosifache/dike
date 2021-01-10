"""Feature extractors for files"""

import pefile
import qiling
import qiling.const
import capstone
import os
from sklearn.base import BaseEstimator
from pypattyrn.creational.singleton import Singleton
import typing
import subordinate.modules.extractors as extractors
import subordinate.modules.carriers as carriers

QILING_LOG_EXTENSION = "qlog"


class ExtractorMaster(object, metaclass=Singleton):
    _filename: str = None
    _configuration: typing.Any = None
    _static_bucket: carriers._StaticBucket = carriers._StaticBucket()
    _dynamic_bucket: carriers._DynamicBucket = carriers._DynamicBucket()
    _extractors: typing.List[extractors._Extractor] = []

    def __init__(self, configuration: typing.Any, filename: str):
        self._configuration = configuration
        self._filename = filename

    def attach(self, extractor: extractors._Extractor) -> None:
        self._extractors.append(extractor)

    @staticmethod
    def _hook_instruction(qiling_instance: qiling.Qiling, address: int,
                          size: int, others: tuple) -> None:
        instructions = qiling_instance.mem.read(address, size)
        disassambler = others[0]
        list_of_opcodes = others[1]
        for instruction in disassambler.disasm(instructions, address):
            list_of_opcodes.append(instruction.mnemonic)

    @staticmethod
    def _check_extractor_type(extractor: extractors._Extractor,
                              class_instance: extractors._Extractor) -> bool:
        return (type(extractor).__name__ == type(class_instance).__name__)

    def squeeze(self) -> list:
        content_needed = False
        pe_file_needed = False
        disassambler_needed = False
        emulator_needed = False

        # Verify what elements are needed and set configuration for each of them
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
                    # Emulator and disassambler needed for extractors based on
                    # dynamic analysis
                    emulator_needed = True
                    disassambler_needed = True
                else:
                    pe_characteristics_present = True

        # Initialize needed elements
        if content_needed or emulator_needed:
            self._static_bucket.content = open(self._filename, "rb").read()
        if pe_file_needed:
            self._static_bucket.pe_file = pefile.PE(self._filename)
        if disassambler_needed:
            # Member exists in the pefile structure pylint: disable=no-member
            if self._static_bucket.pe_file.FILE_HEADER.Machine == 0x14c:
                rootfs = "x86_windows"
                capstone_mode = capstone.CS_MODE_32
            else:
                rootfs = "x8664_windows"
                capstone_mode = capstone.CS_MODE_64

            # Create disassambler
            disassambler = capstone.Cs(capstone.CS_ARCH_X86, capstone_mode)
            disassambler.detail = True
            self._static_bucket.disassambler = disassambler

            # Check Qiling rootfs folder and create emulator
            qiling_rootfs = os.path.join(
                self._configuration["dynamic"]["qiling_rootfs"], rootfs)
            if not os.path.isdir(qiling_rootfs):
                raise FileNotFoundError()
            emulator = qiling.Qiling(
                [self._filename],
                qiling_rootfs,
                ostype="windows",
                console=False,
                log_dir=self._configuration["dynamic"]["log_folder"])

            # Set the log file to be processed by the API extractors
            _, filename = os.path.split(self._filename)
            self._dynamic_bucket.log_file = os.path.join(
                self._configuration["dynamic"]["log_folder"],
                filename + "." + QILING_LOG_EXTENSION)

            # Hook on each executed instruction and API call
            emulator.hook_code(ExtractorMaster._hook_instruction,
                               (disassambler, self._dynamic_bucket.opcodes))

            # Run emulator
            self._dynamic_bucket.emulator = emulator
            try:
                self._dynamic_bucket.emulator.run()
            except:
                pass

        # Apply each extractor
        for extractor in self._extractors:
            extractor.extract(self._static_bucket, self._dynamic_bucket)

        # Remove from strings the imported libraries / functions if an
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
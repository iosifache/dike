"""Feature extractors for files"""

import pefile
import qiling
import qiling.const
import capstone
import os
from pypattyrn.creational.singleton import Singleton
import typing
import subordinate.modules.extractors.extractors as extractors
import subordinate.modules.extractors.carriers as carriers

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

    def attach(self, extractor: extractors._Extractor) -> bool:
        self._extractors.append(extractor)

    @staticmethod
    def hook_instruction(qiling_instance: qiling.Qiling, address: int,
                         size: int, others: tuple) -> None:
        instructions = qiling_instance.mem.read(address, size)
        disassambler = others[0]
        list_of_opcodes = others[1]
        for instruction in disassambler.disasm(instructions, address):
            list_of_opcodes.append(instruction.mnemonic)

    @staticmethod
    def _check_extractor_type(extractor: extractors._Extractor,
                              class_instance: extractors._Extractor):
        return (type(extractor).__name__ == type(class_instance).__name__)

    def squeeze(self) -> dict:
        content_needed = False
        pe_file_needed = False
        disassambler_needed = False
        emulator_needed = False

        # Verify what elements are needed and set configuration for each of them
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
                if ExtractorMaster._check_extractor_type(
                        extractor, extractors.OpcodesExtractor()):
                    extractor.set_configuration(
                        self._configuration["opcodes"]["categories"],
                        self._configuration["opcodes"]["min_ignored_percent"])
                if not ExtractorMaster._check_extractor_type(
                        extractor, extractors.PECharacteristicsExtractor()):
                    # Emulator and disassambler needed for extractors based on
                    # dynamic analysis
                    emulator_needed = True
                    disassambler_needed = True

                    if ExtractorMaster._check_extractor_type(
                            extractor, extractors.APIsExtractor()):
                        extractor.set_configuration(
                            self._configuration["apis"]["categories"],
                            self._configuration["apis"]["min_ignored_percent"])

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
            emulator.hook_code(ExtractorMaster.hook_instruction,
                               (disassambler, self._dynamic_bucket.opcodes))

            # Run emulator
            self._dynamic_bucket.emulator = emulator
            try:
                self._dynamic_bucket.emulator.run()
            except:
                pass

        # Use each extractor and save the results
        attributes = {"filename": self._filename}
        for extractor in self._extractors:

            extractor.extract(self._static_bucket, self._dynamic_bucket)

            if ExtractorMaster._check_extractor_type(
                    extractor, extractors.StringsExtractor()):
                attributes["strings"] = self._static_bucket.strings
            elif ExtractorMaster._check_extractor_type(
                    extractor, extractors.PECharacteristicsExtractor()):
                attributes["sections"] = self._static_bucket.sections
                attributes[
                    "imported_libraries"] = self._static_bucket.imported_libraries
                attributes[
                    "imported_functions"] = self._static_bucket.imported_functions
                attributes[
                    "exported_functions"] = self._static_bucket.exported_functions
            elif ExtractorMaster._check_extractor_type(
                    extractor, extractors.OpcodesExtractor()):
                attributes[
                    "opcodes_categories"] = self._dynamic_bucket.opcodes_freqs
            elif ExtractorMaster._check_extractor_type(
                    extractor, extractors.APIsExtractor()):
                attributes["api_categories"] = self._dynamic_bucket.apis_freqs

        return attributes
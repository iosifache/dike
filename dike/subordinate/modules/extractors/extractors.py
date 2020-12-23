import collections
import abc
import typing
import modules.extractors.carriers as carriers


class _Extractor(abc.ABC):
    @abc.abstractmethod
    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        pass


class StringsExtractor(_Extractor):
    _min_length: int = 1
    _min_occurances: int = 1

    def set_configuration(self, min_length: int, min_occurances: int):
        self._min_length = min_length
        self._min_occurances = min_occurances

    @staticmethod
    def _get_printable_chars() -> bytes:
        chars = 256 * ['\0']
        for i in range(32, 127):
            chars[i] = chr(i)
        chars[ord('\n')] = "\n"
        chars[ord('\t')] = "\t"
        return "".join(chars).encode("utf-8")

    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        all_strings = static_bucket.content.translate(
            self._get_printable_chars()).split(b'\0')
        if (self._min_length != 1):
            all_strings = [
                str(string) for string in all_strings
                if len(string) > self._min_length
            ]
        if (self._min_occurances != 1):
            counter = collections.Counter(all_strings)
            all_strings = [
                string for string in counter.elements()
                if counter[string] >= self._min_occurances
            ]
        static_bucket.strings = all_strings


class PECharacteristicsExtractor(_Extractor):
    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        imported_libraries = []
        imported_functions = []
        exported_functions = []
        sections = []
        for section in static_bucket.pe_file.sections:
            sections.append(
                carriers._SectionCharacteristics(section.Name.decode("utf-8"),
                                                 section.get_entropy(),
                                                 section.Misc_VirtualSize,
                                                 section.SizeOfRawData))
        if hasattr(static_bucket.pe_file, "DIRECTORY_ENTRY_IMPORT"):
            # Member exists in the pefile structure pylint: disable=no-member
            for import_entry in static_bucket.pe_file.DIRECTORY_ENTRY_IMPORT:
                imported_libraries.append(import_entry.dll.decode("utf-8"))
                for function_entry in import_entry.imports:
                    imported_functions.append(
                        function_entry.name.decode("utf-8"))
        if hasattr(static_bucket.pe_file, "DIRECTORY_ENTRY_EXPORT"):
            # Member exists in the pefile structure pylint: disable=no-member
            for export_entry in static_bucket.pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
                exported_functions.append(export_entry.name.decode("utf-8"))
        static_bucket.sections = sections
        static_bucket.imported_libraries = imported_libraries
        static_bucket.imported_functions = imported_functions
        static_bucket.exported_functions = exported_functions


class OpcodesExtractor(_Extractor):
    _groups: list = []
    _min_ignored_percent: float = 0

    def set_configuration(self, groups: list, min_ignored_percent: float):
        self._groups = groups
        self._min_ignored_percent = min_ignored_percent

    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        # Traverse the occurances of instructions to classify them into
        # categories
        total_opcodes = len(dynamic_bucket.opcodes)
        counter = collections.Counter(dynamic_bucket.opcodes)
        for group in self._groups:
            group_count = 0
            group_instructions = group[(list(group.keys()))[0]]
            for instruction in group_instructions:
                if instruction[-1] == '*':
                    matched_instructions = [
                        opcode for opcode in counter.keys()
                        if opcode.find(instruction[:-1]) == 0
                    ]
                    for matched_instruction in matched_instructions:
                        group_count += counter[matched_instruction]
                        del counter[matched_instruction]
                else:
                    try:
                        group_count += counter[instruction]
                        del counter[instruction]
                    except:
                        pass
            dynamic_bucket.opcodes_freqs.append(
                carriers._OpcodesCategoryFrequency(
                    (list(group.keys()))[0],
                    100 * group_count / total_opcodes))

        # Log the ignored instruction, with high hitcount
        # TODO: convert the print call into a riposte logger one
        for key in counter.keys():
            percent = counter[key] / total_opcodes
            if (percent > self._min_ignored_percent):
                print("Instruction {} has {} occurances ({:.3f}% from total)".
                      format(key, counter[key], 100 * percent))


class APIsExtractor(_Extractor):
    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        pass


class FilesystemExtractor(_Extractor):
    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        pass


class NetworkActivityExtractor(_Extractor):
    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        pass
import re
import collections
import abc
import typing
import subordinate.modules.extractors.carriers as carriers
from utils.logger import Logger

API_CALL_REGEX = r"^((\w)+)\("


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
        size = static_bucket.pe_file.OPTIONAL_HEADER.SizeOfHeaders
        for section in static_bucket.pe_file.sections:
            sections.append(
                carriers._SectionCharacteristics(section.Name.decode("utf-8"),
                                                 section.get_entropy(),
                                                 section.Misc_VirtualSize,
                                                 section.SizeOfRawData))
            size += section.SizeOfRawData
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
        static_bucket.size = size
        static_bucket.sections = sections
        static_bucket.imported_libraries = imported_libraries
        static_bucket.imported_functions = imported_functions
        static_bucket.exported_functions = exported_functions


class _FrequencyExtractor(_Extractor):
    _elements: list = None
    _categories: dict = None
    _counter: collections.Counter = None
    _min_ignored_percent: float = 0

    def set_configuration(self, elements: list, categories: dict,
                          min_ignored_percent: float) -> None:
        self._elements = elements
        self._categories = categories
        self._min_ignored_percent = min_ignored_percent

    @staticmethod
    def _check_custom_match(pattern: str, string: str) -> bool:
        pattern = pattern.replace("*", r"(\w)*")
        return (re.match(pattern, string) is not None)

    def extract(self) -> list:
        elements_count = len(self._elements)
        self._counter = collections.Counter(self._elements)
        frequency_list = []
        for category in self._categories:
            group_count = 0
            for label in self._categories[category]:
                if "*" in label:
                    # If the label has wild chars, then search all elements that
                    # matches the given pattern and add their occurences
                    matched_elements = [
                        element for element in self._counter.keys()
                        if self._check_custom_match(label, element)
                    ]
                    for matched_element in matched_elements:
                        group_count += self._counter[matched_element]
                        del self._counter[matched_element]
                else:
                    try:
                        group_count += self._counter[label]
                        del self._counter[label]
                    except:
                        pass

            frequency_list.append(
                carriers._GenericCategoryFrequency(
                    category, 100 * group_count / elements_count))

        return frequency_list

    def print_list_of_outliers(self):
        printed_caption = False
        for key in self._counter.keys():
            percent = self._counter[key] / len(self._elements)
            if (percent > self._min_ignored_percent):
                if not printed_caption:
                    Logger.log_new(
                        "Outliers (that are not in any category) are:")
                    printed_caption = True
                Logger.log(
                    "\t- {} with {} occurances ({:.3f}% from total)".format(
                        key, self._counter[key], 100 * percent))


class OpcodesExtractor(_FrequencyExtractor):
    _opcodes_categories: dict = {}
    _min_ignored_percent: float = 0

    def set_configuration(self, opcodes_categories: dict,
                          min_ignored_percent: float) -> None:
        self._opcodes_categories = opcodes_categories
        self._min_ignored_percent = min_ignored_percent

    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        base_extractor = _FrequencyExtractor()
        base_extractor.set_configuration(dynamic_bucket.opcodes,
                                         self._opcodes_categories,
                                         self._min_ignored_percent)
        dynamic_bucket.opcodes_freqs = base_extractor.extract()
        base_extractor.print_list_of_outliers()


class APIsExtractor(_Extractor):
    _api_categories: dict = {}
    _min_ignored_percent: float = 0

    @staticmethod
    def _remove_prefix(string: str, prefix: str) -> str:
        return re.sub(r"^{0}".format(re.escape(prefix)), "", string)

    @staticmethod
    def _remove_suffix(string: str, suffix: str) -> str:
        return string[:-len(suffix)] if string.endswith(suffix) else string

    @staticmethod
    def normalize_function_name(name: str) -> str:
        prefixes = ["Rtl", "Csr", "Dbg", "Ldr", "Nt"]
        suffixes = ["Ex", "ExEx", "A", "W"]
        for prefix in prefixes:
            name = APIsExtractor._remove_prefix(name, prefix)
        for suffix in suffixes:
            name = APIsExtractor._remove_suffix(name, suffix)
        return name

    def set_configuration(self, api_categories: list,
                          min_ignored_percent: float) -> None:
        self._api_categories = api_categories
        self._min_ignored_percent = min_ignored_percent

    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        # Get the API calls if these are not already set
        if not dynamic_bucket.apis:
            with open(dynamic_bucket.log_file, "r") as log_file:
                for line in log_file.readlines():
                    api_calls = re.search(API_CALL_REGEX, line)
                    if api_calls:
                        # Normalize function name and append to list
                        dynamic_bucket.apis.append(
                            APIsExtractor.normalize_function_name(
                                api_calls.group(1)))

        # Effective extraction
        base_extractor = _FrequencyExtractor()
        base_extractor.set_configuration(dynamic_bucket.apis,
                                         self._api_categories,
                                         self._min_ignored_percent)
        dynamic_bucket.apis_freqs = base_extractor.extract()
        base_extractor.print_list_of_outliers()


class FilesystemExtractor(_Extractor):
    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        pass


class NetworkActivityExtractor(_Extractor):
    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        pass
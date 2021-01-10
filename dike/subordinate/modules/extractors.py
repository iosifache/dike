import re
import collections
import abc
import typing
from enum import Enum
import subordinate.modules.carriers as carriers
from subordinate.modules.preprocessors import PreprocessorsTypes

API_CALLS_REGEX = r"^((\w)+)\("
API_CALLS_IGNORED_PREFIXES = ["Rtl", "Csr", "Dbg", "Ldr", "Nt"]
API_CALLS_IGNORED_SUFFIXES = ["Ex", "ExEx", "A", "W"]


class FeatureTypes(Enum):
    INTEGER = 0
    FLOAT = 1
    STRING = 2
    INTEGER_ARRAY = 10
    FLOAT_ARRAY = 11
    STRING_ARRAY = 12


class _Extractor(abc.ABC):
    @abc.abstractstaticmethod
    def get_feature_types() -> typing.List[typing.Tuple[str, FeatureTypes]]:
        pass

    @abc.abstractstaticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        pass

    @abc.abstractmethod
    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        pass

    @abc.abstractmethod
    def squeeze(
            self, static_bucket: carriers._StaticBucket,
            dynamic_bucket: carriers._DynamicBucket
    ) -> typing.List[typing.List]:
        pass


class StringsExtractor(_Extractor):
    _min_length: int = 1
    _min_occurances: int = 1

    @staticmethod
    def get_feature_types() -> typing.List[typing.Tuple[str, FeatureTypes]]:
        return [("found strings", FeatureTypes.STRING_ARRAY)]

    @staticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        return [[PreprocessorsTypes.COUNTER, PreprocessorsTypes.N_GRAMS]]

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
                string.decode("utf-8") for string in all_strings
                if len(string) > self._min_length
            ]
        if (self._min_occurances != 1):
            counter = collections.Counter(all_strings)
            all_strings = [
                string for string in counter.elements()
                if counter[string] >= self._min_occurances
            ]
        static_bucket.strings = all_strings

    def squeeze(
            self, static_bucket: carriers._StaticBucket,
            dynamic_bucket: carriers._DynamicBucket
    ) -> typing.List[typing.List]:
        return [static_bucket.strings]


class PECharacteristicsExtractor(_Extractor):
    @staticmethod
    def get_feature_types() -> typing.List[FeatureTypes]:
        return [("executable size", FeatureTypes.INTEGER),
                ("imported libraries", FeatureTypes.STRING_ARRAY),
                ("imported functions", FeatureTypes.STRING_ARRAY),
                ("exported functions", FeatureTypes.STRING_ARRAY),
                ("sections names", FeatureTypes.STRING_ARRAY),
                ("sections entropies", FeatureTypes.FLOAT_ARRAY),
                ("sections virtual sizes", FeatureTypes.INTEGER_ARRAY),
                ("sections sizes of raw data", FeatureTypes.INTEGER_ARRAY)]

    @staticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        return [
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.COUNTER, PreprocessorsTypes.COUNT_VECTORIZER],
            [PreprocessorsTypes.COUNTER, PreprocessorsTypes.COUNT_VECTORIZER],
            [PreprocessorsTypes.COUNTER],
            [PreprocessorsTypes.COUNT_VECTORIZER, PreprocessorsTypes.N_GRAMS],
            [PreprocessorsTypes.K_BINS_DISCRETIZER],
            [PreprocessorsTypes.K_BINS_DISCRETIZER],
            [PreprocessorsTypes.K_BINS_DISCRETIZER]
        ]

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

    def squeeze(
            self, static_bucket: carriers._StaticBucket,
            dynamic_bucket: carriers._DynamicBucket
    ) -> typing.List[typing.List]:
        return [
            static_bucket.size, static_bucket.imported_libraries,
            static_bucket.imported_functions, static_bucket.exported_functions,
            [section["name"] for section in static_bucket.sections],
            [section["entropy"] for section in static_bucket.sections],
            [section["virtual_size"] for section in static_bucket.sections],
            [section["raw_size"] for section in static_bucket.sections]
        ]


class OpcodesExtractor(_Extractor):
    @staticmethod
    def get_feature_types() -> typing.List[FeatureTypes]:
        return [("opcodes", FeatureTypes.STRING_ARRAY)]

    @staticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        return [[
            PreprocessorsTypes.COUNTER, PreprocessorsTypes.COUNT_VECTORIZER,
            PreprocessorsTypes.FREQUENCY_EXTRACTOR
        ]]

    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        pass

    def squeeze(
            self, static_bucket: carriers._StaticBucket,
            dynamic_bucket: carriers._DynamicBucket
    ) -> typing.List[typing.List]:
        return [dynamic_bucket.opcodes]


class APIsExtractor(_Extractor):
    @staticmethod
    def get_feature_types() -> typing.List[FeatureTypes]:
        return [("Windows API calls", FeatureTypes.STRING_ARRAY)]

    @staticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        return [[
            PreprocessorsTypes.COUNTER, PreprocessorsTypes.COUNT_VECTORIZER,
            PreprocessorsTypes.FREQUENCY_EXTRACTOR
        ]]

    @staticmethod
    def _remove_prefix(string: str, prefix: str) -> str:
        return re.sub(r"^{0}".format(re.escape(prefix)), "", string)

    @staticmethod
    def _remove_suffix(string: str, suffix: str) -> str:
        return string[:-len(suffix)] if string.endswith(suffix) else string

    @staticmethod
    def normalize_function_name(name: str) -> str:
        for prefix in API_CALLS_IGNORED_PREFIXES:
            name = APIsExtractor._remove_prefix(name, prefix)
        for suffix in API_CALLS_IGNORED_SUFFIXES:
            name = APIsExtractor._remove_suffix(name, suffix)
        return name

    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        # Get the API calls if these are not already set
        if not dynamic_bucket.apis:
            with open(dynamic_bucket.log_file, "r") as log_file:
                for line in log_file.readlines():
                    api_calls = re.search(API_CALLS_REGEX, line)
                    if api_calls:
                        # Normalize function name and append to list
                        dynamic_bucket.apis.append(
                            APIsExtractor.normalize_function_name(
                                api_calls.group(1)))

    def squeeze(
            self, static_bucket: carriers._StaticBucket,
            dynamic_bucket: carriers._DynamicBucket
    ) -> typing.List[typing.List]:
        return [dynamic_bucket.apis]
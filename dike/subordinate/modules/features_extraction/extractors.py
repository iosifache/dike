import re
import collections
import abc
import typing
from enum import Enum
import subordinate.modules.features_extraction.carriers as carriers
from subordinate.modules.preprocessors import PreprocessorsTypes
from configuration.dike import DikeConfig


class FeatureTypes(Enum):
    """Enumeration for all possible types of an extracted feature"""
    INTEGER = 0
    FLOAT = 1
    STRING = 2
    INTEGER_ARRAY = 10
    FLOAT_ARRAY = 11
    STRING_ARRAY = 12


class _Extractor(abc.ABC):
    """Class modeling the extractors standard behavior

    The types of the extracted features are indicated in the return value of
    the method get_feature_types.

    If a preprocessing of the features is needed, attach an available
    preprocessor (of a type returned by the method get_supported_preprocessors).

    """
    @abc.abstractstaticmethod
    def get_feature_types() -> typing.List[typing.Tuple[str, FeatureTypes]]:
        """Returns the list with captions and types of the extracted features.

        Returns:
            typing.List[typing.Tuple[str, FeatureTypes]]: List of mentioned
                                                          types
        """
        pass

    @abc.abstractstaticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        """Returns the preprocessors that can be attached to the extractor.

        Returns:
            typing.List[typing.List[PreprocessorsTypes]]: List of mentioned
                                                          preprocessors
        """
        pass

    @abc.abstractmethod
    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        """Populates the given buckets with the features obtained by the
        extractor.

        Args:
            static_bucket (carriers._StaticBucket): Storage for static analysis
                                                    results
            dynamic_bucket (carriers._DynamicBucket): Storage for dynamic
                                                      analysis results
        """
        pass

    @abc.abstractmethod
    def squeeze(
            self, static_bucket: carriers._StaticBucket,
            dynamic_bucket: carriers._DynamicBucket
    ) -> typing.List[typing.Any]:
        """Returns the extracted features.

        Args:
            static_bucket (carriers._StaticBucket): Storage for static analysis
                                                    results
            dynamic_bucket (carriers._DynamicBucket): Storage for dynamic
                                                      analysis results

        Returns:
            typing.List[typing.List]: List of the extracted features
        """
        pass


class StringsExtractor(_Extractor):
    """Class extracting printable characters sequences

    It iterates through the file content and search for sequences of printable
    characters with length and number of occurances greater that some (implicit
    or custom) parameters.

    Extracted features are:
    - found string.

    """
    _min_length: int = 1
    _min_occurances: int = 1

    @staticmethod
    def get_feature_types() -> typing.List[typing.Tuple[str, FeatureTypes]]:
        """Same as the corresponding method of the parent class"""
        return [("found strings", FeatureTypes.STRING_ARRAY)]

    @staticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        """Same as the corresponding method of the parent class"""
        return [[PreprocessorsTypes.COUNTER, PreprocessorsTypes.N_GRAMS]]

    def set_configuration(self, min_length: int, min_occurances: int):
        """Sets custom parameters for extraction process.

        Args:
            min_length (int): Minimum length of a string to be saved
            min_occurances (int): Minimum number of occurances of a string to be
                                  saved
        """
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
        """Same as the corresponding method of the parent class"""
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
    ) -> typing.List[typing.Any]:
        """Same as the corresponding method of the parent class"""
        return [static_bucket.strings]


class PECharacteristicsExtractor(_Extractor):
    """Class extracting the characteristics of the executable
    
    Extracted features are:
    - executable size,
    - imported libraries,
    - imported functions,
    - exported functions,
    - sections names,
    - sections entropies,
    - sections virtual sizes, and
    - sections sizes of raw data.
    """
    @staticmethod
    def get_feature_types() -> typing.List[FeatureTypes]:
        """Same as the corresponding method of the parent class"""
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
        """Same as the corresponding method of the parent class"""
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
        """Same as the corresponding method of the parent class"""
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
    ) -> typing.List[typing.Any]:
        """Same as the corresponding method of the parent class"""
        return [
            static_bucket.size, static_bucket.imported_libraries,
            static_bucket.imported_functions, static_bucket.exported_functions,
            [section["name"] for section in static_bucket.sections],
            [section["entropy"] for section in static_bucket.sections],
            [section["virtual_size"] for section in static_bucket.sections],
            [section["raw_size"] for section in static_bucket.sections]
        ]


class OpcodesExtractor(_Extractor):
    """Class extracting the executed opcodes

    This extractor runs the executable into a controlled environment (Qemu, via
    Qiling Framework) and extracts all opcodes executed by the processor.

    Extracted features are:
    - mnemonics of the executed opcodes.
    """
    @staticmethod
    def get_feature_types() -> typing.List[FeatureTypes]:
        """Same as the corresponding method of the parent class"""
        return [("opcodes", FeatureTypes.STRING_ARRAY)]

    @staticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        """Same as the corresponding method of the parent class"""
        return [[
            PreprocessorsTypes.COUNTER, PreprocessorsTypes.COUNT_VECTORIZER,
            PreprocessorsTypes.GROUP_COUNTER
        ]]

    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        """Same as the corresponding method of the parent class"""
        pass

    def squeeze(
            self, static_bucket: carriers._StaticBucket,
            dynamic_bucket: carriers._DynamicBucket
    ) -> typing.List[typing.Any]:
        """Same as the corresponding method of the parent class"""
        return [dynamic_bucket.opcodes]


class APIsExtractor(_Extractor):
    """Class extracting the called Windows API functions

    As the opcodes extractor, it runs the program into a controlled environment
    (Qemu, via Qiling Framework) and parse the log file produced by the emulator
    to discover all Windows API functions that were called during the execution.

    Extracted features are:
    - Windows API calls.
    """
    _ignored_prefixes: typing.List[str] = []
    _ignored_suffixes: typing.List[str] = []

    @staticmethod
    def get_feature_types() -> typing.List[FeatureTypes]:
        """Same as the corresponding method of the parent class"""
        return [("Windows API calls", FeatureTypes.STRING_ARRAY)]

    @staticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        """Same as the corresponding method of the parent class"""
        return [[
            PreprocessorsTypes.COUNTER, PreprocessorsTypes.COUNT_VECTORIZER,
            PreprocessorsTypes.GROUP_COUNTER
        ]]

    def set_configuration(self, ignored_prefixes: typing.List[str],
                          ignored_suffixes: typing.List[str]):
        """Sets custom parameters for extraction process.

        Args:
            ignored_prefixes (typing.List[str]): List of ignored prefixes
            ignored_suffixes (typing.List[str]): List of ignored suffixes
        """
        self._ignored_prefixes = ignored_prefixes
        self._ignored_suffixes = ignored_suffixes

    @staticmethod
    def _remove_prefix(string: str, prefix: str) -> str:
        return re.sub(r"^{0}".format(re.escape(prefix)), "", string)

    @staticmethod
    def _remove_suffix(string: str, suffix: str) -> str:
        return string[:-len(suffix)] if string.endswith(suffix) else string

    def normalize_function_name(self, name: str) -> str:
        """Normalizes a Windows API function name by stripping the specific
        prefixes and suffixes.

        Args:
            name (str): Name of Windows API function

        Returns:
            str: Normalized name of the function
        """
        for prefix in self._ignored_prefixes:
            name = APIsExtractor._remove_prefix(name, prefix)
        for suffix in self._ignored_suffixes:
            name = APIsExtractor._remove_suffix(name, suffix)
        return name

    def extract(self, static_bucket: carriers._StaticBucket,
                dynamic_bucket: carriers._DynamicBucket) -> None:
        """Same as the corresponding method of the parent class"""
        # Get the API calls if these are not already set
        if not dynamic_bucket.apis:
            with open(dynamic_bucket.log_file, "r") as log_file:
                for line in log_file.readlines():
                    api_calls = re.search(DikeConfig.API_CALLS_REGEX, line)
                    if api_calls:
                        # Normalize function name and append to list
                        dynamic_bucket.apis.append(
                            self.normalize_function_name(api_calls.group(1)))

    def squeeze(
            self, static_bucket: carriers._StaticBucket,
            dynamic_bucket: carriers._DynamicBucket
    ) -> typing.List[typing.Any]:
        """Same as the corresponding method of the parent class"""
        return [dynamic_bucket.apis]
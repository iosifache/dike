"""Extractors.

As they are dependent on the extraction core, they are not meant to be used as
independent components.
"""
import abc
import collections
import re
import typing

import modules.features.carriers as carriers
from modules.configuration.parameters import Packages
from modules.dataset.types import AnalyzedFileTypes
from modules.features.types import FeatureTypes
from modules.preprocessing.types import PreprocessorsTypes
from olefile import OleFileIO
from oletools.oleid import OleID
from oletools.olevba import VBA_Parser


class Extractor(abc.ABC):
    """Class modeling the extractors' standard behavior.

    The types of the supported types of files to extract features from are
    indicated in the return value of the method get_analyzed_file_types().

    Same for the types of the extracted features, that are indicated in the
    return value of the method get_feature_types().

    If a preprocessing of the features is needed, attach an available
    preprocessor (of a type returned by the method
    get_supported_preprocessors()).
    """

    @staticmethod
    @abc.abstractmethod
    def get_analyzed_file_types() -> typing.Set[AnalyzedFileTypes]:
        """Returns the list of the supported types of files to analyze.

        Returns:
            typing.List[AnalyzedFileTypes]: List of supported filetypes
        """
        return

    @staticmethod
    @abc.abstractmethod
    def get_feature_types() -> typing.List[typing.Tuple[str, FeatureTypes]]:
        """Returns the list with captions and types of the extracted features.

        Returns:
            typing.List[typing.Tuple[str, FeatureTypes]]: List of mentioned
                types
        """
        return

    @staticmethod
    @abc.abstractmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        """Returns the preprocessors that can be attached to the extractor.

        Returns:
            typing.List[typing.List[PreprocessorsTypes]]: List of mentioned
                preprocessors
        """
        return

    @abc.abstractmethod
    def extract(self, static_bucket: carriers.StaticBucket,
                dynamic_bucket: carriers.DynamicBucket,
                document_bucket: carriers.DocumentBucket) -> None:
        """Populates the given buckets with the extracted features.

        Args:
            static_bucket (carriers.StaticBucket): Storage for static analysis
                results
            dynamic_bucket (carriers.DynamicBucket): Storage for dynamic
                analysis results
            document_bucket (carriers.DocumentBucket): Storage for documents
                analysis results
        """
        return

    @abc.abstractmethod
    def squeeze(
            self, static_bucket: carriers.StaticBucket,
            dynamic_bucket: carriers.DynamicBucket,
            document_bucket: carriers.DocumentBucket
    ) -> typing.List[typing.Any]:
        """Returns the extracted features.

        Args:
            static_bucket (carriers.StaticBucket): Storage for static analysis
                results
            dynamic_bucket (carriers.DynamicBucket): Storage for dynamic
                analysis results
            document_bucket (carriers.DocumentBucket): Storage for documents
                analysis results

        Returns:
            typing.List[typing.List]: List of the extracted features
        """
        return


class StaticStrings(Extractor):
    """Class extracting printable character sequences.

    It iterates through the file content and searches for sequences of printable
    characters with length and number of occurrences greater than some (implicit
    or custom) parameters.

    Extracted features are:
    - found string.
    """

    _min_length: int
    _min_occurrences: int

    def __init__(self) -> None:
        """Initializes the StaticStrings instance."""
        self._min_length = 1
        self._min_occurrences = 1

    @staticmethod
    def get_analyzed_file_types() -> typing.Set[AnalyzedFileTypes]:
        """See the Extractor.get_analyzed_file_types() method.

        # noqa
        """
        return {AnalyzedFileTypes.PE, AnalyzedFileTypes.OLE}

    @staticmethod
    def get_feature_types() -> typing.List[typing.Tuple[str, FeatureTypes]]:
        """See the Extractor.get_feature_types() method.

        # noqa
        """
        return [("found strings", FeatureTypes.STRING_ARRAY)]

    @staticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        """See the Extractor.get_supported_preprocessors() method.

        # noqa
        """
        return [[PreprocessorsTypes.COUNTER, PreprocessorsTypes.N_GRAMS]]

    def set_configuration(self, min_length: int, min_occurrences: int):
        """Sets custom parameters for the extraction process.

        Args:
            min_length (int): Minimum length of a string to be saved
            min_occurrences (int): Minimum number of occurrences of a string to
                be saved
        """
        self._min_length = min_length
        self._min_occurrences = min_occurrences

    @staticmethod
    def _get_printable_chars() -> bytes:
        chars = 256 * ['\0']
        for i in range(32, 127):
            chars[i] = chr(i)

        chars[ord('\n')] = "\n"
        chars[ord('\t')] = "\t"

        return "".join(chars).encode("utf-8")

    def extract(self, static_bucket: carriers.StaticBucket,
                dynamic_bucket: carriers.DynamicBucket,
                document_bucket: carriers.DocumentBucket) -> None:
        """See the Extractor.extract() method.

        # noqa
        """
        all_strings = static_bucket.content.translate(
            self._get_printable_chars()).split(b'\0')

        if self._min_length != 1:
            all_strings = [
                string.decode("utf-8") for string in all_strings
                if len(string) > self._min_length
            ]

        if self._min_occurrences != 1:
            counter = collections.Counter(all_strings)
            all_strings = [
                string for string in counter.elements()
                if counter[string] >= self._min_occurrences
            ]

        static_bucket.strings = all_strings

    def squeeze(
            self, static_bucket: carriers.StaticBucket,
            dynamic_bucket: carriers.DynamicBucket,
            document_bucket: carriers.DocumentBucket
    ) -> typing.List[typing.Any]:
        """See the Extractor.squeeze() method.

        # noqa
        """
        return [static_bucket.strings]


class StaticPECharacteristics(Extractor):
    """Class extracting the characteristics of the executable.

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
    def get_analyzed_file_types() -> typing.Set[AnalyzedFileTypes]:
        """See the Extractor.get_analyzed_file_types() method.

        # noqa
        """
        return {AnalyzedFileTypes.PE}

    @staticmethod
    def get_feature_types() -> typing.List[FeatureTypes]:
        """See the Extractor.get_feature_types() method.

        # noqa
        """
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
        """See the Extractor.get_supported_preprocessors() method.

        # noqa
        """
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

    def extract(self, static_bucket: carriers.StaticBucket,
                dynamic_bucket: carriers.DynamicBucket,
                document_bucket: carriers.DocumentBucket) -> None:
        """See the Extractor.extract() method.

        # noqa
        """
        # Extract the details about the size
        size = static_bucket.pe_file.OPTIONAL_HEADER.SizeOfHeaders

        # Extract the details about the sections
        sections = []
        for section in static_bucket.pe_file.sections:
            sections.append(
                carriers.SectionCharacteristics(
                    section.Name.decode("utf-8", "ignore"),
                    section.get_entropy(), section.Misc_VirtualSize,
                    section.SizeOfRawData))
            size += section.SizeOfRawData

        # Extract the details about the imports
        imported_libraries = []
        imported_functions = []
        if hasattr(static_bucket.pe_file, "DIRECTORY_ENTRY_IMPORT"):
            # Member exists in the pefile structure pylint: disable=no-member
            for import_entry in static_bucket.pe_file.DIRECTORY_ENTRY_IMPORT:
                library_name = import_entry.dll.decode("utf-8")
                library_name = re.sub(".dll",
                                      "",
                                      library_name,
                                      flags=re.IGNORECASE)
                imported_libraries.append(library_name)
                for function_entry in import_entry.imports:
                    imported_functions.append(
                        function_entry.name.decode("utf-8"))

        # Extract the details about the exports
        exported_functions = []
        if hasattr(static_bucket.pe_file, "DIRECTORY_ENTRY_EXPORT"):
            entries = static_bucket.pe_file.DIRECTORY_ENTRY_EXPORT.symbols
            for entry in entries:
                exported_functions.append(entry.name.decode("utf-8"))

        static_bucket.size = size
        static_bucket.sections = sections
        static_bucket.imported_libraries = imported_libraries
        static_bucket.imported_functions = imported_functions
        static_bucket.exported_functions = exported_functions

    def squeeze(
            self, static_bucket: carriers.StaticBucket,
            dynamic_bucket: carriers.DynamicBucket,
            document_bucket: carriers.DocumentBucket
    ) -> typing.List[typing.Any]:
        """See the Extractor.squeeze() method.

        # noqa
        """
        return [
            static_bucket.size, static_bucket.imported_libraries,
            static_bucket.imported_functions, static_bucket.exported_functions,
            [section["name"] for section in static_bucket.sections],
            [section["entropy"] for section in static_bucket.sections],
            [section["virtual_size"] for section in static_bucket.sections],
            [section["raw_size"] for section in static_bucket.sections]
        ]


# pylint: disable=abstract-method
class _Opcodes(Extractor, abc.ABC):
    """Class extracting the executed opcodes.

    Extracted features are:
    - mnemonics of the executed opcodes.
    """

    @staticmethod
    def get_analyzed_file_types() -> typing.Set[AnalyzedFileTypes]:
        """See the Extractor.get_analyzed_file_types() method.

        # noqa
        """
        return {AnalyzedFileTypes.PE}

    @staticmethod
    def get_feature_types() -> typing.List[FeatureTypes]:
        """See the Extractor.get_feature_types() method.

        # noqa
        """
        return [("opcodes", FeatureTypes.STRING_ARRAY)]

    @staticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        """See the Extractor.get_supported_preprocessors() method.

        # noqa
        """
        return [[
            PreprocessorsTypes.COUNTER, PreprocessorsTypes.COUNT_VECTORIZER,
            PreprocessorsTypes.GROUP_COUNTER
        ]]

    def extract(self, static_bucket: carriers.StaticBucket,
                dynamic_bucket: carriers.DynamicBucket,
                document_bucket: carriers.DocumentBucket) -> None:
        """See the Extractor.extract() method.

        # noqa
        """
        return


class StaticOpcodes(_Opcodes):
    """Class extracting the executed opcodes via static analysis.

    This extractor analyses the given executable into a decompiler and extracts
    all opcodes (possibly) executed by the processor.
    """

    def squeeze(
            self, static_bucket: carriers.StaticBucket,
            dynamic_bucket: carriers.DynamicBucket,
            document_bucket: carriers.DocumentBucket
    ) -> typing.List[typing.Any]:
        """See the Extractor.squeeze() method.

        # noqa
        """
        return [static_bucket.opcodes]


class DynamicOpcodes(_Opcodes):
    """Class extracting the executed opcodes via dynamic analysis.

    This extractor runs the executable into a controlled environment (Qemu, via
    Qiling Framework) and extracts all opcodes executed by the processor.
    """

    def squeeze(
            self, static_bucket: carriers.StaticBucket,
            dynamic_bucket: carriers.DynamicBucket,
            document_bucket: carriers.DocumentBucket
    ) -> typing.List[typing.Any]:
        """See the Extractor.squeeze() method.

        # noqa
        """
        return [dynamic_bucket.opcodes]


# pylint: disable=abstract-method
class _APIs(Extractor, abc.ABC):
    """Class extracting the called Windows API functions.

    Extracted features are:
    - Windows API calls.
    """

    _ignored_prefixes: typing.List[str]
    _ignored_suffixes: typing.List[str]

    def __init__(self) -> None:
        self._ignored_prefixes = []
        self._ignored_suffixes = []

    @staticmethod
    def get_analyzed_file_types() -> typing.Set[AnalyzedFileTypes]:
        """See the Extractor.get_analyzed_file_types() method.

        # noqa
        """
        return {AnalyzedFileTypes.PE}

    @staticmethod
    def get_feature_types() -> typing.List[FeatureTypes]:
        """See the Extractor.get_feature_types() method.

        # noqa
        """
        return [("Windows API calls", FeatureTypes.STRING_ARRAY)]

    @staticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        """See the Extractor.get_supported_preprocessors() method.

        # noqa
        """
        return [[
            PreprocessorsTypes.COUNTER, PreprocessorsTypes.COUNT_VECTORIZER,
            PreprocessorsTypes.GROUP_COUNTER
        ]]

    def set_configuration(self, ignored_prefixes: typing.List[str],
                          ignored_suffixes: typing.List[str]):
        """Sets custom parameters for the extraction process.

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
        """Normalizes a Windows API function name.

        The normalization consists of stripping the specific prefixes and
        suffixes.

        Args:
            name (str): Name of Windows API function

        Returns:
            str: Normalized name of the function
        """
        for prefix in self._ignored_prefixes:
            name = _APIs._remove_prefix(name, prefix)
        for suffix in self._ignored_suffixes:
            name = _APIs._remove_suffix(name, suffix)
        return name


class StaticAPIs(_APIs):
    """Class extracting the called Windows API functions via static analysis.

    This extractor analyses the given executable into a decompiler and extracts
    all (possibly) called Windows API functions.
    """

    def extract(self, static_bucket: carriers.StaticBucket,
                dynamic_bucket: carriers.DynamicBucket,
                document_bucket: carriers.DocumentBucket) -> None:
        """See the Extractor.extract() method.

        # noqa
        """
        # Normalize functions names
        static_bucket.apis = [
            self.normalize_function_name(api) for api in static_bucket.apis
        ]

    def squeeze(
            self, static_bucket: carriers.StaticBucket,
            dynamic_bucket: carriers.DynamicBucket,
            document_bucket: carriers.DocumentBucket
    ) -> typing.List[typing.Any]:
        """See the Extractor.squeeze() method.

        # noqa
        """
        return [static_bucket.apis]


class DynamicAPIs(_APIs):
    """Class extracting the called Windows API functions via dynamic analysis.

    As the opcodes extractor, it runs the program into a controlled environment
    (Qemu, via Qiling Framework) and parses the log file produced by the
    emulator to discover all Windows API functions that were called during the
    execution.
    """

    def extract(self, static_bucket: carriers.StaticBucket,
                dynamic_bucket: carriers.DynamicBucket,
                document_bucket: carriers.DocumentBucket) -> None:
        """See the Extractor.extract() method.

        # noqa
        """
        # Get the API calls if these are not already set
        if not dynamic_bucket.apis:
            with open(dynamic_bucket.log_file, "r") as log_file:
                for line in log_file.readlines():
                    api_calls = re.search(
                        Packages.Features.Qiling.API_CALLS_REGEX, line)
                    if api_calls:
                        # Normalize function name and append to list
                        dynamic_bucket.apis.append(
                            self.normalize_function_name(api_calls.group(1)))

    def squeeze(
            self, static_bucket: carriers.StaticBucket,
            dynamic_bucket: carriers.DynamicBucket,
            document_bucket: carriers.DocumentBucket
    ) -> typing.List[typing.Any]:
        """See the Extractor.squeeze() method.

        # noqa
        """
        return [dynamic_bucket.apis]


class GeneralOLEDetails(Extractor):
    """Class extracting general details from an OLE file."""

    @staticmethod
    def get_analyzed_file_types() -> typing.Set[AnalyzedFileTypes]:
        """See the Extractor.get_analyzed_file_types() method.

        # noqa
        """
        return {AnalyzedFileTypes.OLE}

    @staticmethod
    def get_feature_types() -> typing.List[FeatureTypes]:
        """See the Extractor.get_feature_types() method.

        # noqa
        """
        return [("text found in the header of the document",
                 FeatureTypes.STRING_ARRAY),
                ("document edit time", FeatureTypes.INTEGER),
                ("number of pages", FeatureTypes.INTEGER),
                ("number of words", FeatureTypes.INTEGER),
                ("number of characters", FeatureTypes.INTEGER),
                ("security level", FeatureTypes.INTEGER),
                ("time of creation", FeatureTypes.INTEGER),
                ("time of the last modification", FeatureTypes.INTEGER),
                ("boolean indicating if the SummaryInformation stream exists",
                 FeatureTypes.BOOLEAN),
                ("boolean indicating if the document is encrypted",
                 FeatureTypes.BOOLEAN),
                ("boolean indicating if the document is a Word",
                 FeatureTypes.BOOLEAN),
                ("boolean indicating if the document is an Excel",
                 FeatureTypes.BOOLEAN),
                ("boolean indicating if the document is a Powerpoint",
                 FeatureTypes.BOOLEAN),
                ("boolean indicating if the document is a Visio",
                 FeatureTypes.BOOLEAN),
                ("boolean indicating if the ObjectPool stream exists",
                 FeatureTypes.BOOLEAN),
                ("number of Flash objects", FeatureTypes.INTEGER),
                ("names of directory entries", FeatureTypes.STRING_ARRAY),
                ("sizes of directory entries", FeatureTypes.INTEGER_ARRAY),
                ("number of sectors", FeatureTypes.INTEGER)]

    @staticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        """See the Extractor.get_supported_preprocessors() method.

        # noqa
        """
        return [
            [PreprocessorsTypes.N_GRAMS],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.IDENTITY],
            [PreprocessorsTypes.COUNT_VECTORIZER, PreprocessorsTypes.N_GRAMS],
            [PreprocessorsTypes.K_BINS_DISCRETIZER],
            [PreprocessorsTypes.IDENTITY]
        ]  # yapf: disable

    def extract(self, static_bucket: carriers.StaticBucket,
                dynamic_bucket: carriers.DynamicBucket,
                document_bucket: carriers.DocumentBucket) -> None:
        """See the Extractor.extract() method.

        # noqa
        """
        ole = OleFileIO(document_bucket.filename)

        # Metadata
        meta = ole.get_metadata()
        for property_name in meta.SUMMARY_ATTRIBS:
            property_value = getattr(meta, property_name)
            if not property_value:
                continue

            if (property_name in [
                    "title", "subject", "author", "keywords", "comments",
                    "last_saved_by"
            ] and property_value):
                document_bucket.header_text.append(
                    property_value.decode("utf-8"))
            elif property_name == "total_edit_time" and property_value:
                document_bucket.total_edit_time = property_value
            elif property_name == "num_pages":
                document_bucket.pages_count = property_value
            elif property_name == "num_words":
                document_bucket.words_count = property_value
            elif property_name == "num_chars":
                document_bucket.words_count = property_value
            elif property_name == "security":
                document_bucket.security = property_value

        # Timestamps
        creation_time = ole.root.getctime()
        modification_time = ole.root.getmtime()
        if creation_time:
            document_bucket.creation_time = int(
                creation_time.strftime("%Y%m%d%H%M%S"))
        if modification_time:
            document_bucket.modification_time = int(
                modification_time.strftime("%Y%m%d%H%M%S"))

        # Special characteristics
        oid = OleID(document_bucket.filename)
        indicators = oid.check()
        for indicator in indicators:
            indicator_id = indicator.id
            indicator_value = indicator.value

            if indicator_id == "has_suminfo":
                document_bucket.has_suminfo = indicator_value
            elif indicator_id == "encrypted":
                document_bucket.is_encrypted = indicator_value
            elif indicator_id == "word":
                document_bucket.is_word = indicator_value
            elif indicator_id == "excel":
                document_bucket.is_excel = indicator_value
            elif indicator_id == "ppt":
                document_bucket.is_ppt = indicator_value
            elif indicator_id == "visio":
                document_bucket.is_visio = indicator_value
            elif indicator_id == "ObjectPool":
                document_bucket.has_object_pool = indicator_value
            elif indicator_id == "flash":
                document_bucket.flash_count = indicator_value

        # Directory entries
        for entry in ole.direntries:
            if entry:
                name = entry.name if entry.name else ""
                size = entry.size if entry.size else 0
                document_bucket.directory_entries.append(
                    carriers.DirectoryEntry(name, size))

        # Sectors
        document_bucket.sectors_count = len(ole.fat)

    def squeeze(
            self, static_bucket: carriers.StaticBucket,
            dynamic_bucket: carriers.DynamicBucket,
            document_bucket: carriers.DocumentBucket
    ) -> typing.List[typing.Any]:
        """See the Extractor.squeeze() method.

        # noqa
        """
        return [
            document_bucket.header_text, document_bucket.total_edit_time,
            document_bucket.pages_count, document_bucket.words_count,
            document_bucket.chars_count, document_bucket.security,
            document_bucket.creation_time, document_bucket.modification_time,
            document_bucket.has_suminfo, document_bucket.is_encrypted,
            document_bucket.is_word, document_bucket.is_excel,
            document_bucket.is_ppt, document_bucket.is_visio,
            document_bucket.has_object_pool, document_bucket.flash_count,
            [entry["name"] for entry in document_bucket.directory_entries],
            [entry["size"] for entry in document_bucket.directory_entries
             ], document_bucket.sectors_count
        ]


class OLEMacros(Extractor):
    """Class extracting general details from an OLE file."""

    @staticmethod
    def get_analyzed_file_types() -> typing.Set[AnalyzedFileTypes]:
        """See the Extractor.get_analyzed_file_types() method.

        # noqa
        """
        return {AnalyzedFileTypes.OLE}

    @staticmethod
    def get_feature_types() -> typing.List[FeatureTypes]:
        """See the Extractor.get_feature_types() method.

        # noqa
        """
        return [("code of all macros", FeatureTypes.STRING_ARRAY)]

    @staticmethod
    def get_supported_preprocessors(
    ) -> typing.List[typing.List[PreprocessorsTypes]]:
        """See the Extractor.get_supported_preprocessors() method.

        # noqa
        """
        return [[
            PreprocessorsTypes.COUNTER, PreprocessorsTypes.COUNT_VECTORIZER,
            PreprocessorsTypes.N_GRAMS
        ]]

    def extract(self, static_bucket: carriers.StaticBucket,
                dynamic_bucket: carriers.DynamicBucket,
                document_bucket: carriers.DocumentBucket) -> None:
        """See the Extractor.extract() method.

        # noqa
        """
        vbaparser = VBA_Parser(document_bucket.filename)

        if vbaparser.detect_vba_macros():
            for (_, _, _, vba_code) in vbaparser.extract_macros():
                document_bucket.macros_code.append(vba_code)

    def squeeze(
            self, static_bucket: carriers.StaticBucket,
            dynamic_bucket: carriers.DynamicBucket,
            document_bucket: carriers.DocumentBucket
    ) -> typing.List[typing.Any]:
        """See the Extractor.squeeze() method.

        # noqa
        """
        return [document_bucket.macros_code]

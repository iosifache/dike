"""Feature extractors for files"""

import pefile
import collections
import io
import typing


class Extractor:
    """Interface class for all particular extractors.

    Raises:
        NotImplementedError: Abstract method not implemented
    """
    _pe_file: pefile.PE = None
    _content: bytes = None

    def set_pe_file(self, pe_file: pefile.PE) -> None:
        """Sets a pefile handler for the given executable file.

        Args:
            pe_file: Handler to PE file
        """
        self._pe_file = pe_file

    def set_content(self, content: bytes) -> None:
        """Sets content with whom the extractor will work.

        Args:
            content: Content of the executable
        """
        self._content = content

    def extract(self) -> typing.Any:
        """Extracts the features.

        Raises:
            NotImplementedError: Abstract method not implemented

        Returns:
            Any extracted feature
        """
        raise NotImplementedError()


class Strings(Extractor):
    """Extractors for string.
    
    Attributes:
        min_length: Minimum length of selected strings
        min_occurances: Minimum occurances of selected strings
    """

    min_length: int = 1
    min_occurances: int = 1

    # TODO: log "{} strings extracted"
    def __init__(self, min_length: int, min_occurances: int):
        """Initializes the object.

        Args:
            min_length: Minimum length of selected strings
            min_occurances: Minimum occurances of selected strings
        """
        self.min_length = min_length
        self.min_occurances = min_occurances

    def _get_printable_chars(self) -> bytes:
        """Generates a mapping for printable characters.

        Returns:
            Strings representing the mapping
        """
        chars = 256 * ['\0']
        for i in range(32, 127):
            chars[i] = chr(i)
        chars[ord('\n')] = "\n"
        chars[ord('\t')] = "\t"
        return "".join(chars).encode("utf-8")

    # TODO: log "{} strings extracted, that correspond to given constraints"
    def extract(self) -> typing.List[str]:
        """Extracts all strings from the given file, considering some 
           constraints.

        Returns:
            List containing all selected string
        """
        all_strings = self._content.translate(
            self._get_printable_chars()).split(b'\0')
        if (self.min_length != 1):
            strings = [
                str(string) for string in all_strings
                if len(string) > self.min_length
            ]
        if (self.min_occurances != 1):
            counter = collections.Counter(strings)
            strings = [
                string for string in counter.elements()
                if counter[string] >= self.min_occurances
            ]
        return strings


class SectionCharacteristics:
    """Characteristics of sections in the executables.

    Attributes:
        name: Name
        entropy: Entropy
        raw_size: Raw size
        virtual_size: Virtual size
    """
    name: str = None
    entropy: float = 1
    raw_size: int = 0
    virtual_size: int = 0

    def __init__(self, name: str, entropy: float, raw_size: int,
                 virtual_size: int):
        """Initializes the object.

        Args:
            name: Name
            entropy: Entropy
            raw_size: Raw size
            virtual_size: Virtual size
        """
        self.name = name
        self.entropy = entropy
        self.raw_size = raw_size
        self.virtual_size = virtual_size


class PECharacteristics(Extractor):
    """Characteristics of the analysed PE file"""
    def extract(self) -> tuple:
        """Extracts details about the PE file.

        Returns:
            Tuple containing the details
        """
        imported_dlls = []
        imported_functions = []
        exported_functions = []
        sections = []
        for section in self._pe_file.sections:
            sections.append(
                SectionCharacteristics(section.Name.decode("utf-8"),
                                       section.get_entropy(),
                                       section.Misc_VirtualSize,
                                       section.SizeOfRawData))
        if hasattr(self._pe_file, "DIRECTORY_ENTRY_IMPORT"):
            for import_entry in self._pe_file.DIRECTORY_ENTRY_IMPORT:
                imported_dlls.append(import_entry.dll.decode("utf-8"))
                for function_entry in import_entry.imports:
                    imported_functions.append(
                        function_entry.name.decode("utf-8"))
        if hasattr(self._pe_file, "DIRECTORY_ENTRY_EXPORT"):
            for export_entry in self._pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
                exported_functions.append(export_entry.name.decode("utf-8"))
        return (imported_dlls, imported_functions, exported_functions,
                sections)


class ExtractorMaster:
    """Tampon class for using different extractors to the same executable file.

    Attributes:
        strings: List of printable strings
        imported_dlls: List of imported DLLs
        imported_functions: List of imported functions from all DLLs
        exported_functions: List of exported functions
        sections: List of informations about structures

    Raises:
        FileNotFoundError: File does not exists
    """

    strings: typing.List[str] = None
    imported_dlls: typing.List[str] = [None]
    imported_functions: typing.List[str] = None
    exported_functions: typing.List[str] = None
    sections: typing.List[SectionCharacteristics] = None
    _filename: str = None
    _pe_file: pefile.PE = None
    _content: bytes = None

    def __init__(self, filename: str):
        """Initializes the object.

        Args:
            filename: Filename of the executable

        Raises:
            FileNotFoundError: File does not exists
        """
        try:
            self._content = open(filename, "rb").read()
            self._pe_file = pefile.PE(filename)
            self._filename = filename
        except:
            raise FileNotFoundError()

    def extract(self, extractor: Extractor) -> None:
        """Extract features with a specific extractor.

        Args:
            extractor: Extractor to be used
        """
        extractor.set_pe_file(self._pe_file)
        extractor.set_content(self._content)
        if (isinstance(extractor, Strings)):
            self.strings = extractor.extract()
        elif (isinstance(extractor, PECharacteristics)):
            results = extractor.extract()
            self.imported_dlls = results[0]
            self.imported_functions = results[1]
            self.exported_functions = results[2]
            self.sections = results[3]
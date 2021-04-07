"""Carriers encapsulating the extracted features.

As they are dependent on the extraction core, they are not meant to be used as
independent components.
"""
import typing

import capstone
import pefile
import qiling
import qiling.const


class SectionCharacteristics(dict):
    """Class encapsulating details about a section of an executable.

    Attributes:
        name (str): Name of the section
        entropy (float): Entropy of the section
        raw_size (int): Raw size of the section
        virtual_size (int): Virtual size of the section
    """

    name: str
    entropy: float
    raw_size: int
    virtual_size: int

    def __init__(self, name: str, entropy: float, raw_size: int,
                 virtual_size: int) -> None:
        """Initializes the SectionCharacteristics instance.

        # noqa
        """
        dict.__init__(self,
                      name=name,
                      entropy=entropy,
                      raw_size=raw_size,
                      virtual_size=virtual_size)


class StaticBucket:
    """Class encapsulating static analysis details about an executable.

    Attributes:
        filename (str): Filename of the executable
        pe_file (pefile.PE): pefile object representing the executable
        size (int): Size of executable, in bytes
        content (bytes): Bytes representing the whole executable
        disassembler (capstone.Cs): Capstone disassembler instance, shared by
            the extractors
        strings (typing.List[str]): List of printable character sequences from
                                    the executable
        sections (typing.List[SectionCharacteristics]): List of
            SectionCharacteristics, representing the sections of the executable
        imported_libraries (typing.List[str]): List of imported libraries of the
            executable
        imported_functions (typing.List[str]): List of imported functions of the
            executable
        exported_functions (typing.List[str]): List of exported functions of the
            executable
        opcodes (typing.List[str]): List of strings representing the mnemonics
            of the executed opcodes
        apis (typing.List[str]): List of strings representing the names of the
            called Windows API functions names
    """

    filename: str
    pe_file: pefile.PE
    size: int
    content: bytes
    disassembler: capstone.Cs
    strings: typing.List[str]
    sections: typing.List[SectionCharacteristics]
    imported_libraries: typing.List[str]
    imported_functions: typing.List[str]
    exported_functions: typing.List[str]
    opcodes: typing.List[str]
    apis: typing.List[str]

    def __init__(self) -> None:
        """Initializes the StaticBucket instance."""
        self.filename = None
        self.pe_file = None
        self.size = -1
        self.content = None
        self.disassembler = None
        self.strings = []
        self.sections = []
        self.imported_libraries = []
        self.imported_functions = []
        self.exported_functions = []
        self.opcodes = []
        self.apis = []


class DynamicBucket:
    """Class encapsulating dynamic analysis details about an executable.

    Attributes:
        emulator (qiling.Qiling): Qiling emulator instance, shared by extractors
        log_file (str): Full path to the logging file of Qiling
        opcodes (typing.List[str]): List of strings representing the mnemonics
            of the executed opcodes
        apis (typing.List[str]): List of strings representing the names of the
            called Windows API functions names
    """

    emulator: qiling.Qiling
    log_file: str
    opcodes: typing.List[str]
    apis: typing.List[str]

    def __init__(self) -> None:
        """Initializes the DynamicBucket instance."""
        self.emulator = None
        self.log_file = None
        self.opcodes = []
        self.apis = []


class DirectoryEntry(dict):
    """Class encapsulating details about an OLE directory entry.

    Attributes:
        name (str): Name of the entry
        size (float): Size of the entry
    """

    name: str
    size: int

    def __init__(self, name: str, size: int) -> None:
        """Initializes the DirectoryEntry instance.

        # noqa
        """
        dict.__init__(self, name=name, size=size)


class DocumentBucket:
    """Class encapsulating details about an OLE file.

    The OLE file can be Microsoft Word, Powerpoint, or Excel.

    Attributes:
        filename (str): Filename of the document
        header_text (str): Text found in the header of the document, namely in
            fields such as title, subject, authors, keywords and comment
        total_edit_time (int): Document edit time, in seconds
        pages_count (int): Number of pages
        words_count (int): Number of words
        chars_count (int): Number of characters
        security (int): Number indicating the security level of the document
        creation_time (int): Time of creation of the document, composed by
            the concatenation of year, month, day, hour, minutes and seconds
        modification_time (int): Time of the last modification of the document,
            composed by the concatenation of year, month, day, hour, minutes and
            seconds
        has_suminfo (bool): Boolean indicating if the document has a
            SummaryInformation stream
        is_encrypted (bool): Boolean indicating if the document is encrypted
        is_word (bool): Boolean indicating if the document is a Word
        is_excel (bool): Boolean indicating if the document is an Excel
        is_ppt (bool):  Boolean indicating if the document is a Powerpoint
        is_visio (bool): Boolean indicating if the document is a Visio
        has_object_pool (bool): Boolean indicating if the document has an
            ObjectPool stream
        flash_count (int): Number of Flash objects
        directory_entries (typing.List[DirectoryEntry]): Directory entries
        sectors_count (int): Number of sectors
        macros_code (typing.List[str]): Code of all macros found
    """

    filename: str = ""
    header_text: typing.List[str] = []
    total_edit_time: int = 0
    pages_count: int = 0
    words_count: int = 0
    chars_count: int = 0
    security: int = 0
    creation_time: int = 0
    modification_time: int = 0
    has_suminfo: bool = False
    is_encrypted: bool = False
    is_word: bool = False
    is_excel: bool = False
    is_ppt: bool = False
    is_visio: bool = False
    has_object_pool: bool = False
    flash_count: int = 0
    directory_entries: typing.List[DirectoryEntry] = []
    sectors_count: int = 0
    macros_code: typing.List[str] = []

    def __init__(self) -> None:
        """Initializes the DocumentBucket instance."""
        self.filename = ""
        self.header_text = []
        self.total_edit_time = 0
        self.pages_count = 0
        self.words_count = 0
        self.chars_count = 0
        self.security = 0
        self.creation_time = 0
        self.modification_time = 0
        self.has_suminfo = False
        self.is_encrypted = False
        self.is_word = False
        self.is_excel = False
        self.is_ppt = False
        self.is_visio = False
        self.has_object_pool = False
        self.flash_count = 0
        self.directory_entries = []
        self.sectors_count = 0
        self.macros_code = []

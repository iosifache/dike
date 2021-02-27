import typing

import capstone
import pefile
import qiling
import qiling.const


class SectionCharacteristics(dict):
    """Class encapsulating details about a section of an executable

    Attributes:
        name (str): Name of the section
        entropy (float): Entropy of the section
        raw_size (int): Raw size of the section
        virtual_size (int): Virtual size of the section
    """
    name: str = None
    entropy: float = 1
    raw_size: int = 0
    virtual_size: int = 0

    def __init__(self, name: str, entropy: float, raw_size: int,
                 virtual_size: int) -> None:
        """Initializes the SectionCharacteristics instance.
        """
        dict.__init__(self,
                      name=name,
                      entropy=entropy,
                      raw_size=raw_size,
                      virtual_size=virtual_size)


class StaticBucket:
    """Class encapsulating details about an executable, extracted via static
    analysis

    Attributes:
        filename (str): Filename of the executable
        pe_file (pefile.PE): pefile object representing the executable
        size (int): Size of executable, in bytes
        content (bytes): Bytes representing the whole executable
        disassembler (capstone.Cs): Capstone dissasambler instance, shared by
                                    extractors
        strings (typing.List[str]): List of printable character sequences from
                                    the executable
        sections (typing.List[SectionCharacteristics]): List of
                                                        SectionCharacteristics,
                                                        representing the
                                                        sections of the
                                                        executable
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
    filename: str = None
    pe_file: pefile.PE = None
    size: int = -1
    content: bytes = None
    disassembler: capstone.Cs = None
    strings: typing.List[str] = []
    sections: typing.List[SectionCharacteristics] = []
    imported_libraries: typing.List[str] = []
    imported_functions: typing.List[str] = []
    exported_functions: typing.List[str] = []
    opcodes: typing.List[str] = []
    apis: typing.List[str] = []


class DynamicBucket:
    """Class encapsulating details about an executable, extracted via dynamic
    analysis

    Attributes:
        emulator (qiling.Qiling): Qiling emulator instance, shared by extractors
        log_file (str): Full path to the logfile of Qiling
        opcodes (typing.List[str]): List of strings representing the mnemonics
                                    of the executed opcodes
        apis (typing.List[str]): List of strings representing the names of the
                                 called Windows API functions names
    """
    emulator: qiling.Qiling = None
    log_file: str = None
    opcodes: typing.List[str] = []
    apis: typing.List[str] = []


class DirectoryEntry(dict):
    """Class encapsulating details about an OLE directory entry

    Attributes:
        name (str): Name of the entry
        size (float): Size of the entry
    """
    name: str = None
    size: int = 0

    def __init__(self, name: str, size: int) -> None:
        dict.__init__(self, name=name, size=size)


class DocumentBucket:
    """Class encapsulating details about an OLE file, namely files such as
    Microsoft Word, Powerpoint and Excel

    Attributes:
        filename (str): Filename of the document
        header_text (str): Text found in the header of the document, namely in
                           fields such as title, subject, authors, keywords and
                           comment
        total_edit_time (int): Document edit time, in seconds
        pages_count (int): Number of pages in document
        words_count (int): Number of words in document
        chars_count (int): Number of characters in document
        security (int): Number indicating the security level of the document
        creation_time (int): Time of creation of the document, composed by
                             the concatenation of year, month, day, hour,
                             minutes and seconds
        modification_time (int): Time of the last modification of the document,
                                 composed by the concatenation of year, month,
                                 day, hour, minutes and seconds
        has_suminfo (bool): Boolean indicating if the document has a
                            SummaryInformation stream
        is_encrypted (bool): Boolean indicating if the document in encrypted
        is_word (bool): Boolean indicating if the document is a Word
        is_excel (bool): Boolean indicating if the document is an Excel
        is_ppt (bool):  Boolean indicating if the document is a Powerpoint
        is_visio (bool): Boolean indicating if the document is a Visio
        has_object_pool (bool): Boolean indicating if the document has an
                                ObjectPool stream
        flash_count (int): Number of Flash objects in document
        directory_entries (typing.List[DirectoryEntry]): Directory entries in
                                                         document
        sectors_count (int): Number of sectors in document
        macros_code (typing.List[str]): Code of all macros found in document
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

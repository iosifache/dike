import typing

import capstone
import pefile
import qiling
import qiling.const


class SectionCharacteristics(dict):
    """Class encapsulating details about a section

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
                 virtual_size: int):
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

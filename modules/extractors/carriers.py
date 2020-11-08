from pickle import NONE
import pefile
import qiling
import qiling.const
import capstone
import typing


class _OpcodesCategoryFrequency:
    category_name: str = None
    frequency: float = None

    def __init__(self, category_name: str, frequency: float):
        self.category_name = category_name
        self.frequency = frequency


class _APIsFrequency:
    pass


class _SectionCharacteristics:
    name: str = None
    entropy: float = 1
    raw_size: int = 0
    virtual_size: int = 0

    def __init__(self, name: str, entropy: float, raw_size: int,
                 virtual_size: int):
        self.name = name
        self.entropy = entropy
        self.raw_size = raw_size
        self.virtual_size = virtual_size


class _StaticBucket:
    filename: str = None
    pe_file: pefile.PE = None
    content: bytes = None
    disassambler: capstone.Cs = None
    strings: typing.List[str] = []
    sections: typing.List[_SectionCharacteristics] = []
    imported_libraries: typing.List[str] = []
    imported_functions: typing.List[str] = []
    exported_functions: typing.List[str] = []


class _DynamicBucket:
    emulator: qiling.Qiling = None
    opcodes: typing.List[str] = []
    opcodes_freqs: typing.List[_OpcodesCategoryFrequency] = []
    apis: typing.List[str] = []
    apis_freqs: typing.List[_APIsFrequency] = []
import pefile
import qiling
import qiling.const
import capstone
import json
import typing


class _GenericCategoryFrequency(dict):
    category_name: str = None
    frequency: float = None

    def __init__(self, category_name: str, frequency: float):
        dict.__init__(self, category_name=category_name, frequency=frequency)


class _SectionCharacteristics(dict):
    name: str = None
    entropy: float = 1
    raw_size: int = 0
    virtual_size: int = 0

    def __init__(self, name: str, entropy: float, raw_size: int,
                 virtual_size: int):
        dict.__init__(self,
                      name=name,
                      entropy=entropy,
                      raw_size=raw_size,
                      virtual_size=virtual_size)


class _StaticBucket:
    filename: str = None
    pe_file: pefile.PE = None
    size: int = -1
    content: bytes = None
    disassambler: capstone.Cs = None
    strings: typing.List[str] = []
    sections: typing.List[_SectionCharacteristics] = []
    imported_libraries: typing.List[str] = []
    imported_functions: typing.List[str] = []
    exported_functions: typing.List[str] = []


class _DynamicBucket:
    emulator: qiling.Qiling = None
    log_file: str = None
    opcodes: typing.List[str] = []
    opcodes_freqs: typing.List[_GenericCategoryFrequency] = []
    apis: typing.List[str] = []
    apis_freqs: typing.List[_GenericCategoryFrequency] = []
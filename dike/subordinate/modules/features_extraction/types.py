from enum import Enum


class FeatureTypes(Enum):
    """Enumeration for all possible types of an extracted feature"""
    INTEGER = 0
    FLOAT = 1
    STRING = 2
    INTEGER_ARRAY = 10
    FLOAT_ARRAY = 11
    STRING_ARRAY = 12


class ExtractorsType(Enum):
    """Enumeration for all possible types of an extractors"""
    STATIC_STRINGS = "StaticStrings"
    STATIC_PE_CHARACTERISTICS = "StaticPECharacteristics"
    STATIC_OPCODES = "StaticOpcodes"
    STATIC_APIS = "StaticAPIs"
    DYNAMIC_OPCODES = "DynamicOpcodes"
    DYNAMIC_APIS = "DynamicAPIs"

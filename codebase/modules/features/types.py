"""Types used in this module."""
from enum import Enum


class FeatureTypes(Enum):
    """Enumeration for all possible types of extracted features."""

    BOOLEAN = 0
    INTEGER = 1
    FLOAT = 2
    STRING = 3
    INTEGER_ARRAY = 11
    FLOAT_ARRAY = 12
    STRING_ARRAY = 13


class ExtractorsTypes(Enum):
    """Enumeration for all possible types of extractors."""

    STATIC_STRINGS = "StaticStrings"
    STATIC_PE_CHARACTERISTICS = "StaticPECharacteristics"
    STATIC_OPCODES = "StaticOpcodes"
    STATIC_APIS = "StaticAPIs"
    DYNAMIC_OPCODES = "DynamicOpcodes"
    DYNAMIC_APIS = "DynamicAPIs"
    GENERAL_OLE_DETAILS = "GeneralOLEDetails"
    OLE_MACROS = "OLEMacros"

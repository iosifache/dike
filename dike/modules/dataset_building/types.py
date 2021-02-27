from __future__ import annotations

from enum import Enum


class AnalyzedFileTypes(Enum):
    """Enumeration for all possible types of an analyzed file"""
    class PE:
        """Enumeration containing details about PE files"""
        ID = 0
        EXTENSION = "exe"

    class OLE:
        """Enumeration containing details about OLE files"""
        ID = 1
        EXTENSION = "ole"

    @staticmethod
    def map_extension_to_type(extension: str) -> "AnalyzedFileTypes":
        """Maps an extension to its AnalyzedFileTypes parent class.

        Args:
            extension [str]: Extension to map

        Returns:
            AnalyzedFileTypes: Corresponding AnalyzedFileTypes class or, if
                               there is not an mapping defined for this
                               extension, None
        """
        MAP = {
            "exe": AnalyzedFileTypes.PE,
            "doc": AnalyzedFileTypes.OLE,
            "docx": AnalyzedFileTypes.OLE,
            "docm": AnalyzedFileTypes.OLE,
            "xls": AnalyzedFileTypes.OLE,
            "xlsx": AnalyzedFileTypes.OLE,
            "xlsm": AnalyzedFileTypes.OLE,
            "ppt": AnalyzedFileTypes.OLE,
            "pptx": AnalyzedFileTypes.OLE,
            "pptm": AnalyzedFileTypes.OLE
        }

        try:
            return MAP[extension]
        except:
            return None

    @staticmethod
    def map_id_to_type(type_id: int) -> "AnalyzedFileTypes":
        """Maps an identifier number to its AnalyzedFileTypes parent class.

        Args:
            type_id [int]: Identifier number

        Returns:
            AnalyzedFileTypes: Corresponding AnalyzedFileTypes class or, if
                               there is not an mapping defined for this
                               extension, None
        """
        for child in AnalyzedFileTypes:
            if (child.value.ID == type_id):
                return child

        return None

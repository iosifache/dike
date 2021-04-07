"""Types used in this module.

Usage example:

    # Set a file type
    file_type = AnalyzedFileTypes.PE

    # Map an extension to its type
    file_type = AnalyzedFileTypes.map_extension_to_type("exe")

    # Map an ID to its type
    file_type = AnalyzedFileTypes.map_id_to_type(0)
"""
from __future__ import annotations

from enum import Enum


class AnalyzedFileTypes(Enum):
    """Enumeration for all possible types of analyzed files."""

    class PE:
        """Enumeration containing details about PE files."""

        ID = 0
        STANDARD_EXTENSION = "exe"

    class OLE:
        """Enumeration containing details about OLE files."""

        ID = 1
        STANDARD_EXTENSION = "ole"
        OTHER_EXTENSION = [
            "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm"
        ]

    class FEATURES:
        """Enumeration containing details about serialized features files."""

        ID = 2
        STANDARD_EXTENSION = "ftr"

    @staticmethod
    def map_extension_to_type(
            filename_or_extension: str) -> "AnalyzedFileTypes":
        """Maps an extension to its AnalyzedFileTypes parent class.

        Args:
            filename_or_extension (str): Extension or filename whose extension
                to map

        Returns:
            AnalyzedFileTypes: Corresponding AnalyzedFileTypes class or, if
                there is not a mapping defined for the extension, None
        """
        # Extract the extension if it isn't already extracted
        if "." in filename_or_extension:
            extension = filename_or_extension.split(".")[-1]
        else:
            extension = filename_or_extension

        for file_type in AnalyzedFileTypes:
            if (extension == file_type.value.STANDARD_EXTENSION
                    or (hasattr(file_type.value, "OTHER_EXTENSION")
                        and extension in file_type.value.OTHER_EXTENSION)):
                return file_type

        return None

    @staticmethod
    def map_id_to_type(type_id: int) -> "AnalyzedFileTypes":
        """Maps an identifier number to its AnalyzedFileTypes parent class.

        Args:
            type_id (int): Identifier number

        Returns:
            AnalyzedFileTypes: Corresponding AnalyzedFileTypes class or, if
                there is not a mapping defined for the extension, None
        """
        for child in AnalyzedFileTypes:
            if child.value.ID == type_id:
                return child

        return None

    @staticmethod
    def has_valid_extension(filename: str) -> bool:
        """Checks if the filename has a known extension.

        Args:
            filename (str): Name of the file

        Returns:
            bool: Boolean indicating if the filename has a known extension
        """
        if "." not in filename:
            return False

        if not AnalyzedFileTypes.map_extension_to_type(filename):
            return False

        return True

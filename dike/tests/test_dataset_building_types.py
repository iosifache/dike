"""Program testing the types defined for dataset building purposes"""
import math

from modules.dataset_building.types import AnalyzedFileTypes


def test_conversion_from_valid_extension_to_type():
    """Tests the conversion of a valid extension to its corresponding type."""
    file_type = AnalyzedFileTypes.map_extension_to_type("exe")
    assert file_type == AnalyzedFileTypes.PE, "The conversion valid extension - type returned an invalid result."


def test_conversion_from_valid_id_to_type():
    """Tests the conversion of a valid ID to its corresponding type."""
    file_type = AnalyzedFileTypes.map_id_to_type(0)
    assert file_type == AnalyzedFileTypes.PE, "The conversion valid ID - type returned an invalid result."


def test_conversion_from_invalid_extension():
    """Tests the conversion of a invalid extension."""
    file_type = AnalyzedFileTypes.map_extension_to_type("py")
    assert file_type is None, "The conversion invalid extension - type returned an invalid result."


def test_conversion_from_invalid_id():
    """Tests the conversion of a invalid ID."""
    file_type = AnalyzedFileTypes.map_id_to_type(math.inf)
    assert file_type is None, "The conversion invalid ID - type returned an invalid result."

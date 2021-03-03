"""Program testing feature extraction via the core"""
import pytest
from modules.features_extraction.core import ExtractionCore, ExtractorsType
from modules.utils.errors import FileToExtractFromNotFoundError


def test_load_extractor_by_name():
    """Tests the loading of extractors by their names."""
    core = ExtractionCore()

    # Try to load an valid extractor
    assert core.load_extractor_by_name("StaticStrings") is not None

    # Try to load an invalid extractor
    assert core.load_extractor_by_name("Nonexistent") is None


def test_extraction_core_for_pe_files():
    """Tests the extraction of PE files features via ExtractionCore."""
    core = ExtractionCore()

    # Attach the extractors to the core
    core.attach(ExtractorsType.STATIC_STRINGS)
    core.attach(ExtractorsType.STATIC_PE_CHARACTERISTICS)
    core.attach(ExtractorsType.STATIC_OPCODES)
    core.attach(ExtractorsType.STATIC_APIS)

    # Extract the features
    features = core.squeeze("tests/files/sample.exe")

    # Assert features from each extractor
    assert "!This program cannot be run in DOS mode." in features[
        0], "Features from the StaticStrings are not present."
    assert ".textbss" in features[
        5], "Features from the PECharacteristics are not present."
    assert "jmp" in features[
        9], "Features from the StaticOpcodes are not present."
    assert "GetProcAddress" in features[
        10], "Features from the StaticAPIs are not present."


def test_extraction_core_for_ole_files():
    """Tests the extraction of OLE files features via ExtractionCore."""
    core = ExtractionCore()

    # Attach the extractors to the core
    core.attach(ExtractorsType.GENERAL_OLE_DETAILS)
    core.attach(ExtractorsType.OLE_MACROS)

    # Extract the features
    features = core.squeeze("tests/files/sample.ole")

    # Assert features from each extractor
    assert "mmiranda" in features[
        0], "Features from the GeneralOLEDetails are not present."
    assert not features[19], "Features from the OLEMacros are not present."


def test_extraction_core_invalid_file():
    """Tests the reaction of the ExtractionCore when an non-existent file is
    given as parameter."""
    core = ExtractionCore()
    core.attach(ExtractorsType.STATIC_STRINGS)

    with pytest.raises(FileToExtractFromNotFoundError):
        core.squeeze("path/to/nonexistent/sample.exe")

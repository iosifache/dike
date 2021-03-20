"""Script for extracting features from OLE file

The script is meant to be imported (via pybind11 module, for example). The
process_file() function will then be used to extract a file features.

The functionalities are extracted from the dike's extractors module.

Required modules, that needs to be installed, are:
- oletools (used version at the time was 0.56).
"""
import pickle
import typing

from olefile import OleFileIO
from oletools.oleid import OleID
from oletools.olevba import VBA_Parser


class DirectoryEntry(dict):
    """Class encapsulating details about an OLE directory entry

    Attributes:
        name (str): Name of the entry
        size (float): Size of the entry
    """
    name: str
    size: int

    def __init__(self, name: str, size: int) -> None:
        dict.__init__(self, name=name, size=size)


class DocumentBucket:
    """Class encapsulating details about an OLE file, namely files such as
    Microsoft Word, Powerpoint and Excel

    Attributes:
        filename (str): Filename of the document
        header_text (str): Text found in the header of the document, namely in
            fields such as title, subject, authors, keywords and comment
        total_edit_time (int): Document edit time, in seconds
        pages_count (int): Number of pages in document
        words_count (int): Number of words in document
        chars_count (int): Number of characters in document
        security (int): Number indicating the security level of the document
        creation_time (int): Time of creation of the document, composed by
            the concatenation of year, month, day, hour, minutes and seconds
        modification_time (int): Time of the last modification of the document,
            composed by the concatenation of year, month, day, hour, minutes and
            seconds
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

    def __init__(self) -> None:
        # Default values of members
        self.filename = ""
        self.header_text = []
        self.total_edit_time = 0
        self.pages_count = 0
        self.words_count = 0
        self.chars_count = 0
        self.security = 0
        self.creation_time = 0
        self.modification_time = 0
        self.has_suminfo = False
        self.is_encrypted = False
        self.is_word = False
        self.is_excel = False
        self.is_ppt = False
        self.is_visio = False
        self.has_object_pool = False
        self.flash_count = 0
        self.directory_entries = []
        self.sectors_count = 0
        self.macros_code = []


def extract(document_bucket: DocumentBucket) -> None:
    """Extracts the features from an OLE2 file into a bucket.

    Args:
        document_bucket (DocumentBucket): Bucket containing the extracted
            features
    """
    ole = OleFileIO(document_bucket.filename)

    # Metadatas
    meta = ole.get_metadata()
    for property_name in meta.SUMMARY_ATTRIBS:
        property_value = getattr(meta, property_name)

        if (property_name in [
                "title", "subject", "author", "keywords", "comments",
                "last_saved_by"
        ] and property_value):
            document_bucket.header_text.append(property_value.decode("utf-8"))
        elif (property_name == "total_edit_time"):
            document_bucket.total_edit_time = property_value
        elif (property_name == "num_pages"):
            document_bucket.pages_count = property_value
        elif (property_name == "num_words"):
            document_bucket.words_count = property_value
        elif (property_name == "num_chars"):
            document_bucket.words_count = property_value
        elif (property_name == "security"):
            document_bucket.security = property_value

    # Timestamps
    creation_time = ole.root.getctime()
    modification_time = ole.root.getmtime()
    if creation_time:
        document_bucket.creation_time = int(
            creation_time.strftime("%Y%m%d%H%M%S"))
    if modification_time:
        document_bucket.modification_time = int(
            modification_time.strftime("%Y%m%d%H%M%S"))

    # Special characteristics
    oid = OleID(document_bucket.filename)
    indicators = oid.check()
    for indicator in indicators:
        indicator_id = indicator.id
        indicator_value = indicator.value

        if (indicator_id == "has_suminfo"):
            document_bucket.has_suminfo = indicator_value
        elif (indicator_id == "encrypted"):
            document_bucket.is_encrypted = indicator_value
        elif (indicator_id == "word"):
            document_bucket.is_word = indicator_value
        elif (indicator_id == "excel"):
            document_bucket.is_excel = indicator_value
        elif (indicator_id == "ppt"):
            document_bucket.is_ppt = indicator_value
        elif (indicator_id == "visio"):
            document_bucket.is_visio = indicator_value
        elif (indicator_id == "ObjectPool"):
            document_bucket.has_object_pool = indicator_value
        elif (indicator_id == "flash"):
            document_bucket.flash_count = indicator_value

    # Directory entries
    for entry in ole.direntries:
        if entry:
            document_bucket.directory_entries.append(
                DirectoryEntry(entry.name, entry.size))

    # Sectors
    document_bucket.sectors_count = len(ole.fat)

    # Macros
    vbaparser = VBA_Parser(document_bucket.filename)
    if vbaparser.detect_vba_macros():
        for (_, _, _, vba_code) in vbaparser.extract_macros():
            document_bucket.macros_code.append(vba_code)


def squeeze(document_bucket: DocumentBucket) -> typing.List[typing.Any]:
    """Returns the extracted features from bucket.

    Args:
        document_bucket (DocumentBucket): Bucket containing the extracted
            features

    Returns:
        typing.List[typing.Any]: Extracted features
    """
    return [
        document_bucket.header_text, document_bucket.total_edit_time,
        document_bucket.pages_count, document_bucket.words_count,
        document_bucket.chars_count, document_bucket.security,
        document_bucket.creation_time, document_bucket.modification_time,
        document_bucket.has_suminfo, document_bucket.is_encrypted,
        document_bucket.is_word, document_bucket.is_excel,
        document_bucket.is_ppt, document_bucket.is_visio,
        document_bucket.has_object_pool, document_bucket.flash_count,
        [entry["name"] for entry in document_bucket.directory_entries],
        [entry["size"] for entry in document_bucket.directory_entries
         ], document_bucket.sectors_count, document_bucket.macros_code
    ]


def process_file(filename: str) -> str:
    """Extracts the features from a file.
    Args:
        filename (str): Filename of an OLE2 file

    Returns:
        str: Serialized extracted features
    """
    bucket = DocumentBucket()
    bucket.filename = filename

    extract(bucket)
    features = squeeze(bucket)
    serialized_features = pickle.dumps(features, protocol=0)

    return serialized_features

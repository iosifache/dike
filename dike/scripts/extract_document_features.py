"""Script for feature extraction from OLE files.

The script contains functionalities extracted from the dike's modules. It is
platform-independent (the required classes are already included) and runs
without other files.

The script is meant to be imported (via pybind11 module, for example). The
process_file() function will then be used to extract the features of a file.

Required modules, that need to be installed, are:
- oletools (used version at the time was 0.56).
"""
import pickle  # nosec
import typing

from olefile import OleFileIO
from oletools.oleid import OleID
from oletools.olevba import VBA_Parser


class DirectoryEntry(dict):
    """See the modules/features/carriers.py file."""

    name: str
    size: int

    def __init__(self, name: str, size: int) -> None:  # noqa
        dict.__init__(self, name=name, size=size)


class DocumentBucket:
    """See the modules/features/carriers.py file."""

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

    def __init__(self) -> None:  # noqa
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

    # Metadata
    meta = ole.get_metadata()
    for property_name in meta.SUMMARY_ATTRIBS:
        property_value = getattr(meta, property_name)

        if (property_name in [
                "title", "subject", "author", "keywords", "comments",
                "last_saved_by"
        ] and property_value):
            document_bucket.header_text.append(property_value.decode("utf-8"))
        elif property_name == "total_edit_time":
            document_bucket.total_edit_time = property_value
        elif property_name == "num_pages":
            document_bucket.pages_count = property_value
        elif property_name == "num_words":
            document_bucket.words_count = property_value
        elif property_name == "num_chars":
            document_bucket.words_count = property_value
        elif property_name == "security":
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

        if indicator_id == "has_suminfo":
            document_bucket.has_suminfo = indicator_value
        elif indicator_id == "encrypted":
            document_bucket.is_encrypted = indicator_value
        elif indicator_id == "word":
            document_bucket.is_word = indicator_value
        elif indicator_id == "excel":
            document_bucket.is_excel = indicator_value
        elif indicator_id == "ppt":
            document_bucket.is_ppt = indicator_value
        elif indicator_id == "visio":
            document_bucket.is_visio = indicator_value
        elif indicator_id == "ObjectPool":
            document_bucket.has_object_pool = indicator_value
        elif indicator_id == "flash":
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
    """Returns the extracted features, from the bucket.

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

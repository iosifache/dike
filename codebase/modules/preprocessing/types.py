"""Types used in this module."""
import string
from enum import Enum


class Charset(Enum):
    """Enumeration storing all available charsets used by the preprocessors."""

    LOWERCASE = string.ascii_lowercase
    UPPERLOWERCASE = string.ascii_letters
    UPPERLOWERCASE_DIGITS = UPPERLOWERCASE + string.digits
    UPPERLOWERCASE_DIGITS_SPECIALS = UPPERLOWERCASE_DIGITS + string.punctuation


class PreprocessorsTypes(Enum):
    """Enumeration for all possible types of preprocessors."""

    IDENTITY = "Identity"
    BINARIZER = "Binarizer"
    K_BINS_DISCRETIZER = "KBinsDiscretizer"
    COUNTER = "Counter"
    COUNT_VECTORIZER = "CountVectorizer"
    N_GRAMS = "NGrams"
    GROUP_COUNTER = "GroupCounter"
    SAME_LENGTH_IMPUTER = "SameLengthImputer"


class ReductionAlgorithm(Enum):
    """Enumeration for all dimensionality reduction algorithms."""

    PCA = "PCA"
    FAST_ICA = "FastICA"
    NMF = "NMF"

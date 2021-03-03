"""Module defining the types used by the preprocessing functionality"""
from enum import Enum


class PreprocessorsTypes(Enum):
    """Enumeration for all possible types of an preprocessor"""
    IDENTITY = "Identity"
    BINARIZER = "Binarizer"
    K_BINS_DISCRETIZER = "KBinsDiscretizer"
    COUNTER = "Counter"
    COUNT_VECTORIZER = "CountVectorizer"
    N_GRAMS = "NGrams"
    GROUP_COUNTER = "GroupCounter"
    SAME_LENGTH_IMPUTER = "SameLengthImputer"

from __future__ import annotations
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import Binarizer, KBinsDiscretizer
from sklearn.feature_extraction.text import CountVectorizer
import numpy as np
import itertools
import string
import collections
from enum import Enum
import typing
import re
from enum import Enum
from utils.logger import Logger


class PreprocessorsTypes(Enum):
    IDENTITY = "Identity"
    BINARIZER = "Binarizer"
    K_BINS_DISCRETIZER = "KBinsDiscretizer"
    COUNTER = "Counter"
    COUNT_VECTORIZER = "CountVectorizer"
    N_GRAMS = "NGrams"
    FREQUENCY_EXTRACTOR = "FrequencyExtractor"


class Identity(BaseEstimator, TransformerMixin):
    def __init__(self):
        pass

    def fit(self, X: np.array, y: np.array = None) -> Counter:
        return self

    def transform(self, X: np.array, y: np.array = None) -> int:
        return X


class Counter(BaseEstimator, TransformerMixin):
    def __init__(self):
        pass

    def fit(self, X: np.array, y: np.array = None) -> Counter:
        return self

    def transform(self, X: np.array, y: np.array = None) -> int:
        return len(X)


class NGrams(BaseEstimator, TransformerMixin):
    class Charset(Enum):
        LOWERCASE = string.ascii_lowercase
        UPPERLOWERCASE = string.ascii_letters
        UPPERLOWERCASE_DIGITS = UPPERLOWERCASE + string.digits
        UPPERLOWERCASE_DIGITS_SPECIALS = UPPERLOWERCASE_DIGITS + string.punctuation

    _n: int = None
    _to_lowercase: bool = 0
    _valid_charset: Charset = None

    def __init__(self, n: int, to_lowercase: bool,
                 valid_charset: Charset) -> None:
        self._n = n
        self._to_lowercase = to_lowercase
        self._valid_charset = valid_charset

    def fit(self, X: np.array, y: np.array = None) -> NGrams:
        return self

    def transform(self, X: np.array, y: np.array = None) -> list:
        clean_list = []
        valid_charset_str = "".join(self._valid_charset.value)
        for element in X:
            if self._to_lowercase:
                element = element.lower()
            new_element = ""
            for char in element:
                if char in valid_charset_str:
                    new_element += char
            clean_list.append(new_element)

        # Create dictionary
        combinations = itertools.product(self._valid_charset.value,
                                         repeat=self._n)
        ngrams = {}
        for combination in combinations:
            combination_key = "".join(combination)
            ngrams[combination_key] = 0

        # Populate the dictionary
        for element in clean_list:
            for i in range(len(element) - self._n + 1):
                ngrams[element[i:i + self._n]] += 1

        return [ngrams[key] for key in ngrams.keys()]


class FrequencyExtractor(BaseEstimator, TransformerMixin):
    _categories: dict = None
    _verbose: bool = True
    _min_ignored_percent: float = 0

    def __init__(self, categories: dict, verbose: bool,
                 min_ignored_percent: float) -> None:
        self._categories = categories
        self._verbose = verbose
        self._min_ignored_percent = min_ignored_percent

    @staticmethod
    def _check_wildcards_match(pattern: str, string: str) -> bool:
        pattern = pattern.replace("*", r"(\w)*")
        return (re.match(pattern, string) is not None)

    def _print_list_of_outliers(self, elements: typing.List[str],
                                counter: collections.Counter):
        printed_caption = False
        for key in counter.keys():
            percent = counter[key] / len(elements)
            if (percent > self._min_ignored_percent):
                if not printed_caption:
                    Logger.log_new(
                        "Outliers (that are not in any category) are:")
                    printed_caption = True
                Logger.log(
                    "\t- {} with {} occurances ({:.3f}% from total)".format(
                        key, counter[key], 100 * percent))

    def fit(self, X: np.array, y: np.array = None) -> FrequencyExtractor:
        return self

    def transform(self, X: np.array, y: np.array = None) -> list:
        elements_count = len(X)
        counter = collections.Counter(X)
        frequency_dict = {}
        for category in self._categories:
            group_count = 0
            for label in self._categories[category]:
                if "*" in label:
                    # If the label has wild chars, then search all elements that
                    # matches the given pattern and add their occurences
                    matched_elements = [
                        element for element in counter.keys()
                        if self._check_wildcards_match(label, element)
                    ]
                    for matched_element in matched_elements:
                        group_count += counter[matched_element]
                        del counter[matched_element]
                else:
                    try:
                        group_count += counter[label]
                        del counter[label]
                    except:
                        pass

            frequency_dict[category] = 100 * group_count / elements_count

        if self._verbose:
            self._print_list_of_outliers(X, counter)

        return [frequency_dict[key] for key in frequency_dict.keys()]


class PreprocessorsFactory:
    @staticmethod
    def create_preprocessor_from_type(type: PreprocessorsTypes,
                                      arguments: dict) -> BaseEstimator:
        if (type == PreprocessorsTypes.IDENTITY):
            return Identity()
        elif (type == PreprocessorsTypes.BINARIZER):
            return Binarizer()
        elif (type == PreprocessorsTypes.K_BINS_DISCRETIZER):
            return KBinsDiscretizer()
        elif (type == PreprocessorsTypes.COUNTER):
            return Counter()
        elif (type == PreprocessorsTypes.COUNT_VECTORIZER):
            return CountVectorizer()
        elif (type == PreprocessorsTypes.N_GRAMS):
            return NGrams(**arguments)
        elif (type == PreprocessorsTypes.FREQUENCY_EXTRACTOR):
            return FrequencyExtractor(**arguments)
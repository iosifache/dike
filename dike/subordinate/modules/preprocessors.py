from __future__ import annotations
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import Binarizer, KBinsDiscretizer
from sklearn.feature_extraction.text import CountVectorizer
import numpy as np
import itertools
import string
import collections
from enum import Enum
import abc
import typing
import re
from enum import Enum
from utils.logger import Logger, LoggerMessageType


class PreprocessorsTypes(Enum):
    IDENTITY = "Identity"
    BINARIZER = "Binarizer"
    K_BINS_DISCRETIZER = "KBinsDiscretizer"
    COUNTER = "Counter"
    COUNT_VECTORIZER = "CountVectorizer"
    N_GRAMS = "NGrams"
    GROUP_COUNTER = "GroupCounter"


class _Preprocesor(BaseEstimator, TransformerMixin, abc.ABC):
    """Class modeling a preprocessor of extracted features"""
    @abc.abstractmethod
    def fit(self, X: np.array, y: np.array = None) -> typing.Any:
        """Fits the model based on datas.

        Args:
            X (np.array): Data for model fitting
            y (np.array, optional): Defaults to None.

        Returns:
            typing.Any: Instance being fit
        """
        pass

    def transform(self, X: np.array, y: np.array = None) -> typing.Any:
        """Transforms the given data, based on the already fit model

        Args:
            X (np.array): Data to be transformed
            y (np.array, optional): Defaults to None.

        Returns:
            typing.Any: Transformed data
        """
        pass


class Identity(_Preprocesor):
    """Class representing a preprocessor that only passes the input data to
    output"""
    def fit(self, X: np.array, y: np.array = None) -> Identity:
        """Same as the corresponding method of the parent class"""
        return self

    def transform(self, X: np.array, y: np.array = None) -> typing.Any:
        """Same as the corresponding method of the parent class

        Returns:
            typing.Any: Input data
        """
        return X


class Counter(_Preprocesor):
    """Class representing a preprocessor for counting the elements from the
    sample"""
    def fit(self, X: np.array, y: np.array = None) -> Counter:
        """Same as the corresponding method of the parent class"""
        return self

    def transform(self, X: np.array, y: np.array = None) -> int:
        """Same as the corresponding method of the parent class
        
        Returns:
            int: Count of the vector elements
        """
        return len(X)


class NGrams(_Preprocesor):
    """Class representing a preprocessor for generating the N-grams for a given
    piece of text

    It generates an N-gram dictionary based on the given N and charset. Before
    matching it to characters pairs, the text is lowercased if the corresponding
    option is set, case in which the size of the output data is reduced.

    """
    class Charset(Enum):
        """Enumeration storing available charsets"""
        LOWERCASE = string.ascii_lowercase
        UPPERLOWERCASE = string.ascii_letters
        UPPERLOWERCASE_DIGITS = UPPERLOWERCASE + string.digits
        UPPERLOWERCASE_DIGITS_SPECIALS = UPPERLOWERCASE_DIGITS + string.punctuation

    _n: int = None
    _to_lowercase: bool = 0
    _valid_charset: Charset = None

    def __init__(self, n: int, to_lowercase: bool, valid_charset: Charset):
        """Initializes the NGrams instance.

        Args:
            n (int): Number of grouped characters
            to_lowercase (bool): Boolean indicating if input data is lowercased
                                 before the effective processing
            valid_charset (Charset): Charset instace, indicating the charset to
                                     be used
        """
        self._n = n
        self._to_lowercase = to_lowercase
        self._valid_charset = valid_charset

    def fit(self, X: np.array, y: np.array = None) -> NGrams:
        """Same as the corresponding method of the parent class"""
        return self

    def transform(self, X: np.array, y: np.array = None) -> typing.List[int]:
        """Same as the corresponding method of the parent class
        
        Returns:
            typing.List[int]: List of occurances for each generated N gram
        """
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


class GroupCounter(_Preprocesor):
    """Class representing a preprocessor for categories-based frequency
    extraction"""
    _categories: dict = None
    _verbose: bool = True
    _min_ignored_percent: float = 0
    _allow_multiple_categories: bool = False

    def __init__(self, categories: dict, verbose: bool,
                 min_ignored_percent: float,
                 allow_multiple_categories: bool) -> None:
        """Initializes the GroupCounter instance.

        Args:
            categories (dict): Categories in which the data is grouped
            verbose (bool): Boolean indicating if the outliers entries are
                            logged
            min_ignored_percent (float): Percentage of occurances above which a
                                skipped entry is considered outlier
            allow_multiple_categories (bool): Boolean indicating if an entry can
                                              can be grouped under multiple
                                              categories
        """
        self._categories = categories
        self._verbose = verbose
        self._min_ignored_percent = min_ignored_percent
        self._allow_multiple_categories = allow_multiple_categories

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
                    Logger.log("Outliers (that are not in any category) are:",
                               LoggerMessageType.NEW)
                    printed_caption = True
                Logger.log(
                    "\t- {} with {} occurances ({:.3f}% from total)".format(
                        key, counter[key], 100 * percent))

    def fit(self, X: np.array, y: np.array = None) -> GroupCounter:
        """Same as the corresponding method of the parent class"""
        return self

    def transform(self, X: np.array, y: np.array = None) -> typing.List[int]:
        """Same as the corresponding method of the parent class
        
        Returns:
            typing.List[int]: List of occurances for each category
        """
        X = [elem.lower() for elem in X]
        counter = collections.Counter(X)
        frequency_dict = {}
        valid_elements = 0
        for category in self._categories:
            group_count = 0
            for label in self._categories[category]:
                if "*" in label:
                    # If the label has wild chars, then search all elements that
                    # matches the given pattern and add their occurrences
                    matched_elements = [
                        element for element in counter.keys()
                        if self._check_wildcards_match(label, element)
                    ]
                    for matched_element in matched_elements:
                        group_count += counter[matched_element]
                        valid_elements += 1
                        if (not self._allow_multiple_categories):
                            del counter[matched_element]
                else:
                    try:
                        group_count += counter[label]
                        valid_elements += 1
                        if (not self._allow_multiple_categories):
                            del counter[label]
                    except:
                        pass

                if (self._allow_multiple_categories):
                    del counter[label]

            frequency_dict[category] = group_count

        if self._verbose:
            self._print_list_of_outliers(X, counter)

        return [frequency_dict[key] for key in frequency_dict.keys()]


class PreprocessorsFactory:
    """Class for creating preprocessors instances"""
    @staticmethod
    def create_preprocessor_from_type(type: PreprocessorsTypes,
                                      arguments: dict) -> _Preprocesor:
        """Creates a preprocessor instances.

        Args:
            type (PreprocessorsTypes): Type of the preprocessor
            arguments (dict): Arguments being passed to preprocessor contructor

        Returns:
            _Preprocesor: Preprocessor instance
        """
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
        elif (type == PreprocessorsTypes.GROUP_COUNTER):
            return GroupCounter(**arguments)
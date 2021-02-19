from __future__ import annotations

import abc
import collections
import itertools
import re
import string
import typing
from enum import Enum

import numpy as np
import pandas
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import \
    CountVectorizer as StandardCountVectorizer
from utils.logger import LoggedMessageType, Logger


class Preprocessor(BaseEstimator, TransformerMixin, abc.ABC):
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
        return

    @abc.abstractmethod
    def transform(self, X: np.array, y: np.array = None) -> typing.Any:
        """Transforms the given data, based on the already fit model.

        Args:
            X (np.array): Data to be transformed
            y (np.array, optional): Defaults to None.

        Returns:
            typing.Any: Transformed data
        """
        return


class Identity(Preprocessor):
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


class Counter(Preprocessor):
    """Class representing a preprocessor for counting the elements from the
    sample"""
    def fit(self, X: np.array, y: np.array = None) -> Counter:
        """Same as the corresponding method of the parent class"""
        return self

    # pylint: disable=unused-argument
    def _transform_each(self, X: np.array, y: np.array = None) -> int:
        return len(X)

    def transform(self,
                  X: np.array,
                  y: np.array = None) -> typing.List[typing.List[int]]:
        """Same as the corresponding method of the parent class

        Returns:
            int: Count of the vector elements
        """
        return [self._transform_each(x, y) for x in X]


class CountVectorizer(Preprocessor):
    """Class representing a preprocessor for counting the words into a list"""
    _inner_model: StandardCountVectorizer = None

    def __init__(self):
        self._inner_model = StandardCountVectorizer()

    def fit(self, X: np.array, y: np.array = None) -> Counter:
        """Same as the corresponding method of the parent class"""
        # Transform list to phrase
        transformed_X = []
        for i, _ in enumerate(X):
            transformed_X.append(" ".join(X[i]))

        # Fit the standard sklearn model
        self._inner_model.fit(transformed_X, y)

        return self

    def transform(self,
                  X: np.array,
                  y: np.array = None) -> typing.List[typing.List[int]]:
        """Same as the corresponding method of the parent class

        Returns:
            typing.List[typing.List[int]]: List of occurances
        """
        # Transform list to phrase
        transformed_X = []
        for i, _ in enumerate(X):
            transformed_X.append(" ".join(X[i]))

        return self._inner_model.transform(transformed_X)


class NGrams(Preprocessor):
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
        UPPERLOWERCASE_DIGITS_SPECIALS = UPPERLOWERCASE_DIGITS + \
            string.punctuation

    n: int = None
    to_lowercase: bool = False
    valid_charset: Charset = None

    def __init__(self, n: int, to_lowercase: bool, valid_charset: Charset):
        """Initializes the NGrams instance.

        Args:
            n (int): Number of grouped characters
            to_lowercase (bool): Boolean indicating if input data is lowercased
                                 before the effective processing
            valid_charset (Charset): Charset instace, indicating the charset to
                                     be used
        """
        self.n = n
        self.to_lowercase = to_lowercase
        self.valid_charset = valid_charset

    def fit(self, X: np.array, y: np.array = None) -> NGrams:
        """Same as the corresponding method of the parent class"""
        return self

    # pylint: disable=unused-argument
    def _transform_each(self,
                        X: np.array,
                        y: np.array = None) -> typing.List[int]:
        clean_list = []
        valid_charset_str = "".join(self.valid_charset.value)
        for element in X:
            if self.to_lowercase:
                element = element.lower()
            new_element = ""
            for char in element:
                if char in valid_charset_str:
                    new_element += char
            clean_list.append(new_element)

        # Create dictionary
        combinations = itertools.product(self.valid_charset.value,
                                         repeat=self.n)
        ngrams = {}
        for combination in combinations:
            combination_key = "".join(combination)
            ngrams[combination_key] = 0

        # Populate the dictionary
        for element in clean_list:
            for i in range(len(element) - self.n + 1):
                ngrams[element[i:i + self.n]] += 1

        return list(ngrams.values())

    def transform(self,
                  X: np.array,
                  y: np.array = None) -> typing.List[typing.List[int]]:
        """Same as the corresponding method of the parent class

        Returns:
            typing.List[int]: List of occurances for each generated N gram
        """
        return [self._transform_each(x, y) for x in X]


class GroupCounter(Preprocessor):
    """Class representing a preprocessor for categories-based frequency
    extraction"""
    categories: dict = None
    verbose: bool = True
    min_ignored_percent: float = 0
    allow_multiple_categories: bool = False

    def __init__(
        self,
        categories: dict,
        allow_multiple_categories: bool,
        verbose: bool = False,
        min_ignored_percent: float = 0,
    ) -> None:
        """Initializes the GroupCounter instance.

        Args:
            categories (dict): Categories in which the data is grouped
            allow_multiple_categories (bool): Boolean indicating if an entry can
                                              can be grouped under multiple
                                              categories
            verbose (bool): Boolean indicating if the outliers entries are
                            logged
            min_ignored_percent (float): Percentage of occurances above which a
                                         skipped entry is considered outlier
        """
        self.categories = categories
        self.verbose = verbose
        self.min_ignored_percent = min_ignored_percent
        self.allow_multiple_categories = allow_multiple_categories

    @staticmethod
    def _check_wildcards_match(pattern: str, raw_string: str) -> bool:
        pattern = pattern.replace("*", r"(\w)*")
        return (re.match(pattern, raw_string) is not None)

    def _print_list_of_outliers(self, elements: typing.List[str],
                                counter: collections.Counter):
        printed_caption = False
        for key in counter.keys():
            percent = counter[key] / len(elements)
            if (percent > self.min_ignored_percent):
                if not printed_caption:
                    Logger.log("Outliers (that are not in any category) are:",
                               LoggedMessageType.NEW)
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
        for category in self.categories:
            group_count = 0
            for label in self.categories[category]:

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
                        del counter[matched_element]
                else:
                    try:
                        group_count += counter[label]
                        valid_elements += 1
                        del counter[label]
                    except:
                        pass

            frequency_dict[category] = group_count

        if self.verbose:
            self._print_list_of_outliers(X, counter)

        return list(frequency_dict.values())


class SameLengthImputer(Preprocessor):
    """Class representing a preprocessor that imputes the lines of a matrix to
    have the same length"""
    def fit(self, X: np.array, y: np.array = None) -> Identity:
        """Same as the corresponding method of the parent class"""
        return self

    def transform(self, X: np.array, y: np.array = None) -> typing.Any:
        """Same as the corresponding method of the parent class

        Returns:
            typing.Any: Input data
        """
        first_element = X[0][0]
        if (isinstance(first_element, int)
                or isinstance(first_element, float)):
            value = 0
        elif isinstance(first_element, str):
            value = ""

        max_length = max([len(line) for line in X])
        for line in X:
            to_add = max_length - len(line)
            line.extend(to_add * [value])
        return pandas.DataFrame(X)

"""Preprocessors.

Usage example:

    # Create a preprocessor
    preprocessor = Identity()

    # Process data
    preprocessed_data = preprocessor.fit_transform([[0, 1, 2], [0], [0, 1]])
"""
from __future__ import annotations

import abc
import collections
import itertools
import re
import typing

import numpy as np
from modules.preprocessing.types import Charset
from modules.utils.logger import Logger
from modules.utils.types import LoggedMessageTypes
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import \
    CountVectorizer as StandardCountVectorizer


# pylint: disable=invalid-name
class Preprocessor(BaseEstimator, TransformerMixin, abc.ABC):
    """Class modeling a preprocessor."""

    @abc.abstractmethod
    def fit(self, X: np.array, y: np.array = None) -> typing.Any:
        """Fits the model based on data.

        Args:
            X (np.array): Data for model fitting
            y (np.array, optional): None

        Returns:
            typing.Any: Instance being fit
        """
        return

    @abc.abstractmethod
    def transform(self, X: np.array, y: np.array = None) -> typing.Any:
        """Transforms the given data, based on the already fit model.

        Args:
            X (np.array): Data to be transformed
            y (np.array, optional): None

        Returns:
            typing.Any: Transformed data
        """
        return


class Identity(Preprocessor):
    """Identity preprocessor.

    It only passes the input data to output.
    """

    def fit(self, X: np.array, y: np.array = None) -> Identity:
        """See the Preprocessor.fit() method.

        # noqa
        """
        return self

    def transform(self, X: np.array, y: np.array = None) -> typing.Any:
        """See the Preprocessor.transform() method.

        # noqa
        """
        return X


class Counter(Preprocessor):
    """Counter preprocessor.

    It counts the elements for each row of the input.
    """

    def fit(self, X: np.array, y: np.array = None) -> Counter:
        """See the Preprocessor.fit() method.

        # noqa
        """
        return self

    # pylint: disable=unused-argument
    def _transform_each(self, X: np.array, y: np.array = None) -> int:
        return len(X)

    def transform(self, X: np.array, y: np.array = None) -> typing.List[int]:
        """See the Preprocessor.transform() method.

        # noqa
        """
        return [self._transform_each(x, y) for x in X]


class CountVectorizer(Preprocessor):
    """Count vectorizer preprocessor.

    It counts the words from a list.
    """

    _inner_model: StandardCountVectorizer

    def __init__(self) -> None:
        """Initializes the CountVectorizer instance."""
        self._inner_model = StandardCountVectorizer()

    def fit(self, X: np.array, y: np.array = None) -> CountVectorizer:
        """See the Preprocessor.fit() method.

        # noqa
        """
        # Transform list to phrase
        transformed_X = []
        for x in X:
            transformed_X.append(" ".join(x))

        # Fit the standard sklearn model
        self._inner_model.fit(transformed_X, y)

        return self

    def transform(self,
                  X: np.array,
                  y: np.array = None) -> typing.List[typing.List[int]]:
        """See the Preprocessor.transform() method.

        # noqa
        """
        # Transform list to phrase
        transformed_X = []
        for x in X:
            transformed_X.append(" ".join(x))

        # Transform the data with the inner sklearn model
        return self._inner_model.transform(transformed_X)


class NGrams(Preprocessor):
    """N-grams preprocessor.

    It generates an N-gram dictionary based on the given N and charset. Before
    matching it to characters pairs, the text is lowercased if the corresponding
    option is set, a case in which the size of the output data is reduced.
    """

    n: int
    to_lowercase: bool
    valid_charset: Charset

    def __init__(self, n: int, to_lowercase: bool,
                 valid_charset: Charset) -> None:
        """Initializes the NGrams instance.

        Args:
            n (int): Number of grouped characters
            to_lowercase (bool): Boolean indicating if input data is lowercased
                before the effective grouping
            valid_charset (Charset): Charset instance, indicating the charset to
                be used
        """
        self.n = n
        self.to_lowercase = to_lowercase
        self.valid_charset = valid_charset

    def fit(self, X: np.array, y: np.array = None) -> NGrams:
        """See the Preprocessor.fit() method.

        # noqa
        """
        return self

    # pylint: disable=unused-argument
    def _transform_each(self,
                        X: np.array,
                        y: np.array = None) -> typing.List[int]:
        clean_list = []
        valid_charset_alphabet = "".join(self.valid_charset.value)
        for element in X:
            if self.to_lowercase:
                element = element.lower()
            new_element = ""
            for char in element:
                if char in valid_charset_alphabet:
                    new_element += char
            clean_list.append(new_element)

        # Create and populate a dictionary
        combinations = itertools.product(self.valid_charset.value,
                                         repeat=self.n)
        ngrams = {}
        for combination in combinations:
            combination_key = "".join(combination)
            ngrams[combination_key] = 0
        for element in clean_list:
            for i in range(len(element) - self.n + 1):
                ngrams[element[i:i + self.n]] += 1

        return list(ngrams.values())

    def transform(self,
                  X: np.array,
                  y: np.array = None) -> typing.List[typing.List[int]]:
        """See the Preprocessor.transform() method.

        # noqa
        """
        return [self._transform_each(x, y) for x in X]


class GroupCounter(Preprocessor):
    """Group counter preprocessor.

    It computes the categories-based frequency.
    """

    categories: dict
    verbose: bool
    min_ignored_percent: float
    allow_multiple_categories: bool

    def __init__(self,
                 categories: dict,
                 allow_multiple_categories: bool,
                 verbose: bool = False,
                 min_ignored_percent: float = 0) -> None:
        """Initializes the GroupCounter instance.

        Args:
            categories (dict): Categories in which the data is grouped
            allow_multiple_categories (bool): Boolean indicating if an entry can
                be grouped under multiple categories
            verbose (bool): Boolean indicating if the outliers entries are
                logged
            min_ignored_percent (float): Percentage of occurrences above which a
                skipped entry is considered an outlier
        """
        self.categories = categories
        self.verbose = verbose
        self.min_ignored_percent = min_ignored_percent
        self.allow_multiple_categories = allow_multiple_categories

    @staticmethod
    def _check_match_with_wildcards(pattern: str, raw_string: str) -> bool:
        pattern = pattern.replace("*", r"(\w)*")

        return re.match(pattern, raw_string.lower()) is not None

    def _log_outliers(self, elements: typing.List[str],
                      counter: collections.Counter):
        printed_caption = False
        for key in counter.keys():
            percent = counter[key] / len(elements)
            if percent > self.min_ignored_percent:
                if not printed_caption:
                    Logger().log(
                        "Outliers (that are not in any category) are:",
                        LoggedMessageTypes.INFORMATION)
                    printed_caption = True

                Logger().log(
                    "\t- {} with {} occurrences ({:.3f}% from total)".format(
                        key, counter[key], 100 * percent))

    def fit(self, X: np.array, y: np.array = None) -> GroupCounter:
        """See the Preprocessor.fit() method.

        # noqa
        """
        return self

    # pylint: disable=unused-argument
    def _transform_each(self,
                        X: np.array,
                        y: np.array = None) -> typing.List[int]:
        counter = collections.Counter(X)

        frequency_dict = {}
        valid_elements = 0
        for category in self.categories:
            group_count = 0
            for label in self.categories[category]:
                if "*" in label:
                    # If the label has wild chars, then search all elements that
                    # match the given pattern and add their occurrences
                    matched_elements = [
                        element for element in counter.keys()
                        if self._check_match_with_wildcards(label, element)
                    ]

                    for matched_element in matched_elements:
                        group_count += counter[matched_element]
                        valid_elements += 1
                        del counter[matched_element]
                elif label in counter:
                    group_count += counter[label]
                    valid_elements += 1
                    del counter[label]

            frequency_dict[category] = group_count

        if self.verbose:
            self._log_outliers(X, counter)

        return list(frequency_dict.values())

    def transform(self, X: np.array, y: np.array = None) -> typing.List[int]:
        """See the Preprocessor.transform() method.

        # noqa
        """
        return [self._transform_each(x, y) for x in X]


class SameLengthImputer(Preprocessor):
    """Same-length imputer.

    It imputes the rows of the input to have the same length.
    """

    desired_length: int

    def __init__(self, desired_length: int = 0) -> None:
        """Initialized the SameLengthImputer instance.

        Args:
            desired_length (int): Length of the imputed samples. Defaults to 0,
                in case of the desire to reach the maximum length of the
                samples.
        """
        self.desired_length = desired_length

    def fit(self, X: np.array, y: np.array = None) -> SameLengthImputer:
        """See the Preprocessor.fit() method.

        # noqa
        """
        return self

    # pylint: disable=unused-argument
    def _transform_each(self,
                        X: np.array,
                        y: np.array = None,
                        actual_desired_length: int = 0) -> typing.List[int]:
        # Verify what element needs to be used on padding
        first_element = X[0]
        if isinstance(first_element, (int, float)):
            value = 0
        elif isinstance(first_element, str):
            value = ""

        # Pad until the desired length is reached
        to_add = actual_desired_length - len(X)
        X.extend(to_add * [value])

        return X

    def transform(self,
                  X: np.array,
                  y: np.array = None) -> typing.List[typing.List[typing.Any]]:
        """See the Preprocessor.transform() method.

        # noqa
        """
        # Get the desired length (maximum line length or the set one)
        if self.desired_length == 0:
            actual_desired_length = max([len(line) for line in X])
        else:
            actual_desired_length = self.desired_length

        return [self._transform_each(x, y, actual_desired_length) for x in X]

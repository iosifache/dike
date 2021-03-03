"""Program testing the preprocessors"""
from modules.preprocessing.preprocessors import (Counter, CountVectorizer,
                                                 GroupCounter, Identity,
                                                 NGrams, SameLengthImputer)


def test_identity():
    """Tests the Identity preprocessor."""
    numeric_data = [[0, 1, 2], [0, 1], [0, 1, 2, 3]]

    preprocessor = Identity()
    preprocessed_data = preprocessor.fit_transform(numeric_data)
    assert preprocessed_data == numeric_data, "The data preprocessed by the Identity preprocessor are malformated."


def test_counter():
    """Tests the Counter preprocessor."""
    numeric_data = [[0, 1, 2], [0, 1], [0, 1, 2, 3]]
    expected_data = [3, 2, 4]

    preprocessor = Counter()
    preprocessed_data = preprocessor.fit_transform(numeric_data)
    assert preprocessed_data == expected_data, "The data preprocessed by the Counter preprocessor are malformated."


def test_count_vectorizer():
    """Tests the CountVectorizer preprocessor."""
    text_data = [["word", "pass"], ["pass", "pass", "ok"], ["ok"]]
    expected_data = [[0, 1, 1], [1, 2, 0], [1, 0, 0]]

    preprocessor = CountVectorizer()
    preprocessed_data = preprocessor.fit_transform(text_data)
    preprocessed_data = preprocessed_data.toarray().tolist()
    assert preprocessed_data == expected_data, "The data preprocessed by the CountVectorizer preprocessor are malformated."


def test_ngrams():
    """Tests the NGrams preprocessor."""
    text_data = [["word", "pass"], ["pass", "pass", "ok"], ["ok"]]
    expected_data = [[
        1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 2, 0, 0, 0, 1, 0,
        0, 0
    ],
                     [
                         2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 2, 0, 0,
                         4, 0, 0, 0, 0, 0, 0, 0
                     ],
                     [
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0
                     ]]

    preprocessor = NGrams(1, True, NGrams.Charset.LOWERCASE)
    preprocessed_data = preprocessor.fit_transform(text_data)
    assert preprocessed_data == expected_data, "The data preprocessed by the NGrams preprocessor are malformated."


def test_group_counter():
    """Tests the GroupCounter preprocessor."""
    categorical_data = [["a", "b", "a", "c", "d", "d"], ["a"],
                        ["c", "d", "f", "f"]]
    categories = {"first": ["a", "b", "c"], "second": ["d", "e", "f"]}
    expected_data = [[4, 2], [1, 0], [1, 3]]

    preprocessor = GroupCounter(categories, False)
    preprocessed_data = preprocessor.fit_transform(categorical_data)
    assert preprocessed_data == expected_data, "The data preprocessed by the GroupCounter preprocessor are malformated."


def test_same_length_imputer():
    """Tests the SameLengthImputer preprocessor."""
    first_data = [[0, 1, 2], [0, 1], [0, 1, 2, 3]]
    expected_first_data = [[0, 1, 2, 0], [0, 1, 0, 0], [0, 1, 2, 3]]
    second_data = [["word", "pass"], ["pass", "pass", "ok"], ["ok"]]
    expected_second_data = [["word", "pass", "", ""],
                            ["pass", "pass", "ok", ""], ["ok", "", "", ""]]

    preprocessor = SameLengthImputer()
    preprocessed_data = preprocessor.fit_transform(first_data)

    assert preprocessed_data == expected_first_data

    preprocessor = SameLengthImputer(4)
    preprocessed_data = preprocessor.fit_transform(second_data)
    assert preprocessed_data == expected_second_data, "The data preprocessed by the SameLengthImputer preprocessor are malformated."

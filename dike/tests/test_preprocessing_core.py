"""Program testing preprocessing of features via the specific core"""
import pandas
from modules.preprocessing.core import PreprocessingCore
from modules.preprocessing.types import PreprocessorsTypes


def test_preprocess():
    """Tests the preprocessing of features with a pipeline composed of multiple
    preprocessors."""
    data = pandas.DataFrame([[[0, 1, 2], [0, 1, 2], [-1, 1, 0, -4]],
                             [[1, 1, 0], [0, 1], [1, 1, 1, 1]],
                             [[0, 1, 3], [0, 1, 2, 3], [-2, -1, 2, 1]]])

    core = PreprocessingCore()

    core.attach(PreprocessorsTypes.IDENTITY)
    core.attach(PreprocessorsTypes.COUNTER)
    core.attach(PreprocessorsTypes.K_BINS_DISCRETIZER)

    preprocessed_data = core.preprocess(data.values)
    assert preprocessed_data is not None, "The data preprocessed by the core are None."

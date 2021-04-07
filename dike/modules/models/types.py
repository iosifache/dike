"""Types used in this module."""
from enum import Enum


class ModelObjective(Enum):
    """Enumeration for all objectives of a model."""

    MALICE = 0
    CLASSIFICATION = 1


class ReductionAlgorithm(Enum):
    """Enumeration for all dimensionality reduction algorithms."""

    PCA = "PCA"
    FAST_ICA = "FastICA"
    NMF = "NMF"


class RegressionAlgorithms(Enum):
    """Enumeration for all regression-based machine learning algorithms."""

    LOGISTIC = "LogisticRegression"
    DECISION_TREE = "DecisionTreeRegressor"
    LINEAR_SUPPORT_VECTOR_MACHINE = "LinearSVC"
    RANDOM_FOREST = "RandomForestRegressor"

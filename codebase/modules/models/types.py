"""Types used in this module."""
from enum import Enum


class ModelObjective(Enum):
    """Enumeration for all objectives of a model."""

    MALICE = 0
    CLASSIFICATION = 1


class RegressionAlgorithms(Enum):
    """Enumeration for all regression-based machine learning algorithms."""

    DECISION_TREE = "DecisionTreeRegressor"
    LINEAR_SUPPORT_VECTOR_MACHINE = "LinearSVC"
    RANDOM_FOREST = "RandomForestRegressor"

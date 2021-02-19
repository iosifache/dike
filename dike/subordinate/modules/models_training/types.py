from enum import Enum


class ModelObjective(Enum):
    """Enumeration for all possible objectives for a model, where similarity is
    already included in all of them"""
    MALICE = 0
    CLASSIFICATION = 1


class ReductionAlgorithm(Enum):
    """Enumeration for all possible dimensionality reduction algorithms used for
    training a model"""
    PCA = "PCA"
    FAST_ICA = "FastICA"
    NMF = "NMF"


class RegressionAlgorithms(Enum):
    """Enumeration for all possible regression-based machine learning algorithms
    used for training a model"""
    LOGISTIC = "LogisticRegression"
    DECISION_TREE = "DecisionTreeRegressor"
    LINEAR_SUPPORT_VECTOR_MACHINE = "LinearSVC"
    RANDOM_FOREST = "RandomForestRegressor"

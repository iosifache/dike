import math
import typing

import numpy as np
from configuration.dike import DikeConfig
from sklearn.metrics import (accuracy_score, confusion_matrix,
                             matthews_corrcoef, max_error, mean_absolute_error,
                             mean_squared_error, precision_score, r2_score,
                             recall_score)


class ModelsEvaluator:
    """Class evaluating prediction results
    """
    @staticmethod
    def evaluate_regression(y_real: np.array, y_pred: np.array) -> dict:
        """Evaluates the predicted values of a regression model against the real
        values.

        The returned metrics, as keys into the returned dictionary, are:
        - maximum error ("max_error" key);
        - mean average error ("mean_average_error" key);
        - root mean squared error ("root_mean_squared_error" key); and
        - R squared score ("r2_score" key).

        Args:
            y_real (np.array): Real values
            y_pred (np.array): Predicted values

        Returns:
            dict: Dictionary containing all computed scores
        """
        results = dict()

        results["max_error"] = max_error(y_real, y_pred)
        results["mean_average_error"] = mean_absolute_error(y_real, y_pred)
        results["root_mean_squared_error"] = math.sqrt(
            mean_squared_error(y_real, y_pred))
        results["r2_score"] = r2_score(y_real, y_pred)

        return results

    @staticmethod
    def evaluate_soft_multilabel_classification(
            y_real: np.matrix, y_pred: np.matrix,
            label_names: typing.List[str]) -> dict:
        """Evaluates the predicted values of a soft multilabel classification
        model against the real values.

        The soft labels are binaries repeatedly, with different thresholds.
        Their number is stored into the "sampling_steps" key from the root
        object.

        Into the "labels" key, there is an entry for each returned label. The
        label name is stored into the key "label_name". Next to this key, there
        are the following metrics:
        - a regression-wise evaluation, following the format of the
        evaluate_regression() method return value;
        - a classification-wise evaluation, under the key
        "classification_metrics", containing (for each threshold):
            - the confusion matrix;
            - the accuracy;
            - the precision;
            - the recall; and
            - the Matthews correlation coefficient.

        Args:
            y_real (np.matrix): Real values
            y_pred (np.matrix): Predicted values
            label_names (typing.List[str]): List of labels names, that are
                                              included into the returned
                                              dictionary

        Returns:
            dict: Dictionary containing all computed scores
        """
        samples_count = len(y_real)
        labels_count = len(y_real[0])

        result = {
            "sampling_steps": DikeConfig.SAMPLING_STEPS_FOR_PLOTS,
            "labels": []
        }

        # Get metrics for each label at a time
        for label_id in range(labels_count):

            labels_confusion_matrixes = []
            label_accuracies = []
            label_precisions = []
            label_recall = []
            label_matthews_coefficients = []

            # Get the corresponding test and predicted labels
            y_label_test = [sample[label_id] for sample in y_real]
            y_label_pred = [sample[label_id] for sample in y_pred]

            for threashold in np.arange(
                    0, 1, 1 / DikeConfig.SAMPLING_STEPS_FOR_PLOTS):
                # Binarize the values considering the current threshold
                binarized_y_label_test = samples_count * [0]
                binarized_y_label_pred = samples_count * [0]
                for i in range(samples_count):
                    binarized_y_label_test[i] = int(
                        y_label_test[i] >= threashold)
                    binarized_y_label_pred[i] = int(
                        y_label_pred[i] >= threashold)

                # Get numeric metrics
                labels_confusion_matrixes.append(
                    confusion_matrix(binarized_y_label_test,
                                     binarized_y_label_pred).tolist())
                label_accuracies.append(
                    accuracy_score(binarized_y_label_test,
                                   binarized_y_label_pred))
                label_precisions.append(
                    precision_score(binarized_y_label_test,
                                    binarized_y_label_pred))
                label_recall.append(
                    recall_score(binarized_y_label_test,
                                 binarized_y_label_pred))
                label_matthews_coefficients.append(
                    matthews_corrcoef(binarized_y_label_test,
                                      binarized_y_label_pred))

            # Append lists
            result["labels"].append({
                "label_name":
                label_names[label_id],
                "regression_metrics":
                ModelsEvaluator.evaluate_regression(y_label_test,
                                                    y_label_pred),
                "classification_metrics": {
                    "confusion_matrixes": labels_confusion_matrixes,
                    "accuracies": label_accuracies,
                    "precisions": label_precisions,
                    "recalls": label_recall,
                    "matthews_coefficients": label_matthews_coefficients
                }
            })

        return result

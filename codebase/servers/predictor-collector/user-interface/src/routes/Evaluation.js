import React from 'react';
import {Helmet} from 'react-helmet';
import PropTypes from 'prop-types';
import APIWorker from '../utils/api_worker';
import {isModelNameValid} from '../utils/common';

import {
  Badge,
  Col,
  Container,
  Form,
  Image,
  Row,
  Table,
  ToggleButton,
  ToggleButtonGroup,
} from 'react-bootstrap';
import {
  VictoryAxis,
  VictoryChart,
  VictoryHistogram,
  VictoryPie,
  VictoryTheme,
} from 'victory';
import RangeSlider from 'react-bootstrap-range-slider';
import {Link, Redirect} from 'react-router-dom';
import {IoChevronBack} from 'react-icons/io5';

import 'react-bootstrap-range-slider/dist/react-bootstrap-range-slider.css';
import '../stylesheets/Evaluation.css';

import CONFIGURATION from '../configuration/platform';

const ROUTES_CONFIGURATION = CONFIGURATION.routes;
const DECIMALS_ACCURACY = CONFIGURATION.decimalsAccuracy;

/**
 * Component for evaluation page
 *
 * @class Evaluation
 * @extends {React.Component}
 */
class Evaluation extends React.Component {
  defaultState = {
    modelName: '',
    evaluation: null,
    labelsNames: [],
    selectedLabel: 0,
    threshold: 50,
  };

  /**
   * Creates an instance of Evaluation.
   *
   * @param {*} props Props
   * @memberof Evaluation
   */
  constructor(props) {
    super(props);
    this.state = JSON.parse(JSON.stringify(this.defaultState));

    this.updateEvaluation = this.updateEvaluation.bind(this);
    this.handleThresholdChange = this.handleThresholdChange.bind(this);
    this.preprocessHistogramData = this.preprocessHistogramData.bind(this);
    this.evaluateRegression = this.evaluateRegression.bind(this);
    this.generateLabelsBar = this.generateLabelsBar.bind(this);
    this.selectLabel = this.selectLabel.bind(this);
    this.evaluateLabelRegression = this.evaluateLabelRegression.bind(this);
    this.evaluateLabelClassification = this.evaluateLabelClassification.bind(
      this,
    );

    /* eslint-disable camelcase */
    const {model_name} = this.props.match.params;
    this.state.modelName = model_name;
    if (isModelNameValid(model_name))
      APIWorker.getModelEvaluation(model_name, this.updateEvaluation);
    /* eslint-enable camelcase */
  }

  /**
   * Handles the receiving of the evaluation data.
   *
   * @param {Object} evaluation Evaluation
   * @memberof Evaluation
   */
  updateEvaluation(evaluation) {
    let labelsNames = [];

    if (!('max_error' in evaluation)) {
      labelsNames = evaluation.labels.map((value, index) => {
        return value.label_name;
      });
    }

    this.setState({
      evaluation: evaluation,
      labelsNames: labelsNames,
    });
  }

  /**
   * Handles the change of the membership threshold.
   *
   * @param {Event} event Membership threshold change event
   * @memberof Evaluation
   */
  handleThresholdChange(event) {
    this.setState({
      threshold: event.target.value,
    });
  }

  /**
   * Preprocess the data before plotting them in a histogram.
   *
   * @param {*} data Data being plotted
   * @return {Array} Array of dictionaries containing the plotted data
   * @memberof Evaluation
   */
  preprocessHistogramData(data) {
    return data.values.map((count) => {
      return {
        x: count,
      };
    });
  }

  /**
   * Generates the components required for evaluating a regression model.
   *
   * @param {*} data Regression evaluation data
   * @return {*} Components
   * @memberof Evaluation
   */
  evaluateRegression(data) {
    /* eslint-disable camelcase */
    const {
      max_error,
      mean_average_error,
      root_mean_squared_error,
      r2_score,
      errors_histogram,
    } = data;
    /* eslint-enable camelcase */

    return (
      <Row>
        <Col>
          <h3>
            Error Metrics
            <Badge pill variant="dark">
              regression-wise
            </Badge>
          </h3>
          <Table borderless size="sm">
            <thead>
              <tr>
                <th>Metric</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Maximum Error</td>
                <td>{max_error.toFixed(DECIMALS_ACCURACY)}</td>
              </tr>
              <tr>
                <td>Mean Average Error</td>
                <td>{mean_average_error.toFixed(DECIMALS_ACCURACY)}</td>
              </tr>
              <tr>
                <td>Root Mean Squared Error</td>
                <td>{root_mean_squared_error.toFixed(DECIMALS_ACCURACY)}</td>
              </tr>
              <tr>
                <td>
                  R<sup>2</sup> Score
                </td>
                <td>{r2_score.toFixed(DECIMALS_ACCURACY)}</td>
              </tr>
            </tbody>
          </Table>
        </Col>

        <Col>
          <h3>
            Error Histogram
            <Badge pill variant="dark">
              regression-wise
            </Badge>
          </h3>
          <VictoryChart
            theme={VictoryTheme.grayscale}
            domainPadding={10}
            padding={{
              top: 5,
              bottom: 100,
              right: 20,
              left: 50,
            }}
          >
            <VictoryAxis
              label="Relative Error"
              fixLabelOverlap
              tickFormat={(t) => `${t}%`}
              tickCount={10}
              style={{
                axisLabel: {
                  padding: 30,
                  fontSize: 14,
                  fontWeight: 300,
                },
                tickLabels: {
                  padding: 5,
                  fontSize: 10,
                  fontWeight: 300,
                },
              }}
            />
            <VictoryAxis
              label="Count"
              fixLabelOverlap
              tickCount={10}
              dependentAxis
              style={{
                axisLabel: {
                  padding: 30,
                  fontSize: 14,
                  fontWeight: 300,
                },
                tickLabels: {
                  padding: 5,
                  fontSize: 10,
                  fontWeight: 300,
                },
              }}
            />
            <VictoryHistogram
              data={this.preprocessHistogramData(errors_histogram)}
              bins={100}
              domain={{x: [0, 100]}}
            />
          </VictoryChart>
        </Col>
      </Row>
    );
  }

  /**
   * Generates the components required for evaluating (regression-wise) a soft
   * multi-label classification model
   *
   * @return {*} Components
   * @memberof Evaluation
   */
  evaluateLabelRegression() {
    const {evaluation, selectedLabel} = this.state;
    const regressionData = evaluation.labels[selectedLabel].regression_metrics;

    return this.evaluateRegression(regressionData);
  }

  /**
   * Generates the components required for evaluating (classification-wise) a
   * soft multi-label classification model
   *
   * @return {*} Components
   * @memberof Evaluation
   */
  evaluateLabelClassification() {
    const {threshold, evaluation, selectedLabel} = this.state;
    const index = (threshold / 100) * 10;

    const classificationData =
      evaluation.labels[selectedLabel].classification_metrics;
    const confusionMatrix = classificationData.confusion_matrixes[index];
    const accuracy = classificationData.accuracies[index];
    const precision = classificationData.precisions[index];
    const recall = classificationData.recalls[index];
    const matthewsCoefficient = classificationData.matthews_coefficients[index];

    const pieData = [];
    if (confusionMatrix.length === 1) {
      confusionMatrix[0].push(0);
      confusionMatrix.push([0, 0]);
    }
    for (let i = 0; i < confusionMatrix.length; i++) {
      const line = confusionMatrix[i];

      for (let j = 0; j < line.length; j++) {
        const value = line[j];

        if (value) {
          let label;
          if (i === 0 && j === 0) label = 'True Positive';
          else if (i === 0 && j === 1) label = 'False Positive';
          else if (i === 1 && j === 0) label = 'False Negative';
          else label = 'True Negative';
          label = value + ' ' + label;
          if (value !== 0) {
            label += 's';
          }

          pieData.push({
            x: label,
            y: value,
          });
        }
      }
    }

    return (
      <Row>
        <Col>
          <h3>
            Error Metrics
            <Badge pill variant="dark">
              classification-wise
            </Badge>
          </h3>
          <Table borderless size="sm">
            <thead>
              <tr>
                <th>Metric</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Accuracy</td>
                <td>{accuracy.toFixed(DECIMALS_ACCURACY)}</td>
              </tr>
              <tr>
                <td>Precision</td>
                <td>{precision.toFixed(DECIMALS_ACCURACY)}</td>
              </tr>
              <tr>
                <td>Recall</td>
                <td>{recall.toFixed(DECIMALS_ACCURACY)}</td>
              </tr>
              <tr>
                <td>Matthews Coefficient</td>
                <td>{matthewsCoefficient.toFixed(DECIMALS_ACCURACY)}</td>
              </tr>
            </tbody>
          </Table>
        </Col>

        <Col>
          <h3>
            Confusion Chart
            <Badge pill variant="dark">
              classification-wise
            </Badge>
          </h3>
          <VictoryPie
            data={pieData}
            theme={VictoryTheme.grayscale}
            labelPlacement="parallel"
            radius={70}
            style={{
              labels: {
                fontSize: 10,
                fontWeight: 300,
              },
            }}
          />
        </Col>
      </Row>
    );
  }

  /**
   * Handles the change of the label for relativization.
   *
   * @param {*} event Label change event
   * @memberof Evaluation
   */
  selectLabel(event) {
    if (event.target.value) {
      this.setState({
        selectedLabel: event.target.value,
      });
    }
  }

  /**
   * Generates the toggle buttons representing the labels included in the
   * evaluation.
   *
   * @return {*} Components
   * @memberof Evaluation
   */
  generateLabelsBar() {
    const {labelsNames, selectedLabel} = this.state;
    const labels = labelsNames.map((value, index) => {
      return (
        <ToggleButton
          value={index}
          key={index}
          size="sm"
          variant="dark"
          onClick={this.selectLabel}
        >
          {value.charAt(0).toUpperCase() + value.slice(1)}
        </ToggleButton>
      );
    });

    return (
      <ToggleButtonGroup
        type="radio"
        name="options"
        defaultValue={selectedLabel}
        className="labels-chooser"
      >
        {labels}
      </ToggleButtonGroup>
    );
  }

  /**
   * Renders the component.
   *
   * @return {*} Rendered component
   * @memberof Evaluation
   */
  render() {
    const {modelName, evaluation, threshold} = this.state;

    if (!evaluation) {
      return '';
    }

    const isRegression = 'max_error' in evaluation;
    const step = 100 / evaluation.sampling_steps;

    if (!isModelNameValid(modelName))
      return <Redirect to={ROUTES_CONFIGURATION.settings.name} />;

    return (
      <Container className="Evaluation">
        <Helmet>
          <title>dike: Model Evaluation</title>
        </Helmet>

        <Row className="menu">
          <Col>
            <Link to={ROUTES_CONFIGURATION.default.name}>
              <Image
                src={process.env.PUBLIC_URL + '/images/logo.png'}
                className="logo"
              />
            </Link>
          </Col>
          <Col>
            <Link to={ROUTES_CONFIGURATION.settings.name}>
              <IoChevronBack className="action-button" />
            </Link>
          </Col>
        </Row>

        <h1>Model Details</h1>
        {isRegression ? (
          <div>
            <p>
              The model named <b>{modelName}</b> is a regression one. It can be
              used to predict the malice of a file and to detect the samples
              from the dataset that are the most similar to the submitted one.
            </p>
            <h1>Evaluation</h1>
            {this.evaluateRegression(evaluation)}
          </div>
        ) : (
          <div>
            <p>
              The model named <b>{modelName}</b> is a soft multi-label
              classification one. It can be used to predict the membership of a
              file to various malware families and to detect the samples from
              the dataset that are the most similar to the submitted one.
            </p>

            <h1>Configuration</h1>
            <Row>
              <Col xs={8}>
                <Form.Group>
                  <Form.Label>Label Relativization</Form.Label>
                  {this.generateLabelsBar()}
                  <Form.Text className="text-muted">
                    Considering the multi-label aspect of the model type, the
                    evaluation must be relativized to a specific malware family.
                  </Form.Text>
                </Form.Group>
              </Col>
              <Col>
                <Form.Group>
                  <Form.Label>Threshold Relativization</Form.Label>
                  <RangeSlider
                    tooltipPlacement="top"
                    variant="dark"
                    value={threshold}
                    step={step}
                    onChange={this.handleThresholdChange}
                  />
                  <Form.Text className="text-muted">
                    Considering the soft aspect of the model type, a threshold
                    is needed to binarize the prediction for a specific
                    category. If the membership is above the threshold, the
                    given file is considered to belong to that specific family.
                  </Form.Text>
                </Form.Group>
              </Col>
            </Row>
            <h1>Evaluation</h1>
            {this.evaluateLabelRegression()}
            {this.evaluateLabelClassification()}
          </div>
        )}
      </Container>
    );
  }

  static propTypes = {
    match: PropTypes.shape({
      params: PropTypes.shape({
        model_name: PropTypes.string.isRequired,
      }),
    }),
  };
}

export default Evaluation;

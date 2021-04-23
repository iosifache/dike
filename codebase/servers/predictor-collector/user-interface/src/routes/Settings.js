import React from 'react';
import {Cookies, withCookies} from 'react-cookie';
import {Helmet} from 'react-helmet';
import {instanceOf} from 'prop-types';
import APIWorker from '../utils/api_worker';
import {isModelNameValid} from '../utils/common';

import {
  Button,
  Container,
  Col,
  Form,
  Image,
  InputGroup,
  Row,
  ToggleButton,
  ToggleButtonGroup,
} from 'react-bootstrap';
import {Link} from 'react-router-dom';
import {AiFillCheckCircle} from 'react-icons/ai';
import {FaSave} from 'react-icons/fa';
import {GoGraph} from 'react-icons/go';
import {IoChevronBack} from 'react-icons/io5';

import '../stylesheets/Settings.css';

import CONFIGURATION from '../configuration/platform';

const ROUTES_CONFIGURATION = CONFIGURATION.routes;

/**
 * Component for settings page
 *
 * @class Settings
 * @extends {React.Component}
 */
class Settings extends React.Component {
  defaultState = {
    modelName: '',
    checkingInterval: 0,
    isAnalystModeEnabled: 0,
    similarSamplesCount: 0,
    predictionConfiguration: {},
    invalidField: -1,
    isSaved: 0,
  };

  /**
   * Creates an instance of Settings.
   *
   * @param {*} props Props
   * @memberof Settings
   */
  constructor(props) {
    super(props);

    this.state = JSON.parse(JSON.stringify(this.defaultState));

    this.handleNameChange = this.handleNameChange.bind(this);
    this.handleIntervalChange = this.handleIntervalChange.bind(this);
    this.handleAnalystModeChange = this.handleAnalystModeChange.bind(this);
    this.handleSimilarsCountChange = this.handleSimilarsCountChange.bind(this);
    this.updateModelConfigurationField = this.updateModelConfigurationField.bind(
      this,
    );
    this.save = this.save.bind(this);

    const {cookies} = this.props;
    const scanConfiguration = cookies.get('configuration');
    if (scanConfiguration) {
      const {
        modelName,
        checkingInterval,
        isAnalystModeEnabled,
        similarSamplesCount,
      } = scanConfiguration;

      this.state.modelName = modelName;
      this.state.checkingInterval = checkingInterval;
      this.state.isAnalystModeEnabled = isAnalystModeEnabled;
      this.state.similarSamplesCount = similarSamplesCount;

      APIWorker.getModelConfiguration(
        modelName,
        this.updateModelConfigurationField,
      );
    }
  }

  /**
   * Handles the change of the model name
   *
   * @param {Event} event Name change event
   * @memberof Settings
   */
  handleNameChange(event) {
    const modelName = event.target.value;

    if (isModelNameValid(modelName)) {
      APIWorker.getModelConfiguration(
        modelName,
        this.updateModelConfigurationField,
      );
    }

    this.setState({
      modelName: modelName,
      isSaved: 0,
    });
  }

  /**
   * Updates the model configuration field after the receipt.
   *
   * @param {Object} configuration Model configuration
   * @memberof Settings
   */
  updateModelConfigurationField(configuration) {
    this.setState({
      predictionConfiguration: configuration,
    });
  }

  /**
   * Handles the change of the checking interval
   *
   * @param {Event} event Interval change event
   * @memberof Settings
   */
  handleIntervalChange(event) {
    this.setState({
      checkingInterval: Number(event.target.value),
      isSaved: 0,
    });
  }

  /**
   * Handles the change of the analyst mode enabling.
   *
   * @param {Event} event Analyst mode enabling event
   * @memberof Settings
   */
  handleAnalystModeChange(event) {
    let similarSamplesCount = this.state.similarSamplesCount;

    if (event === 0) similarSamplesCount = 0;
    this.setState({
      isAnalystModeEnabled: Boolean(event),
      similarSamplesCount: similarSamplesCount,
      isSaved: 0,
    });
  }

  /**
   * Handles the change of the similar samples count.
   *
   * @param {Event} event Similar samples count change event
   * @memberof Settings
   */
  handleSimilarsCountChange(event) {
    this.setState({
      similarSamplesCount: Number(event.target.value),
      isSaved: 0,
    });
  }

  /**
   * Saves the set parameters into the settings.
   *
   * @memberof Settings
   */
  save() {
    let {
      modelName,
      checkingInterval,
      isAnalystModeEnabled,
      similarSamplesCount,
      predictionConfiguration,
      isSaved,
    } = this.state;
    let invalidField = -1;

    if (isAnalystModeEnabled === 1 && similarSamplesCount < 1) invalidField = 3;
    if (checkingInterval < 1) invalidField = 1;
    if (!isModelNameValid(modelName)) invalidField = 0;

    if (invalidField === -1) {
      const {cookies} = this.props;

      isSaved = 1;
      cookies.set('configuration', {
        modelName: modelName,
        checkingInterval: checkingInterval,
        isAnalystModeEnabled: isAnalystModeEnabled,
        similarSamplesCount: similarSamplesCount,
        predictionConfiguration: predictionConfiguration,
      });
    }

    this.setState({
      invalidField: invalidField,
      isSaved: isSaved,
    });
  }

  /**
   * Renders the components
   *
   * @return {*} Rendered component
   * @memberof Settings
   */
  render() {
    const {
      modelName,
      checkingInterval,
      isAnalystModeEnabled,
      similarSamplesCount,
      invalidField,
      isSaved,
    } = this.state;

    return (
      <div className="Settings">
        <Container>
          <Helmet>
            <title>dike: Settings</title>
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
              <Link to={ROUTES_CONFIGURATION.default.name}>
                <IoChevronBack className="action-button" />
              </Link>
            </Col>
          </Row>

          <Form>
            <h1>Settings</h1>
            <p>
              The parameters set above are mandatory for executing a scan. Their
              fields are marked accordingly, with a red border, if they are
              invalid at the time of their saving.
            </p>
            <Form.Group controlId="formBasicEmail">
              <Form.Label>Model Name</Form.Label>
              <InputGroup className="mb-2">
                <Form.Control
                  value={modelName}
                  type="text"
                  size="sm"
                  placeholder="Enter the name of the model"
                  invalid={invalidField === 0 ? 1 : 0}
                  onChange={this.handleNameChange}
                />
                <InputGroup.Append>
                  {isModelNameValid(modelName) && isAnalystModeEnabled ? (
                    <Link target="_blank" to={'/evaluation/' + modelName}>
                      <Button variant="dark" size="sm">
                        <span>
                          Check the model evaluation <GoGraph />
                        </span>
                      </Button>
                    </Link>
                  ) : (
                    <Button size="sm" disabled variant="dark">
                      <span>
                        Check the model evaluation <GoGraph />
                      </span>
                    </Button>
                  )}
                </InputGroup.Append>
              </InputGroup>
              <Form.Text className="text-muted">
                The name is a sequence of 64 hexadecimal characters that
                identifies the model used to make the predictions. After a valid
                name is entered, its evaluation can be checked by clicking the
                right button.
              </Form.Text>
            </Form.Group>
            <Row>
              <Col>
                <Form.Group>
                  <Form.Label>Status Check Interval</Form.Label>
                  <Form.Control
                    value={checkingInterval}
                    type="number"
                    size="sm"
                    placeholder="Enter the status check interval"
                    invalid={invalidField === 1 ? 1 : 0}
                    onChange={this.handleIntervalChange}
                  />
                  <Form.Text className="text-muted">
                    The interval, mentioned in seconds, is the time between two
                    consecutive checks of the status of the active scan.
                  </Form.Text>
                </Form.Group>
              </Col>
              <Col>
                <Form.Group>
                  <Form.Label>Analyst Mode</Form.Label>
                  <ToggleButtonGroup
                    type="radio"
                    size="sm"
                    name="analysis-options"
                    defaultValue={Number(isAnalystModeEnabled)}
                    onChange={this.handleAnalystModeChange}
                  >
                    <ToggleButton value={0} variant="dark">
                      Disabled
                    </ToggleButton>
                    <ToggleButton value={1} variant="dark">
                      Enabled
                    </ToggleButton>
                  </ToggleButtonGroup>
                  <Form.Text className="text-muted">
                    The analyst mode enables some application features, such as
                    the model evaluation and analysis of the similarity. The
                    last one consists of returning, besides the predicted
                    result, the samples in the dataset that are the most similar
                    to the submitted file, considering their extracted features.
                  </Form.Text>
                </Form.Group>
              </Col>
              <Col>
                <Form.Group>
                  <Form.Label>Number of Similar Samples</Form.Label>
                  <Form.Control
                    value={similarSamplesCount}
                    type="number"
                    size="sm"
                    placeholder="Enter the number of similar samples"
                    invalid={invalidField === 3 ? 1 : 0}
                    disabled={!isAnalystModeEnabled}
                    onChange={this.handleSimilarsCountChange}
                  />
                  <Form.Text className="text-muted">
                    If the similarity analysis is enabled (namely the analyst
                    mode), the number indicated how many similar samples to
                    return.
                  </Form.Text>
                </Form.Group>
              </Col>
            </Row>
            <Button
              variant="dark"
              size="sm"
              className="save-button"
              onClick={this.save}
            >
              {!isSaved ? (
                <span>
                  Save <FaSave />
                </span>
              ) : (
                <AiFillCheckCircle />
              )}
            </Button>
          </Form>
        </Container>
      </div>
    );
  }

  static propTypes = {
    cookies: instanceOf(Cookies).isRequired,
  };
}

export default withCookies(Settings);

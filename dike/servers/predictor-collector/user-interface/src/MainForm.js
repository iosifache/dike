import React from 'react';
import {Cookies, withCookies} from 'react-cookie';
import {Helmet} from 'react-helmet';
import {instanceOf} from 'prop-types';
import APIWorker from './utils/api_worker';

import {
  Button,
  Container,
  Col,
  Form,
  Image,
  InputGroup,
  Row,
  Table,
} from 'react-bootstrap';
import Particles from 'react-particles-js';
import {Link} from 'react-router-dom';
import {AiOutlineScan, AiOutlineSetting} from 'react-icons/ai';
import {CgSpinner} from 'react-icons/cg';
import {IoMdRefresh} from 'react-icons/io';
import {MdPublish} from 'react-icons/md';

import './stylesheets/MainForm.css';

import CONFIGURATION from './configuration/platform';

const DECIMALS_ACCURACY = CONFIGURATION.decimalsAccuracy;
const PARTICLES_CONFIGURATION = CONFIGURATION.particles;

const STAGE = {
  DEFAULT: 0,
  WAIT_SCAN_RESULTS: 1,
  SHOW_SCAN_RESULTS: 2,
  AFTER_PUBLISHING_FILE: 3,
};

/**
 * Component for scan page
 *
 * @class MainForm
 * @extends {React.Component}
 */
class MainForm extends React.Component {
  defaultState = {
    scannedFileInputPlaceholder: 'Select the file to scan',
    publishedFileInputPlaceholder: 'Select the file to publish',
    selectedFileToScan: null,
    selectedFileToPublish: null,
    setMalice: 0,
    familiesNames: null,
    setFamiliesMemberships: null,
    invalidField: -1,
    currentStage: STAGE.DEFAULT,
    scanResult: {},
  };

  /**
   * Creates an instance of MainForm.
   *
   * @param {*} props Props
   * @memberof MainForm
   */
  constructor(props) {
    super(props);

    this.state = JSON.parse(JSON.stringify(this.defaultState));

    this.updateMalwareFamilies = this.updateMalwareFamilies.bind(this);
    this.selectLocalFileToScan = this.selectLocalFileToScan.bind(this);
    this.selectLocalFileToPublish = this.selectLocalFileToPublish.bind(this);
    this.handleMaliceChange = this.handleMaliceChange.bind(this);
    this.handleMembershipChange = this.handleMembershipChange.bind(this);
    this.goToNextScanStage = this.goToNextScanStage.bind(this);
    this.showScanResult = this.showScanResult.bind(this);
    this.getPublicationFamiliesTableBody = this.getPublicationFamiliesTableBody.bind(
      this,
    );
    this.goToNextPublicationStage = this.goToNextPublicationStage.bind(this);

    const {cookies} = this.props;
    const malwareFamilies = cookies.get('malwareFamilies');
    if (malwareFamilies) {
      this.defaultState.familiesNames = malwareFamilies;
      this.defaultState.setFamiliesMemberships = Array(
        malwareFamilies.length,
      ).fill(0);

      this.state.familiesNames = malwareFamilies;
      this.state.setFamiliesMemberships = this.defaultState.setFamiliesMemberships;
    } else {
      APIWorker.getMalwareFamilies(this.updateMalwareFamilies);
    }
  }

  /**
   * Updates the malware families after receiving them from the server.
   *
   * @param {Array} families Names of malware families
   * @memberof MainForm
   */
  updateMalwareFamilies(families) {
    this.defaultState.familiesNames = families;
    this.defaultState.setFamiliesMemberships = Array(families.length).fill(0);

    const {cookies} = this.props;
    cookies.set('malwareFamilies', families);

    this.setState({
      familiesNames: families,
      setFamiliesMemberships: this.defaultState.setFamiliesMemberships,
    });
  }

  /**
   * Handles the selection of a local file for scanning.
   *
   * @param {Event} event File selection event
   * @memberof MainForm
   */
  selectLocalFileToScan(event) {
    const file = event.target.files[0];

    this.setState({
      selectedFileToScan: file,
      scannedFileInputPlaceholder: file.name,
    });
  }

  /**
   * Handles the selection of a local file for publication.
   *
   * @param {Event} event File selection event
   * @memberof MainForm
   */
  selectLocalFileToPublish(event) {
    const file = event.target.files[0];

    this.setState({
      selectedFileToPublish: file,
      publishedFileInputPlaceholder: file.name,
    });
  }

  /**
   * Handles the change of the malice.
   *
   * @param {*} event Malice change event
   * @memberof MainForm
   */
  handleMaliceChange(event) {
    this.setState({
      setMalice: event.target.value,
      invalidField: -1,
    });
  }

  /**
   * Handles the change of the membership.
   *
   * @param {*} event Membership change event
   * @memberof MainForm
   */
  handleMembershipChange(event) {
    const {setFamiliesMemberships} = this.state;
    const elementId = event.target.getAttribute('family-key');

    setFamiliesMemberships[elementId] = event.target.value;
    this.setState({
      setFamiliesMemberships: setFamiliesMemberships,
      invalidField: -1,
    });
  }

  /**
   * Handles the click of the button corresponding for going to the next scan
   * stage.
   *
   * @memberof MainForm
   */
  goToNextScanStage() {
    const {currentStage, selectedFileToScan} = this.state;

    if (currentStage === STAGE.DEFAULT) {
      const {cookies} = this.props;
      const scanConfiguration = cookies.get('configuration');
      if (scanConfiguration) {
        const {
          modelName,
          checkingInterval,
          isSimilarityAnalysisEnabled,
          similarSamplesCount,
        } = scanConfiguration;

        APIWorker.scanSample(
          modelName,
          isSimilarityAnalysisEnabled,
          similarSamplesCount,
          selectedFileToScan,
          checkingInterval,
          this.showScanResult,
        );
      }

      this.setState({
        currentStage: STAGE.WAIT_SCAN_RESULTS,
      });
    } else if (currentStage === STAGE.SHOW_SCAN_RESULTS)
      this.setState(this.defaultState);
  }

  /**
   * Handles the click of the button corresponding for going to the next
   * publication stage.
   *
   * @memberof MainForm
   */
  goToNextPublicationStage() {
    const {
      currentStage,
      setMalice,
      setFamiliesMemberships,
      selectedFileToPublish,
    } = this.state;

    if (currentStage === STAGE.DEFAULT) {
      const malice = Number(setMalice);
      if (malice < 0 || malice > 1) {
        this.setState({
          invalidField: 0,
        });
        return;
      }

      let invalidMemberships = false;
      let membershipsSum = 0;
      for (let i = 0; i < setFamiliesMemberships.length; i++) {
        const membership = Number(setFamiliesMemberships[i]);

        if (membership < 0 || membership > 1) {
          invalidMemberships = true;
          break;
        }

        membershipsSum += membership;
      }
      if (membershipsSum != 1 || invalidMemberships) {
        this.setState({
          invalidField: 1,
        });
        return;
      }

      const {cookies} = this.props;
      const scanConfiguration = cookies.get('configuration');
      if (scanConfiguration) {
        const {modelName} = scanConfiguration;

        APIWorker.publishResults(
          modelName,
          selectedFileToPublish,
          setMalice,
          setFamiliesMemberships,
        );

        this.setState({
          currentStage: STAGE.AFTER_PUBLISHING_FILE,
        });
      }
    } else if (currentStage === STAGE.AFTER_PUBLISHING_FILE)
      this.setState(this.defaultState);
  }

  /**
   * Shows the results of a scan.
   *
   * @param {Object} results Results of the scan
   * @memberof MainForm
   */
  showScanResult(results) {
    this.setState({
      scanResult: results,
      currentStage: STAGE.SHOW_SCAN_RESULTS,
    });
  }

  /**
   * Generates the table used to fill the memberships to malware categories in
   * the publication step.
   *
   * @return {*} Components
   * @memberof MainForm
   */
  getPublicationFamiliesTableBody() {
    const {familiesNames, setFamiliesMemberships, invalidField} = this.state;

    return familiesNames.map((value, index) => {
      return (
        <InputGroup key={index} size="sm" className="membership-input">
          <InputGroup.Prepend>
            <InputGroup.Text>{value}</InputGroup.Text>
          </InputGroup.Prepend>
          <Form.Control
            value={setFamiliesMemberships[index]}
            type="text"
            size="sm"
            family-key={index}
            placeholder={'Enter the membership to the ' + value + ' family'}
            invalid={invalidField === 1 ? 1 : 0}
            onChange={this.handleMembershipChange}
          />
        </InputGroup>
      );
    });
  }

  /**
   * Renders the component.
   *
   * @return {*} Rendered component
   * @memberof MainForm
   */
  render() {
    const {
      scannedFileInputPlaceholder,
      publishedFileInputPlaceholder,
      currentStage,
      invalidField,
      scanResult,
      setMalice,
      familiesNames,
    } = this.state;

    if (!familiesNames) return '';

    const {cookies} = this.props;
    const scanConfiguration = cookies.get('configuration');

    let malice;
    let description;
    let membershipsTableBody;
    let similarsTableBody;
    let sampleType;
    if (currentStage === STAGE.SHOW_SCAN_RESULTS) {
      if ('malice' in scanResult) {
        malice = scanResult.malice;

        const printableMalice = (100 * malice).toFixed(DECIMALS_ACCURACY);
        if (
          malice < scanConfiguration.predictionConfiguration.min_malice_suspect
        ) {
          description = (
            <p>
              The file is <b>benign</b>, with predicted{' '}
              <b>malice of {printableMalice}%</b>, and can be used carefree. If
              you notice an anomalous behavior of your device after the usage,
              report the incident to the security teams of the company.
            </p>
          );
        } else if (
          malice <
          scanConfiguration.predictionConfiguration.min_malice_malicious
        ) {
          description = (
            <p>
              The file is <b>suspect</b>, with predicted{' '}
              <b>malice of {printableMalice}%</b>. Run it in a controlled
              environment (for example, a sandbox) for avoiding any risk. As an
              alternative, send it to the security team of the company, letting
              them provide an advanced analysis.
            </p>
          );
        } else {
          description = (
            <p>
              The file is <b>malicious</b>, with predicted{' '}
              <b>malice of {printableMalice}%</b>. Delete it now from your
              computer and report the incident to the security team of the
              company.
            </p>
          );
        }
      } else {
        membershipsTableBody = Object.keys(scanResult.memberships).map(
          (key, index) => {
            let membership = scanResult.memberships[key];
            const className =
              membership >=
              scanConfiguration.predictionConfiguration.min_category_membership
                ? 'active'
                : '';

            membership = (100 * membership).toFixed(DECIMALS_ACCURACY);

            return (
              <tr key={index} className={className}>
                <td>{key}</td>
                <td>{membership}%</td>
              </tr>
            );
          },
        );
      }
      if ('similar' in scanResult) {
        similarsTableBody = scanResult.similar.map((sample, index) => {
          let {hash, similarity} = sample;

          similarity = (100 * similarity).toFixed(DECIMALS_ACCURACY);

          return (
            <tr key={index}>
              <td>{hash}</td>
              <td>{similarity}%</td>
            </tr>
          );
        });
      }
    }

    return (
      <div className="MainForm">
        <Helmet>
          <title>dike: New Operation</title>
        </Helmet>

        {PARTICLES_CONFIGURATION.enable && (
          <Particles
            params={PARTICLES_CONFIGURATION.configuration}
            className={'particles-background ' + sampleType}
          />
        )}

        <Container>
          <Row className="menu">
            <Col>
              <Link to="/">
                <Image
                  src={process.env.PUBLIC_URL + '/images/logo.png'}
                  className="logo"
                />
              </Link>
            </Col>
            <Col>
              <Link to="/settings">
                <AiOutlineSetting
                  className={
                    'action-button' +
                    (!scanConfiguration ? ' no-configuration' : '')
                  }
                />
              </Link>
            </Col>
          </Row>

          <Form className="scan-form">
            <h1>Scan</h1>
            <p>
              Select the file to scan using the predictions of the artificial
              intelligence model specified in the settings. When the prediction
              finishes, the results will be listed above.
            </p>
            <Form.File
              label={scannedFileInputPlaceholder}
              size="sm"
              custom
              disabled={!scanConfiguration}
              className="file"
              onChange={this.selectLocalFileToScan}
            />
            <Button
              className="proceed-button"
              variant="dark"
              size="sm"
              disabled={!scanConfiguration}
              onClick={this.goToNextScanStage}
            >
              {currentStage === STAGE.DEFAULT ? (
                <span>
                  Scan <AiOutlineScan />
                </span>
              ) : currentStage === STAGE.WAIT_SCAN_RESULTS ? (
                <span className="spin">
                  <CgSpinner />
                </span>
              ) : (
                <span>
                  Restart <IoMdRefresh />
                </span>
              )}
            </Button>
          </Form>

          {currentStage === STAGE.SHOW_SCAN_RESULTS && (
            <div className="scan-results">
              {'malice' in scanResult && (
                <div>
                  <h3>Malice</h3>
                  {description}
                </div>
              )}
              {'memberships' in scanResult && (
                <div>
                  <h3>Membership to Malware Families</h3>
                  <p>
                    The predicted memberships to malware families were listed in
                    the table above.
                  </p>
                  <Table borderless size="sm">
                    <thead>
                      <tr>
                        <th>Family</th>
                        <th>Membership</th>
                      </tr>
                    </thead>
                    <tbody>{membershipsTableBody}</tbody>
                  </Table>
                </div>
              )}
              {'similar' in scanResult && (
                <div>
                  <h3>Similarity Analysis Results</h3>
                  <p>
                    Considering the features extracted from the submitted file,
                    the <b>{scanResult.similar.length} most similar samples</b>{' '}
                    from the dataset were listed in the table above.
                  </p>
                  <Table borderless size="sm">
                    <thead>
                      <tr>
                        <th>Hash</th>
                        <th>Similarity</th>
                      </tr>
                    </thead>
                    <tbody>{similarsTableBody}</tbody>
                  </Table>
                </div>
              )}
            </div>
          )}

          <Form className="publication-form">
            <h1>Publication</h1>
            <p>
              After finishing the malware analysis process, select the file and
              fill the accurate results to publish to the artificial
              intelligence model specified in the settings.
            </p>
            <Form.File
              label={publishedFileInputPlaceholder}
              size="sm"
              custom
              disabled={!scanConfiguration}
              className="file"
              onChange={this.selectLocalFileToPublish}
            />
            <Button
              className="proceed-button"
              variant="dark"
              size="sm"
              disabled={!scanConfiguration}
              onClick={this.goToNextPublicationStage}
            >
              {currentStage != STAGE.AFTER_PUBLISHING_FILE ? (
                <span>
                  Publish <MdPublish />
                </span>
              ) : (
                <span>
                  Restart <IoMdRefresh />
                </span>
              )}
            </Button>
            <Row>
              <Col>
                <Form.Group>
                  <Form.Label>Malice</Form.Label>
                  <Form.Control
                    value={setMalice}
                    type="text"
                    size="sm"
                    placeholder="Enter the malice"
                    invalid={invalidField === 0 ? 1 : 0}
                    onChange={this.handleMaliceChange}
                  />
                  <Form.Text className="text-muted">
                    The malice will be used to train the model if it is a
                    regression one.
                  </Form.Text>
                </Form.Group>
              </Col>
              <Col>
                <Form.Group>
                  <Form.Label>Memberships to Malware Families</Form.Label>
                  {this.getPublicationFamiliesTableBody()}
                  <Form.Text className="text-muted">
                    The memberships to malware families will be used to train
                    the model if it is a soft multi-label classification one.
                  </Form.Text>
                </Form.Group>
              </Col>
            </Row>
          </Form>
        </Container>
      </div>
    );
  }

  static propTypes = {
    cookies: instanceOf(Cookies).isRequired,
  };
}

export default withCookies(MainForm);

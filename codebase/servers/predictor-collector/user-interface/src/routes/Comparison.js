import React from 'react';
import {Cookies, withCookies} from 'react-cookie';
import {Helmet} from 'react-helmet';
import PropTypes from 'prop-types';
import {instanceOf} from 'prop-types';
import APIWorker from '../utils/api_worker';
import {isModelNameValid, isFileHashValid} from '../utils/common';

import {Container, Col, Image, Row} from 'react-bootstrap';
import {Link, Redirect} from 'react-router-dom';
import {IoChevronBack} from 'react-icons/io5';

import FeaturesTable from '../components/FeaturesTable';

import CONFIGURATION from '../configuration/platform';

const ROUTES_CONFIGURATION = CONFIGURATION.routes;

/**
 * Component for comparison page
 *
 * @class Comparison
 * @extends {React.Component}
 */
class Comparison extends React.Component {
  defaultState = {
    modelName: '',
    fileHash: '',
    scannedFileFeatures: null,
    selectedFileFeatures: null,
  };

  /**
   * Creates an instance of Comparison.
   *
   * @param {*} props Props
   * @memberof Comparison
   */
  constructor(props) {
    super(props);

    this.state = JSON.parse(JSON.stringify(this.defaultState));
    this.state.scannedFileFeatures = JSON.parse(
      localStorage.getItem('scannedFileFeatures'),
    );

    this.showComparison = this.showComparison.bind(this);

    /* eslint-disable camelcase */
    const {model_name, file_hash} = this.props.match.params;
    this.state.modelName = model_name;
    this.state.fileHash = file_hash;
    if (isModelNameValid(model_name) && isFileHashValid(file_hash))
      APIWorker.getFeatures(model_name, file_hash, this.showComparison);
    /* eslint-enable camelcase */
  }

  /**
   * Handles the receive of the features of the selected file.
   *
   * @param {*} result Features
   * @memberof Comparison
   */
  showComparison(result) {
    this.setState({
      selectedFileFeatures: result.features,
    });
  }

  /**
   * Renders the components.
   *
   * @return {*} Rendered component
   * @memberof Comparison
   */
  render() {
    const {
      modelName,
      fileHash,
      scannedFileFeatures,
      selectedFileFeatures,
    } = this.state;

    if (!isModelNameValid(modelName) && !isFileHashValid(fileHash))
      return <Redirect to={ROUTES_CONFIGURATION.default.name} />;

    if (!selectedFileFeatures) return '';

    return (
      <div className="Comparison">
        <Container>
          <Helmet>
            <title>dike: Comparison</title>
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
          <h1>Features Comparison</h1>
          <p>
            A comparison between the features of the last scanned file and the
            file with the hash of <b>{fileHash}</b>, member of the dataset, is
            shown in the table below.
          </p>
          {selectedFileFeatures && (
            <FeaturesTable
              scannedFileFeatures={scannedFileFeatures}
              selectedFileFeatures={selectedFileFeatures}
            />
          )}
        </Container>
      </div>
    );
  }

  static propTypes = {
    cookies: instanceOf(Cookies).isRequired,
    match: PropTypes.shape({
      params: PropTypes.shape({
        model_name: PropTypes.string.isRequired,
        file_hash: PropTypes.string.isRequired,
      }),
    }),
  };
}

export default withCookies(Comparison);

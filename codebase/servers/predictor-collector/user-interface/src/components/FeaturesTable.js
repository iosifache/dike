import React from 'react';
import PropTypes from 'prop-types';

import {Table} from 'react-bootstrap';

import '../stylesheets/FeaturesTable.css';

/**
 * Component for a table showing a file features or a comparison between
 * features
 *
 * @class FeaturesTable
 * @extends {React.Component}
 */
class FeaturesTable extends React.Component {
  /**
   * Renders the components.
   *
   * @return {*} Rendered component
   * @memberof FeaturesTable
   */
  render() {
    const {scannedFileFeatures} = this.props;
    let isCompare = false;
    let selectedFileFeatures;
    if (this.props.selectedFileFeatures) {
      selectedFileFeatures = this.props.selectedFileFeatures;
      isCompare = true;
    }

    if (!scannedFileFeatures) return '';

    const tableContent = scannedFileFeatures.map(
      (extractorValue, extractorIndex) => {
        const rows = extractorValue.features.map(
          (featureValue, featureIndex) => {
            let comparedFeatures = null;
            const {meaning, preprocessor, features} = featureValue;

            if (isCompare)
              comparedFeatures =
                selectedFileFeatures[extractorIndex].features[featureIndex]
                  .features;

            return (
              <tr key={100 * extractorIndex + featureIndex}>
                {featureIndex == 0 && (
                  <td rowSpan={extractorValue.features.length}>
                    {extractorValue.extractor}
                  </td>
                )}
                <td>{meaning}</td>
                <td>{preprocessor}</td>
                <td className="features-column">
                  <div>[{features.join(', ')}]</div>
                </td>
                {isCompare && (
                  <td className="features-column">
                    <div>[{comparedFeatures.join(', ')}]</div>
                  </td>
                )}
              </tr>
            );
          },
        );
        return rows;
      },
    );

    return (
      <Table size="sm" className="FeaturesTable">
        <thead>
          <tr>
            <th>Extractor Identifier</th>
            <th>Property Description</th>
            <th>Preprocessor Identifier</th>
            <th>{isCompare && 'Scanned '} File Features</th>
            {isCompare && <th>Selected File Features</th>}
          </tr>
        </thead>
        <tbody>{tableContent}</tbody>
      </Table>
    );
  }

  static propTypes = {
    scannedFileFeatures: PropTypes.array.isRequired,
    selectedFileFeatures: PropTypes.array,
  };
}

export default FeaturesTable;

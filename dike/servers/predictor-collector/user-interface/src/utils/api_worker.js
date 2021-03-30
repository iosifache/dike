import axios from 'axios';
import configuration from '../configuration/platform';

const API_CONFIGURATION = configuration.api;

/**
 * Class for working with the API
 *
 * @class APIWorker
 */
class APIWorker {
  /**
   * Gets the used malware families in the platform
   *
   * @param {Function} callback Function to call after the families are received
   * @memberof APIWorker
   */
  static getMalwareFamilies(callback) {
    const url =
      API_CONFIGURATION.baseAddress +
      '/' +
      API_CONFIGURATION.routes.getMalwareFamilies;

    axios
      .get(url, {
        headers: {
          'Access-Control-Allow-Origin': '*',
        },
      })
      .then((response) => {
        if (typeof callback === 'function') {
          const data = response.data;

          if (data) {
            callback(data.families);
          }
        }
      })
      .catch((error) => console.error(error));
  }

  /**
   * Gets the evaluation of a model.
   *
   * @static
   * @param {String} modelName Name of the model
   * @param {Function} callback Function to call after the evaluation is received
   * @memberof APIWorker
   */
  static getModelEvaluation(modelName, callback) {
    const url =
      API_CONFIGURATION.baseAddress +
      '/' +
      API_CONFIGURATION.routes.getEvaluation +
      '/' +
      modelName;

    axios
      .get(url, {
        headers: {
          'Access-Control-Allow-Origin': '*',
        },
      })
      .then((response) => {
        if (typeof callback === 'function') {
          const data = response.data;

          if (data) {
            callback(data);
          }
        }
      })
      .catch((error) => console.error(error));
  }

  /**
   * Gets the prediction configuration of a model.
   *
   * @static
   * @param {String} modelName Name of the model
   * @param {Function} callback Function to call after the configuration is received
   * @memberof APIWorker
   */
  static getModelConfiguration(modelName, callback) {
    const url =
      API_CONFIGURATION.baseAddress +
      '/' +
      API_CONFIGURATION.routes.getConfiguration +
      '/' +
      modelName;

    axios
      .get(url, {
        headers: {
          'Access-Control-Allow-Origin': '*',
        },
      })
      .then((response) => {
        if (typeof callback === 'function') {
          const data = response.data;

          if (data) {
            callback(data);
          }
        }
      })
      .catch((error) => console.error(error));
  }

  /**
   * Scans a file.
   *
   * @static
   * @param {string} modelName Name of the model
   * @param {boolean} similarityAnalysisEnable Boolean indicating if the
   *     similarity analysis is enabled
   * @param {number} similarCount Number of similar samples to return
   * @param {File} file File to scan
   * @param {number} checkingInterval Interval in seconds between two
   *     consecutive checks of the scan
   * @param {Function} callback Function to call after the scan is finished
   * @memberof APIWorker
   */
  static scanSample(
    modelName,
    similarityAnalysisEnable,
    similarCount,
    file,
    checkingInterval,
    callback,
  ) {
    const url =
      API_CONFIGURATION.baseAddress +
      '/' +
      API_CONFIGURATION.routes.createTicket +
      '/' +
      modelName;
    const formData = new FormData();

    formData.append('sample', file);
    formData.append('similarity_analysis', Number(similarityAnalysisEnable));
    if (similarCount) formData.append('similars_count', similarCount);

    axios
      .post(url, formData, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'multipart/form-data',
        },
      })
      .then((response) => {
        if (typeof callback === 'function') {
          const {status, name} = response.data;

          if (status === API_CONFIGURATION.statuses.success) {
            const ticketName = name;
            const checkingIntervalMiliseconds = 1000 * checkingInterval;

            APIWorker.getTicketPeriodically(
              ticketName,
              checkingIntervalMiliseconds,
              callback,
            );
          } else if (status === API_CONFIGURATION.statuses.error) {
            console.error(response.data.message);
          }
        }
      })
      .catch((error) => console.error(error));
  }

  /**
   * Checks if the scan corresponding to a ticket is finished.
   *
   * @static
   * @param {string} ticketName Name of the ticket
   * @param {Number} interval Interval in miliseconds between two consecutive checks
   *     of the scan
   * @param {Function} callback
   * @memberof APIWorker
   */
  static getTicketPeriodically(ticketName, interval, callback) {
    const url =
      API_CONFIGURATION.baseAddress +
      '/' +
      API_CONFIGURATION.routes.getTicket +
      '/' +
      ticketName;

    axios
      .get(url, {
        headers: {
          'Access-Control-Allow-Origin': '*',
        },
      })
      .then((response) => {
        if (typeof callback === 'function') {
          const data = response.data;
          const {status} = data;

          if (status === API_CONFIGURATION.statuses.success) {
            callback(data);
          } else if (status === API_CONFIGURATION.statuses.unfinished) {
            setTimeout(function () {
              APIWorker.getTicketPeriodically(ticketName, interval, callback);
            }, interval);
          } else if (status == API_CONFIGURATION.statuses.error) {
            console.error(data.message);
          }
        }
      })
      .catch((error) => console.error(error));
  }

  /**
   * Publish the accurate results of a malware analysis process.
   *
   * @static
   * @param {string} modelName Name of the model
   * @param {File} file File to publish
   * @param {Number} malice Accurate malice of the file
   * @param {Array} memberships Array containing the accurate memberships for
   *     each malware family
   * @memberof APIWorker
   */
  static publishResults(modelName, file, malice, memberships) {
    const url =
      API_CONFIGURATION.baseAddress +
      '/' +
      API_CONFIGURATION.routes.publish +
      '/' +
      modelName;

    const formData = new FormData();
    formData.append('sample', file);
    formData.append('malice', malice);
    formData.append('memberships', memberships.join(','));

    axios
      .post(url, formData, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'multipart/form-data',
        },
      })
      .then((response) => {
        if (typeof callback === 'function') {
          const {status} = response.data;

          if (status === API_CONFIGURATION.statuses.error) {
            console.error(response.data.message);
          }
        }
      })
      .catch((error) => console.error(error));
  }
}

export default APIWorker;

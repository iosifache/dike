import CONFIGURATION from '../configuration/platform';

/**
 * Verifies if a string is a valid hash (namely a string of N hexadecimal
 * characters, where the length N is given).
 *
 * @param {string} stringToCheck Hash
 * @param {int} length Desired length of the hash
 * @return {boolean} Boolean indicating if the hash is valid
 */
function isHashValid(stringToCheck, length) {
  return !(
    typeof stringToCheck !== 'string' ||
    stringToCheck.length !== length ||
    isNaN(Number('0x' + stringToCheck))
  );
}

/**
 * Verifies if a model name is valid.
 *
 * @export
 * @param {string} modelName Name of the model
 * @return {boolean} Boolean indicating if the model name is valid
 */
export function isModelNameValid(modelName) {
  return isHashValid(modelName, CONFIGURATION.modelNameLength);
}

/**
 * Verifies if a file hash is valid.
 *
 * @export
 * @param {string} fileHash File hash
 * @return {boolean} Boolean indicating if the file hash is valid
 */
export function isFileHashValid(fileHash) {
  return isHashValid(fileHash, CONFIGURATION.fileHashLength);
}

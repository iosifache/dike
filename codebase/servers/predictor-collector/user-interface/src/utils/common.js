/**
 * Verifies if a model name is valid (namely a string of 64 hexadecimal
 * characters).
 *
 * @export
 * @param {string} modelName
 * @return {boolean} Boolean indicating if the model name is valid
 */
export function isModelNameValid(modelName) {
  return !(
    typeof modelName !== 'string' ||
    modelName.length !== 64 ||
    isNaN(Number('0x' + modelName))
  );
}

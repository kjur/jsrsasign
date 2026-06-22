/**
 * Copies a 64-bit word from one Uint32Array into another.
 *
 * @param {Uint32Array} I - The array from which to copy the word.
 * @param {Number} i - The logical index of the 64-bit word.
 *
 * @returns {function} - Returns a function that accepts the target array and index.
 */
const copy = (I, i) => (O, o) => {
  const oi = o * 2;
  const ii = i * 2;

  O[oi] = I[ii];
  O[oi + 1] = I[ii + 1];
};

module.exports = copy;

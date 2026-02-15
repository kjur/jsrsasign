import ROUND_CONSTANTS from './round-constants';

const iota = ({ A, roundIndex }) => {
  const i = roundIndex * 2;
  A[0] ^= ROUND_CONSTANTS[i];
  A[1] ^= ROUND_CONSTANTS[i + 1];
};

export default iota;

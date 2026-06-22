import copy from '../copy';

const chi = ({ A, C }) => {
  for (let y = 0; y < 25; y += 5) {
    for (let x = 0; x < 5; x++) {
      copy(A, y + x)(C, x);
    }

    for (let x = 0; x < 5; x++) {
      const xy = (y + x) * 2;
      const x1 = (x + 1) % 5 * 2;
      const x2 = (x + 2) % 5 * 2;

      A[xy] ^= ~C[x1] & C[x2];
      A[xy + 1] ^= ~C[x1 + 1] & C[x2 + 1];
    }
  }
};

export default chi;

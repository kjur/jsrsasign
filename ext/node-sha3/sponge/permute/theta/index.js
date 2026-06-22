import copy from '../copy';

// eslint-disable-next-line max-statements
const theta = ({ A, C, D, W }) => {
  let H = 0;
  let L = 0;

  for (let x = 0; x < 5; x++) {
    const x20 = x * 2;
    const x21 = (x + 5) * 2;
    const x22 = (x + 10) * 2;
    const x23 = (x + 15) * 2;
    const x24 = (x + 20) * 2;

    C[x20] = A[x20] ^ A[x21] ^ A[x22] ^ A[x23] ^ A[x24];
    C[x20 + 1] = A[x20 + 1] ^ A[x21 + 1] ^ A[x22 + 1] ^ A[x23 + 1] ^ A[x24 + 1];
  }

  for (let x = 0; x < 5; x++) {
    copy(C, (x + 1) % 5)(W, 0);

    H = W[0];
    L = W[1];
    W[0] = H << 1 | L >>> 31;
    W[1] = L << 1 | H >>> 31;

    D[x * 2] = C[(x + 4) % 5 * 2] ^ W[0];
    D[x * 2 + 1] = C[(x + 4) % 5 * 2 + 1] ^ W[1];

    for (let y = 0; y < 25; y += 5) {
      A[(y + x) * 2] ^= D[x * 2];
      A[(y + x) * 2 + 1] ^= D[x * 2 + 1];
    }
  }
};

export default theta;

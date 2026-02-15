import PI_SHUFFLES from './pi-shuffles';
import RHO_OFFSETS from './rho-offsets';
import copy from '../copy';

// eslint-disable-next-line max-statements
const rhoPi = ({ A, C, W }) => {
  copy(A, 1)(W, 0);

  let H = 0;
  let L = 0;
  let Wi = 0;
  let ri = 32;

  for (let i = 0; i < 24; i++) {
    const j = PI_SHUFFLES[i];
    const r = RHO_OFFSETS[i];

    copy(A, j)(C, 0);
    H = W[0];
    L = W[1];
    ri = 32 - r;
    Wi = r < 32 ? 0 : 1;
    W[Wi] = H << r | L >>> ri;
    W[(Wi + 1) % 2] = L << r | H >>> ri;
    copy(W, 0)(A, j);
    copy(C, 0)(W, 0);
  }
};

export default rhoPi;

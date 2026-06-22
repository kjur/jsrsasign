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

const ROUND_CONSTANTS = new Uint32Array([
  0x00000000, 0x00000001,
  0x00000000, 0x00008082,
  0x80000000, 0x0000808a,
  0x80000000, 0x80008000,
  0x00000000, 0x0000808b,
  0x00000000, 0x80000001,
  0x80000000, 0x80008081,
  0x80000000, 0x00008009,
  0x00000000, 0x0000008a,
  0x00000000, 0x00000088,
  0x00000000, 0x80008009,
  0x00000000, 0x8000000a,
  0x00000000, 0x8000808b,
  0x80000000, 0x0000008b,
  0x80000000, 0x00008089,
  0x80000000, 0x00008003,
  0x80000000, 0x00008002,
  0x80000000, 0x00000080,
  0x00000000, 0x0000800a,
  0x80000000, 0x8000000a,
  0x80000000, 0x80008081,
  0x80000000, 0x00008080,
  0x00000000, 0x80000001,
  0x80000000, 0x80008008
]);

const iota = ({ A, roundIndex }) => {
  const i = roundIndex * 2;
  A[0] ^= ROUND_CONSTANTS[i];
  A[1] ^= ROUND_CONSTANTS[i + 1];
};

const PI_SHUFFLES = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
const RHO_OFFSETS = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];

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

const permute = () => {
  // Intermediate variables
  const C = new Uint32Array(10);
  const D = new Uint32Array(10);
  const W = new Uint32Array(2);

  return (A) => {
    for (let roundIndex = 0; roundIndex < 24; roundIndex++) {
      theta({ A, C, D, W });
      rhoPi({ A, C, W });
      chi({ A, C });
      iota({ A, roundIndex });
    }
    C.fill(0);
    D.fill(0);
    W.fill(0);
  };
};

const xorWords = (I, O) => {
  for (let i = 0; i < I.length; i += 8) {
    const o = i / 4;
    O[o] ^= I[i + 7] << 24 | I[i + 6] << 16 | I[i + 5] << 8 | I[i + 4];
    O[o + 1] ^= I[i + 3] << 24 | I[i + 2] << 16 | I[i + 1] << 8 | I[i];
  }
  return O;
};

// eslint-disable-next-line max-statements
const readWords = (I, O, offset, queueSize) => {
  for (let o = 0; o < queueSize; o += 8) {
    const i = o / 4;
    const x = o + offset;
    O[x] = I[i + 1];
    O[x + 1] = I[i + 1] >>> 8;
    O[x + 2] = I[i + 1] >>> 16;
    O[x + 3] = I[i + 1] >>> 24;
    O[x + 4] = I[i];
    O[x + 5] = I[i] >>> 8;
    O[x + 6] = I[i] >>> 16;
    O[x + 7] = I[i] >>> 24;
  }

  return O;
};

// eslint-disable-next-line max-statements
const Sponge = function({ capacity, padding }) {
  const keccak = permute();

  const stateSize = 200;
  const blockSize = capacity / 8;
  const queueSize = stateSize - capacity / 4;
  let queueOffset = 0;

  const state = new Uint32Array(stateSize / 4);
  const queue = new Uint8Array(queueSize);

  this.absorb = (buffer) => {
    for (let i = 0; i < buffer.length; i++) {
      queue[queueOffset] = buffer[i];
      queueOffset += 1;

      if (queueOffset >= queueSize) {
        xorWords(queue, state);
        keccak(state);
        queueOffset = 0;
      }
    }
    return this;
  };

  // eslint-disable-next-line max-statements
  this.squeeze = (options = {}) => {
    const output = {
      buffer: options.buffer || new Uint8Array(blockSize),
      padding: options.padding || padding,
      queue: new Uint8Array(queue.length),
      state: new Uint32Array(state.length)
    };

    for (let j = 0; j < queue.length; j++) {
      output.queue[j] = queue[j];
    }
    for (let i = 0; i < state.length; i++) {
      output.state[i] = state[i];
    }
    for (let k = queueOffset; k < output.queue.length; k++) {
      output.queue[k] = 0;
    }

    output.queue[queueOffset] |= output.padding;
    output.queue[queueSize - 1] |= 0x80;

    xorWords(output.queue, output.state);

    for (let offset = 0; offset < output.buffer.length; offset += queueSize) {
      keccak(output.state);
      readWords(output.state, output.buffer, offset, queueSize);
    }

    return output.buffer;
  };

  this.reset = () => {
    queue.fill(0);
    state.fill(0);
    queueOffset = 0;
    return this;
  };

  return this;
};

const createHash = ({ allowedSizes, defaultSize, padding }) => function Hash(size = defaultSize) {
  if (!this || this.constructor !== Hash) {
    return new Hash(size);
  }

  if (allowedSizes && !allowedSizes.includes(size)) {
    throw new Error('Unsupported hash length');
  }

  const sponge = new Sponge({ capacity: size });

  this.update = (input, encoding = 'utf8') => {
    if (input instanceof Uint8Array) {
      sponge.absorb(input);
      return this;
    }

    if (typeof input === 'string') {
      switch (encoding) {
        case 'utf8': {
		let te = new TextEncoder();
		return this.update(te.encode(input));
	}
        case 'hex': return this.update(Uint8Array.fromHex(input));
        case 'base64': return this.update(Uint8Array.fromBase64(input));
        case 'base64url': return this.update(Uint8Array.fromBase64(input, 'base64url'));
        default:
          throw new TypeError('Unknown encoding (use utf8, hex, base64, or base64url');
      }
    }

    throw new TypeError('Not a string or Uint8Array');
  };

  this.digest = (formatOrOptions = 'binary') => {
    const options = typeof formatOrOptions === 'string' ? { format: formatOrOptions } : formatOrOptions;
    const buffer = sponge.squeeze({
      buffer: options.buffer,
      padding: options.padding || padding
    });

    if (options.format && options.format !== 'binary') {
      return buffer.toHex();
    }

    return buffer;
  };

  this.reset = () => {
    sponge.reset();
    return this;
  };

  return this;
};

/**
 * The Keccak reference implementation uses the simplest possible padding scheme,
 * described as follows:
 *
 * > Definition 1. Multi-rate padding, denoted by pad10*1, appends a single bit 1
 * > followed by the minimum number of bits 0 followed by a single bit 1 such that
 * > the length of the result is a multiple of the block length.
 *
 * @see {@link https://keccak.team/files/Keccak-reference-3.0.pdf}, Section 1.1.2
 */
const Keccak = createHash({ allowedSizes: [224, 256, 384, 512], defaultSize: 512, padding: 0x01 });

/**
 * The SHA-3 specification requires that the input message be appended with a
 * two-bit suffix, `01`. For byte-aligned messages, this results in an extra
 * `0x02` byte (bits fill in from the right).
 *
 * Then, the standard Keccak padding scheme is applied (pad10*1), placing an
 * additional bit at the `0x04` position, resulting in `0x06`.
 *
 * @see {@link https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf}, Section B.2
 */
const SHA3 = createHash({ allowedSizes: [224, 256, 384, 512], defaultSize: 512, padding: 0x06 });

/**
 * SHAKE is an 128-bit or 256-bit extendable output function (XOF) variant of
 * Keccak that uses `0x1F` padding. (SHAKE = Secure Hash Algorithm KEccak)
 *
 * @see {@link https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf}, Section 6.3
 */
const SHAKE = createHash({ allowedSizes: [128, 256], defaultSize: 256, padding: 0x1F });

var NodeSha3;
if (typeof NodeSha3 == "undefined" || !NodeSha3) NodeSha3 = {};
NodeSha3.SHA3_224 = () => { return new SHA3(224); };
NodeSha3.SHA3_256 = () => { return new SHA3(256); };
NodeSha3.SHA3_384 = () => { return new SHA3(384); };
NodeSha3.SHA3_512 = () => { return new SHA3(512); };

NodeSha3.SHAKE = SHAKE;
NodeSha3.SHAKE128 = () => { return new SHAKE(128); };
NodeSha3.SHAKE256 = () => { return new SHAKE(256); };

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};
if (typeof KJUR.crypto.NodeSha3 == "undefined" || !KJUR.crypto.NodeSha3) KJUR.crypto.NodeSha3 = NodeSha3;

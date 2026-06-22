import { Buffer } from 'buffer';
import permute from './permute';

const xorWords = (I, O) => {
  for (let i = 0; i < I.length; i += 8) {
    const o = i / 4;
    O[o] ^= I[i + 7] << 24 | I[i + 6] << 16 | I[i + 5] << 8 | I[i + 4];
    O[o + 1] ^= I[i + 3] << 24 | I[i + 2] << 16 | I[i + 1] << 8 | I[i];
  }
  return O;
};

// eslint-disable-next-line max-statements
const readWords = (I, O) => {
  for (let o = 0; o < O.length; o += 8) {
    const i = o / 4;
    O[o] = I[i + 1];
    O[o + 1] = I[i + 1] >>> 8;
    O[o + 2] = I[i + 1] >>> 16;
    O[o + 3] = I[i + 1] >>> 24;
    O[o + 4] = I[i];
    O[o + 5] = I[i] >>> 8;
    O[o + 6] = I[i] >>> 16;
    O[o + 7] = I[i] >>> 24;
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
  const queue = Buffer.allocUnsafe(queueSize);

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
      buffer: options.buffer || Buffer.allocUnsafe(blockSize),
      padding: options.padding || padding,
      queue: Buffer.allocUnsafe(queue.length),
      state: new Uint32Array(state.length)
    };

    queue.copy(output.queue);
    for (let i = 0; i < state.length; i++) {
      output.state[i] = state[i];
    }

    output.queue.fill(0, queueOffset);

    output.queue[queueOffset] |= output.padding;
    output.queue[queueSize - 1] |= 0x80;

    xorWords(output.queue, output.state);

    for (let offset = 0; offset < output.buffer.length; offset += queueSize) {
      keccak(output.state);
      readWords(output.state, output.buffer.slice(offset, offset + queueSize));
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

export default Sponge;

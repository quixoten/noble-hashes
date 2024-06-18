// adapted from https://gist.github.com/paulmillr/405d7f1efca6e37bee63d6499cd4c8f9

import { HashMD, Chi} from './_md.js';
import { rotl, wrapConstructor } from './utils.js';

// MD5 (RFC 1321) was cryptographically broken.
// It is still widely used in legacy apps. Don't use it for a new protocol.
// - Collisions: 2**18 (vs 2**60 for SHA1)
// - No practical pre-image attacks (only theoretical, 2**123.4)
// - HMAC seems kinda ok: https://datatracker.ietf.org/doc/html/rfc6151
// Architecture is similar to SHA1. Differences:
// - reduced output length: 16 bytes (128 bit) instead of 20
// - 64 rounds, instead of 80
// - little-endian: could be faster, but will require more code
// - non-linear index selection: huge speed-up for unroll
// - per round constants: more memory accesses, additional speed-up for unroll

// Per-round constants
const MD5_K = /* @__PURE__ */ new Uint32Array([
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453,  0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]);

// Initial state (same as sha1, but 4 u32 instead of 5)
const IV = /* @__PURE__ */ new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);

// Temporary buffer, not used to store anything between runs
// Named this way for SHA1 compat
const MD5_W = /* @__PURE__ */ new Uint32Array(16);
class MD5 extends HashMD<MD5> {
  private A = IV[0] | 0;
  private B = IV[1] | 0;
  private C = IV[2] | 0;
  private D = IV[3] | 0;

  constructor() {
    super(64, 16, 8, true);
  }
  protected get(): [number, number, number, number] {
    const { A, B, C, D } = this;
    return [A, B, C, D];
  }
  protected set(A: number, B: number, C: number, D: number) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
  }
  protected process(view: DataView, offset: number): void {
    for (let i = 0; i < 16; i++, offset += 4) MD5_W[i] = view.getUint32(offset, true);
    // Compression function main loop, 64 rounds
    let { A, B, C, D } = this;
    for (let i = 0; i < 64; i++) {
      let F, g, s;
      if (i < 16) {
        F = Chi(B, C, D);
        g = i;
        s = [7, 12, 17, 22];
      } else if (i < 32) {
        F = Chi(D, B, C);
        g = (5 * i + 1) % 16;
        s = [5, 9, 14, 20];
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
        s = [4, 11, 16, 23];
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
        s = [6, 10, 15, 21];
      }
      F = F + A + MD5_K[i] + MD5_W[g];
      A = D;
      D = C;
      C = B;
      B = B + rotl(F, s[i % 4]);
    }
    // Add the compressed chunk to the current hash value
    A = (A + this.A) | 0;
    B = (B + this.B) | 0;
    C = (C + this.C) | 0;
    D = (D + this.D) | 0;
    this.set(A, B, C, D);
  }
  protected roundClean() {
    MD5_W.fill(0);
  }
  destroy() {
    this.set(0, 0, 0, 0);
    this.buffer.fill(0);
  }
}

export const md5 = /* @__PURE__ */ wrapConstructor(() => new MD5());

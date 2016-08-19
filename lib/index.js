import {
  createDecipheriv
} from 'crypto';

import assert from 'assert';

export default class Decryption {

  static attributes = {
    hostname: '',
    username: '',
    'protocol name': '',
  };

  static parsePassword(
    buffPass,
    buffKey0,
    buffKey1
  ) {

    const iv = new Buffer([0, 0, 0, 0, 0, 0, 0, 0])

    const bf0 = createDecipheriv('BF-CBC', buffKey0, iv);

    bf0.setAutoPadding(false);

    const decrypted = Buffer.concat(
      [
        bf0.update(buffPass),
        bf0.final()
      ]
    );

    const bf1 = createDecipheriv('BF-CBC', buffKey1, iv);

    bf1.setAutoPadding(false);

    const padded = Buffer.concat(
      [
        bf1.update(decrypted.slice(4, -4)),
        bf1.final()
      ]
    );

    let end = 0;

    const {
      length
    } = padded;

    for (let i = 0; i < length; i += 2) {
      if (padded[i] === 0 && padded[i + 1] === 0) {
        end = i;
        break;
      }
    }

    return padded.toString('utf16le', 0, end);
  }

  static reg = /^\w:"([^"]+)"=(\S*)/;

  result = {};

  update(line) {

    const {
      reg,
      attributes,
      parsePassword,
    } = Decryption;

    const matches = line.match(reg);

    if (matches) {

      const [,
        key,
        val,
      ] = matches;

      const {
        result
      } = this;

      const _key = key.toLowerCase();

      const valid = attributes.hasOwnProperty(_key)

      if (valid) {
        result[_key] = val;
      } else if (_key === 'password') {

        const {
          length
        } = val;

        assert((length - 1) % 2 === 0, 'Password should be length of 2n+1');

        const buffKey0 = new Buffer([0x24, 0xA6, 0x3D, 0xDE, 0x5B, 0xD3, 0xB3, 0x82, 0x9C, 0x7E, 0x06, 0xF4, 0x08, 0x16, 0xAA, 0x07]);

        const buffKey1 = new Buffer([0x5F, 0xB0, 0x45, 0xA2, 0x94, 0x17, 0xD9, 0x16, 0xC6, 0xC6, 0xA2, 0xFF, 0x06, 0x41, 0x82, 0xB7]);

        const buffPass = new Buffer((length - 1) / 2);

        let offset = 0;

        for (let i = 1; i < length; i += 2) {
          buffPass[offset] = parseInt(val.slice(i, i + 2), 16);
          ++offset;
        }

        result[_key] = parsePassword(buffPass, buffKey0, buffKey1);

      } else if (_key[0] === '[' && _key.slice(-4) === 'port') {
        let parsed = parseInt(val, 16);
        const port = isNaN(parsed) ? val : parsed;
        result[_key] = port;
        result['port'] = port;
      }
    }
  }

  getResult() {
    return this.result;
  }
};
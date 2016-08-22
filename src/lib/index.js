import {
  createDecipheriv
} from 'crypto';

export default () =>
  class Decryption {

    static buffKey0 = Buffer.from([0x24, 0xA6, 0x3D, 0xDE, 0x5B, 0xD3, 0xB3, 0x82, 0x9C, 0x7E, 0x06, 0xF4, 0x08, 0x16, 0xAA, 0x07]);
    static buffKey1 = Buffer.from([0x5F, 0xB0, 0x45, 0xA2, 0x94, 0x17, 0xD9, 0x16, 0xC6, 0xC6, 0xA2, 0xFF, 0x06, 0x41, 0x82, 0xB7]);
    static buffIV = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]);
    static buffPass = null;

    static regSplit = /.{2}/g;
    static reg = /^\w:"([^"]+)"=(\S*)/;

    static attributes = {
      hostname: '',
      username: '',
      'protocol name': '',
    };

    static parsePassword(
      password,
      buffKey0 = this.buffKey0,
      buffKey1 = this.buffKey1,
      buffIV = this.buffIV
    ) {

      const {
        regSplit
      } = this;

      const chunks = password.length % 2 === 0 ? password.match(regSplit) : password.slice(1).match(regSplit);

      const {
        length
      } = chunks;

      let buffPass = this.buffPass;
      if (!buffPass || buffPass.length !== length) {
        buffPass = new Buffer(length);
        this.buffPass = buffPass;
      }

      for (let i = 0; i < length; ++i) {
        buffPass[i] = parseInt(chunks[i], 16);
      }

      const bf0 = createDecipheriv('BF-CBC', buffKey0, buffIV);

      bf0.setAutoPadding(false);

      const decrypted = Buffer.concat(
        [
          bf0.update(buffPass),
          bf0.final()
        ]
      );

      const bf1 = createDecipheriv('BF-CBC', buffKey1, buffIV);

      bf1.setAutoPadding(false);

      const padded = Buffer.concat(
        [
          bf1.update(decrypted.slice(4, -4)),
          bf1.final()
        ]
      );

      let end = 0;

      const {
        length: paddedLength
      } = padded;

      for (let i = 0; i < paddedLength; i += 2) {
        if (padded.readInt16LE(i, true) === 0) {
          end = i;
          break;
        }
      }

      return padded.toString('utf16le', 0, end);
    }

    result = {};

    update(line) {

      const {
        reg,
        attributes,
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

          result[_key] = val ? Decryption.parsePassword(val) : '';

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

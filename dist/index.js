'use strict';

var _commander = require('commander');

var _commander2 = _interopRequireDefault(_commander);

var _readline = require('readline');

var _fs = require('fs');

var _path = require('path');

var _package = require('../package.json');

var _lib = require('./lib');

var _lib2 = _interopRequireDefault(_lib);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

_commander2.default.version(_package.version).description('Decrypts securecrt session files, which can be found inside:\n\n\t%appdata%/VanDyke/Config/Sessions').usage('[options] <file ...>').option('-f, --format [url|json]', 'set output format, default: url', 'url').option('-d, --delimiter [char]', 'set output delimiter, default: space', ' ').parse(process.argv);

const {
  args: files,
  format,
  delimiter
} = _commander2.default;

if (files.length < 1) {
  _commander2.default.help();
}

const start = Date.now();

const Decryption = (0, _lib2.default)();

const decrypt = input => new Promise((resolve, reject) => {
  const decryption = new Decryption();

  input.once('readable', () => {

    const buff = input.read(3);
    const notBOM = String(buff) !== '\uFEFF';
    if (notBOM) {
      input.unshift(buff);
    }

    const lineReader = (0, _readline.createInterface)({
      input
    });

    lineReader.on('line', line => {
      decryption.update(line);
    });

    input.on('end', () => {
      resolve(decryption.getResult());
    });
  });
});

const enc = (strings, ...values) => {
  let output = strings[0];
  const {
    length
  } = values;
  for (let i = 0; i < length; ++i) {
    output += encodeURIComponent(values[i]);
    output += strings[i + 1];
  }
  return output;
};

const {
  length
} = files;

_asyncToGenerator(function* () {

  const promises = files.map(function (filePath) {
    return _asyncToGenerator(function* () {
      const input = (0, _fs.createReadStream)(filePath);
      const result = yield decrypt(input);

      input.close();

      return result;
    })();
  });

  const results = yield Promise.all(promises);

  for (let i = 0; i < length; ++i) {
    const filePath = files[i];
    const result = results[i];

    const name = (0, _path.basename)(filePath);

    let output;

    if (format === 'url') {
      const {
        "protocol name": protocol,
        hostname,
        username,
        port,
        password
      } = result;

      output = enc`${ protocol }://${ username }:${ password }@${ hostname }:${ port }`;
    } else {
      output = JSON.stringify(result);
    }

    console.log(`${ name }${ delimiter }${ output }`);
  }
})().catch(err => {
  console.error(err);
  process.exit(-1);
});
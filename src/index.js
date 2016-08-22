import program from 'commander';

import {
  createInterface
} from 'readline';

import {
  createReadStream
} from 'fs';

import {
  basename
} from 'path';

import {
  version
} from '../package.json';

import DecryptionFactory from './lib';

program
  .version(version)
  .description('Decrypts securecrt session files, which can be found inside:\n\n\t%appdata%/VanDyke/Config/Sessions')
  .usage('[options] <file ...>')
  .option('-f, --format [url|json]', 'set output format, default: url', 'url')
  .option('-d, --delimiter [char]', 'set output delimiter, default: space', ' ')
  .parse(process.argv);

const {
  args: files,
  format,
  delimiter,
} = program;

if (files.length < 1) {
  program.help();
}

const start = Date.now();

const Decryption = DecryptionFactory();

const decrypt = input =>
  new Promise((resolve, reject) => {
    const decryption = new Decryption();

    input.once('readable', () => {

      const buff = input.read(3);
      const notBOM = String(buff) !== '\uFEFF';
      if (notBOM) {
        input.unshift(buff);
      }

      const lineReader = createInterface({
        input,
      });

      lineReader.on('line', line => {
        decryption.update(line);
      });

      input.on('end', () => {
        resolve(
          decryption.getResult()
        );
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
}

const {
  length
} = files;

(async() => {

  const promises = files.map(
    filePath => (async() => {
      const input = createReadStream(filePath);
      const result = await decrypt(input);

      input.close();

      return result;
    })()
  );

  const results = await Promise.all(promises);

  for (let i = 0; i < length; ++i) {
    const filePath = files[i];
    const result = results[i];

    const name = basename(filePath);

    let output;

    if (format === 'url') {
      const {
        "protocol name": protocol,
        hostname,
        username,
        port,
        password,
      } = result;


      output = enc `${protocol}://${username}:${password}@${hostname}:${port}`;
    } else {
      output = JSON.stringify(result);
    }

    console.log(`${name}${delimiter}${output}`);
  }
})().catch(err => {
  console.error(err);
  process.exit(-1);
});

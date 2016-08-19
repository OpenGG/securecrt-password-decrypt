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
} from './package.json';
import Decryption from './lib';

const decrypt = input =>
  new Promise((resolve, reject) => {
    const decrypt = new Decryption();

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
        decrypt.update(line);
      });

      input.on('end', () => {
        resolve(
          decrypt.getResult()
        );
      });

    });
  });

program
  .version(version)
  .description('Decrypts securecrt session files, which can be found inside:\n\n\t%appdata%/VanDyke/Config/Sessions')
  .usage('[options] <file ...>')
  .option('-f, --format [url|json]', 'specify the log format string', 'url')
  .parse(process.argv);

const {
  args: files
} = program;

const start = Date.now();

(async () => {
  for (let file of files) {
    const input = createReadStream(file);
    const result = await decrypt(input);

    input.close();

    const name = basename(file);

    if (program.format === 'url') {
      const {
        "protocol name": protocol,
        hostname,
        username,
        port,
        password,
      } = result;

      const enc = (strings, ...values) => {
        let output = strings[0];
        const { length } = values;
        for (let i = 0; i < length; ++i) {
          output += encodeURIComponent(values[i]);
          output += strings[i + 1];
        }
        return output;
      }

      console.log(name, enc`${protocol}://${username}:${password}@${hostname}:${port}`);
    } else {
      console.log(name, JSON.stringify(result));
    }
  }
})().catch(err => {
  console.error(err);
  process.exit(-1);
});
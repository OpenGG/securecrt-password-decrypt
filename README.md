# SecureCRT-password-decrypt
Exactly as the title says.

## usage

    Usage: securecrt-password-decrypt [options] <file ...>

    Decrypts securecrt session files, which can be found inside:

        %appdata%/VanDyke/Config/Sessions

    Options:

      -h, --help               output usage information
      -V, --version            output the version number
      -f, --format [url|json]  specify the log format string


## Babel

This lib is written in ES6, with stage-0 syntax. Currently babel-register
is a must.

## Credits

The decryption algorithm is taken from `SecureCRT-decryptpass.py` (author
Eloi Vanderbeken).

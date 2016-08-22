# securecrt-password-decrypt
Exactly as the title says.

## usage

    Usage: securecrt-password-decrypt [options] <file ...>

    Decrypts securecrt session files, which can be found inside:

            %appdata%/VanDyke/Config/Sessions

    Options:

        -h, --help               output usage information
        -V, --version            output the version number
        -f, --format [url|json]  set output format, default: url
        -d, --delimiter [char]   set output delimiter, default: space

## Credits

The decryption algorithm is taken from `SecureCRT-decryptpass.py` (author
Eloi Vanderbeken).

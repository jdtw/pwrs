# PWRS

[![Build status](https://ci.appveyor.com/api/projects/status/github/jdtw/pwrs?branch=master&retina=true&svg=true)](https://ci.appveyor.com/project/jdtw/pwrs/)

pwrs is a command-line password manager for Windows, that works with any
smart card that supports ECDH on the P256 curve (such as the YubiKey 4).

## Usage

``` example
PWRS 0.2.0
John Wood <j@jdtw.us>
Command-line password manager

USAGE:
    pwrs [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -v, --vault <vault>    Vault input file

SUBCOMMANDS:
    add     Add a new entry to the vault
    del     Delete a vault
    get     Retrieve an entry from the vault
    help    Prints this message or the help of the given subcommand(s)
    ls      List the entries in the vault
    new     Create a new vault
```

# `PWV`

[![Build status](https://ci.appveyor.com/api/projects/status/github/jdtw/pwrs?branch=master&retina=true&svg=true)](https://ci.appveyor.com/project/jdtw/pwrs/)
[![crates.io](https://img.shields.io/crates/v/pwv.svg)](https://crates.io/crates/pwv)

`pwv` (**p**ass**w**word **v**ault) is a command-line password manager for Windows, that works with any
smart card that supports ECDH on the P256 curve (such as the YubiKey 4).

## Documentation

Documentation of `pwv` internals can be found on [docs.rs](https://docs.rs/pwv/*/x86_64-pc-windows-msvc/pwv/).

## Usage

``` example
PWV 0.2.1
John Wood <j@jdtw.us>
Command-line password manager

USAGE:
    pwv [OPTIONS] <SUBCOMMAND>

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

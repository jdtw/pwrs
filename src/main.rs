#[macro_use]
extern crate human_panic;

#[macro_use]
extern crate clap;
use clap::{App, AppSettings, Arg, SubCommand};

extern crate pwrs;
use pwrs::error::*;

use std::io::Write;

fn main() {
    setup_panic!();

    // Here's how I want to use this tool:
    // > pwrs new /path/to/vault.json --smartcard --key-name pwrskeyname
    // > pwrs new /path/to/vault.json --software --key-name pwrskeyname
    // > pwrs add firsttechfed # will prompt for username/password, and use the vault from PWRS_VAULT
    // > pwrs add google -u me@gmail.com -p password
    // > pwrs get google # will copy to clipboard and use vault from PWRS_VAULT
    // > pwrs get google --show
    // > pwrs del /path/to/vault.json # path should be required here, because we want this to be explicit
    // > pwrs ls
    let matches = App::new("PWRS")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Command line password manager")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("new").about("Create a new vault"))
        .subcommand(SubCommand::with_name("add").about("Add a new entry to the vault"))
        .subcommand(SubCommand::with_name("get").about("Retrieve an entry from the vault"))
        .subcommand(SubCommand::with_name("ls").about("List the entries in the database"))
        .subcommand(SubCommand::with_name("del").about("Delete a vault"))
        .get_matches();

    if let Err(ref e) = run() {
        let stderr = &mut std::io::stderr();
        let errmsg = "Error writing to stderr";

        writeln!(stderr, "error: {}", e).expect(errmsg);

        for cause in e.causes() {
            writeln!(stderr, "caused by: {}", cause).expect(errmsg);
        }

        std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
    Ok(())
}

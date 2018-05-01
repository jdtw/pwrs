#[macro_use]
extern crate human_panic;

#[macro_use]
extern crate clap;
use clap::{App, AppSettings, Arg, ArgGroup, ArgMatches, SubCommand};

extern crate pwrs;
use pwrs::error::*;

use std::io::Write;

fn main() {
    //    setup_panic!();

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
        .subcommand(
            SubCommand::with_name("new")
                .about("Create a new vault")
                .arg(
                    Arg::with_name("VAULT")
                        .help("Path to the vault file")
                        .required(true)
                        .index(1),
                )
                .args_from_usage(
                    "-c, --smartcard 'smart card KSP'
                     -w, --software  'software KSP'",
                )
                .group(
                    ArgGroup::with_name("ksp")
                        .required(true)
                        .args(&["smartcard", "software"]),
                )
                .arg(
                    Arg::with_name("key")
                        .help("Key name to use")
                        .required(true)
                        .takes_value(true)
                        .short("k")
                        .long("key-name"),
                ),
        )
        .subcommand(SubCommand::with_name("add").about("Add a new entry to the vault"))
        .subcommand(SubCommand::with_name("get").about("Retrieve an entry from the vault"))
        .subcommand(SubCommand::with_name("ls").about("List the entries in the database"))
        .subcommand(SubCommand::with_name("del").about("Delete a vault"))
        .get_matches();

    if let Err(ref e) = run(matches) {
        let stderr = &mut std::io::stderr();
        let errmsg = "Error writing to stderr";

        writeln!(stderr, "error: {}", e).expect(errmsg);

        for cause in e.causes() {
            writeln!(stderr, "caused by: {}", cause).expect(errmsg);
        }

        std::process::exit(1);
    }
}

fn run(matches: ArgMatches) -> Result<(), Error> {
    match matches.subcommand() {
        ("new", Some(new_matches)) => println!(
            "Create a new vault at {} with a sc:{}, sw:{} authenticator and a {} key name",
            new_matches.value_of("VAULT").unwrap(),
            new_matches.is_present("smartcard"),
            new_matches.is_present("software"),
            new_matches.value_of("key").unwrap()
        ),
        ("add", Some(_add_matches)) => (),
        ("get", Some(_get_matches)) => (),
        ("ls", Some(_ls_matches)) => (),
        ("del", Some(_del_matches)) => (),
        _ => unreachable!(),
    }

    Ok(())
}

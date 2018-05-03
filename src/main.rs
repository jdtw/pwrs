//#[macro_use]
extern crate human_panic;

#[macro_use]
extern crate clap;
use clap::{App, AppSettings, Arg, ArgGroup, ArgMatches, SubCommand};

extern crate pwrs;
use pwrs::error::*;
use pwrs::prompt::*;

use std::io::Write;
use std::path::PathBuf;

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
        .arg(
            Arg::with_name("vault")
                .help("Vault input file")
                .takes_value(true)
                .short("v")
                .long("vault"),
        )
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("new")
                .about("Create a new vault")
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
        .subcommand(
            SubCommand::with_name("add")
                .about("Add a new entry to the vault")
                .arg(
                    Arg::with_name("SITE")
                        .help("Site for the password (e.g. example.com)")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("user")
                        .help("Username")
                        .takes_value(true)
                        .short("u")
                        .long("user")
                        .requires("password"),
                )
                .arg(
                    Arg::with_name("password")
                        .help("Password")
                        .takes_value(true)
                        .short("p")
                        .long("pass")
                        .requires("user"),
                ),
        )
        .subcommand(
            SubCommand::with_name("get")
                .about("Retrieve an entry from the vault")
                .arg(
                    Arg::with_name("SITE")
                        .help("Site for the password (e.g. example.com)")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(SubCommand::with_name("ls").about("List the entries in the database"))
        .subcommand(SubCommand::with_name("del").about("Delete a vault"))
        .get_matches();

    if let Err(ref e) = run(matches) {
        let stderr = &mut std::io::stderr();
        let errmsg = "Error writing to stderr";

        writeln!(stderr, "error: {}", e).expect(errmsg);

        for cause in e.causes().skip(1) {
            writeln!(stderr, "caused by: {}", cause).expect(errmsg);
        }

        std::process::exit(1);
    }
}

fn vault_path_from_matches(matches: &ArgMatches) -> Result<PathBuf, Error> {
    Ok(PathBuf::from(matches
        .value_of("vault")
        .map_or_else(|| std::env::var("VAULT_PATH"), |s| Ok(String::from(s)))
        .context(
            "Vault command line option or VAULT_PATH environment variable must be set.",
        )?))
}

fn run(matches: ArgMatches) -> Result<(), Error> {
    let vault_path = vault_path_from_matches(&matches)?;
    match matches.subcommand() {
        ("new", Some(new_matches)) => println!(
            "Create a new vault at {} with a sc:{}, sw:{} authenticator and a {} key name",
            vault_path.display(),
            new_matches.is_present("smartcard"),
            new_matches.is_present("software"),
            new_matches.value_of("key").unwrap()
        ),
        ("add", Some(add_matches)) => {
            let site = add_matches.value_of("SITE").unwrap();
            let (username, password) = if add_matches.is_present("user") {
                (
                    String::from(add_matches.value_of("user").unwrap()),
                    String::from(add_matches.value_of("password").unwrap()),
                )
            } else {
                let message = format!("Enter credentials for {}", site);
                UIPrompt::new("PWRS", &message)
                    .prompt()
                    .with_context(move |_| format!("Prompt '{}' cancelled", message))?
                    .to_tuple()
            };
            println!(
                "Add new entry to vault {} for {} with user: {}, pass: {}",
                vault_path.display(),
                site,
                username,
                password
            )
        }
        ("get", Some(get_matches)) => {
            let site = get_matches.value_of("SITE").unwrap();
            println!("Get entry {} from vault {}", site, vault_path.display())
        }
        ("ls", Some(_ls_matches)) => unimplemented!(),
        ("del", Some(_del_matches)) => unimplemented!(),
        _ => unreachable!(),
    }

    Ok(())
}

//#[macro_use]
extern crate human_panic;

extern crate clipboard_win;
use clipboard_win::Clipboard;

#[macro_use]
extern crate clap;
use clap::{App, AppSettings, Arg, ArgGroup, ArgMatches, SubCommand};

extern crate pwrs;
use pwrs::authenticator::{KeyStorageProvider, Ksp};
use pwrs::error::*;
use pwrs::prompt::*;
use pwrs::vault::Vault;

use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

fn main() {
    //    setup_panic!();

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
                )
                .arg(
                    Arg::with_name("dump")
                        .help("Dump the password to STDOUT")
                        .short("d")
                        .long("dump"),
                )
                .arg(
                    Arg::with_name("user")
                        .help("Only retrieve the username")
                        .short("u")
                        .long("user"),
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
            "Vault command line option or VAULT_PATH environment variable must be set",
        )?))
}

fn run(matches: ArgMatches) -> Result<(), Error> {
    let vault_path = vault_path_from_matches(&matches)?;
    match matches.subcommand() {
        ("new", Some(new_matches)) => {
            let ksp = if new_matches.is_present("software") {
                Ksp::Software
            } else if new_matches.is_present("smartcard") {
                Ksp::SmartCard
            } else {
                unreachable!()
            };
            let key_name = String::from(new_matches.value_of("key").unwrap());
            let authenticator = KeyStorageProvider::new(ksp, key_name)?;
            let vault = Vault::new(authenticator);
            let vault_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(vault_path.as_path())
                .context(format!(
                    "Create new vault file failed: {}",
                    vault_path.display()
                ))?;
            vault
                .to_writer(vault_file)
                .context("Serialize vault failed")?;
        }
        ("add", Some(add_matches)) => {
            let site = String::from(add_matches.value_of("SITE").unwrap());
            let (username, password) = if add_matches.is_present("user") {
                (
                    String::from(add_matches.value_of("user").unwrap()),
                    String::from(add_matches.value_of("password").unwrap()),
                )
            } else {
                let message = format!("Enter credentials for {}", site);
                UIPrompt::new("PWRS", &message)
                    .prompt()
                    .context(format!("Prompt '{}' cancelled", message))?
                    .to_tuple()
            };

            let vault_file = File::open(vault_path.as_path())
                .context(format!("Open vault file failed: {}", vault_path.display()))?;
            let mut vault = Vault::from_reader(vault_file)?;
            vault
                .insert(site, username, &password)
                .context("Insert vault entry failed")?;
            let vault_file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(vault_path.as_path())
                .context(format!(
                    "Open vault file for write failed: {}",
                    vault_path.display()
                ))?;
            vault.to_writer(vault_file)?;
        }
        ("get", Some(get_matches)) => {
            let site = get_matches.value_of("SITE").unwrap();
            let vault_file = File::open(vault_path.as_path())
                .context(format!("Open vault file failed: {}", vault_path.display()))?;
            let vault = Vault::from_reader(vault_file)?;
            if let Some(entry) = vault.get(site) {
                println!("Username: {}", entry.username());
                if !get_matches.is_present("user") {
                    let password = entry
                        .decrypt_password()
                        .context("Password decryption failed")?;
                    if get_matches.is_present("dump") {
                        println!("Password: {}", password);
                    } else {
                        Clipboard::new()?.set_string(&password)?;
                        println!("Password copied to clipboard");
                    }
                }
            }
        }
        ("ls", Some(_ls_matches)) => unimplemented!(),
        ("del", Some(_del_matches)) => {
            let vault_file = File::open(vault_path.as_path())
                .context(format!("Open vault file failed: {}", vault_path.display()))?;
            let vault = Vault::from_reader(vault_file)?;
            vault.delete().context("Failed to remove the vault key")?;
            fs::remove_file(vault_path.as_path()).context(format!(
                "Remove vault file failed: {}",
                vault_path.display()
            ))?;
        }
        _ => unreachable!(),
    }

    Ok(())
}

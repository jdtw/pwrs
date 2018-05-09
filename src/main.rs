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
use std::io::Write;
use std::path::PathBuf;

fn main() {
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
        .subcommand(SubCommand::with_name("ls").about("List the entries in the vault"))
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

fn vault_path(matches: &ArgMatches) -> Result<PathBuf, Error> {
    Ok(PathBuf::from(matches
        .value_of("vault")
        .map_or_else(|| std::env::var("VAULT_PATH"), |s| Ok(String::from(s)))
        .context(
            "Vault command line option or VAULT_PATH environment variable must be set",
        )?))
}

fn new(vault_path: PathBuf, matches: &ArgMatches) -> Result<(), Error> {
    let ksp = if matches.is_present("software") {
        Ksp::Software
    } else if matches.is_present("smartcard") {
        Ksp::SmartCard
    } else {
        unreachable!()
    };
    let key_name = String::from(matches.value_of("key").unwrap());
    let authenticator = KeyStorageProvider::new(ksp, key_name)?;
    let vault = Vault::new(authenticator);
    let thumbprint = vault.thumbprint()?;
    vault.write_new(vault_path)?;
    println!("Created vault with thumbprint: {}", thumbprint);
    Ok(())
}

fn add(vault_path: PathBuf, matches: &ArgMatches) -> Result<(), Error> {
    let mut vault = Vault::from_path(vault_path.as_path())?;
    let thumbprint = vault.thumbprint()?;
    let site = String::from(matches.value_of("SITE").unwrap());
    let creds = if matches.is_present("user") {
        Credentials::new(
            String::from(matches.value_of("user").unwrap()),
            // Note that we're copying the password here, so the copy
            // still owned by `matches` may remain in memory, which is
            // less than ideal (if it wasn't obvious enough that passing
            // in a password on the command line isn't very secure...).
            String::from(matches.value_of("password").unwrap()),
        )
    } else {
        let caption = format!("Enter credentials for {}", site);
        let message = format!("Public key thumbprint: {}", thumbprint);
        UIPrompt::new(&caption, &message)
            .prompt()
            .context(format!("Prompt '{}' failed", caption))?
    };
    vault
        .insert(site, creds)
        .context("Insert vault entry failed")?;
    vault.write_update(vault_path)?;
    println!(
        "Password encrypted to public key thumbprint: {}",
        thumbprint
    );
    Ok(())
}

fn get(vault_path: PathBuf, matches: &ArgMatches) -> Result<(), Error> {
    let site = matches.value_of("SITE").unwrap();
    let vault = Vault::from_path(vault_path)?;
    let entry = vault
        .get(site)
        .ok_or(PwrsError::EntryNotFound(String::from(site)))?;
    println!("Username: {}", entry.username());
    if !matches.is_present("user") {
        let password = entry
            .decrypt_password()
            .context("Password decryption failed")?;
        if matches.is_present("dump") {
            println!("Password: {}", password.str());
        } else {
            Clipboard::new()?.set_string(password.str())?;
            println!("Password copied to clipboard");
        }
    }

    Ok(())
}

fn ls(vault_path: PathBuf) -> Result<(), Error> {
    let vault = Vault::from_path(vault_path)?;
    println!("{}", vault.thumbprint()?);
    let mut entries = vault.iter().collect::<Vec<_>>();
    entries.sort_by(|a, b| a.site().cmp(&b.site()));
    for entry in entries {
        println!("{}, {}", entry.site(), entry.username());
    }

    Ok(())
}

fn del(vault_path: PathBuf) -> Result<(), Error> {
    let vault = Vault::from_path(vault_path.as_path())?;
    vault.delete().context("Failed to remove the vault key")?;
    fs::remove_file(vault_path.as_path()).context(format!(
        "Remove vault file failed: {}",
        vault_path.display()
    ))?;

    Ok(())
}

fn run(matches: ArgMatches) -> Result<(), Error> {
    let vault_path = vault_path(&matches)?;
    match matches.subcommand() {
        ("new", Some(matches)) => new(vault_path, matches),
        ("add", Some(matches)) => add(vault_path, matches),
        ("get", Some(matches)) => get(vault_path, matches),
        ("ls", _) => ls(vault_path),
        ("del", _) => del(vault_path),
        _ => unreachable!(),
    }
}

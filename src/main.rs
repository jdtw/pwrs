#[macro_use]
extern crate human_panic;

extern crate pwrs;

use pwrs::error::*;
use std::io::Write;

fn main() {
    setup_panic!();

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

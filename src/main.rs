extern crate mini_emulator;

use std::env;
use std::process;

use mini_emulator::Config;

fn main() {
    let args: Vec<String> = env::args().collect();

    let config = Config::new(&args).unwrap_or_else(|err| {
        println!("Problem parsing arguments: {}", err);
        process::exit(1);
    });

    mini_emulator::run(config);
}

extern crate eris_disass;

use std::fs::File;
use std::io::Read;
use eris_disass::*;

fn main() {
    let mut file = File::open("./examples/binary")
        .expect("failed to open binary file");

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .expect("failed to read file");

    let data = contents.as_slice();

    // set the base address the code will run at
    let addr = 0x1000;
    let mut offset = 0;

    while offset < data.len()-1 {
        let (insn, size) = instruction::Insn::parse(BitMode::X86_32, (addr+offset) as i32, &data[offset..])
            .expect("failed to parse instruction");

        println!("{}", insn);
        offset += size;
    }
}

# eris-disass [![Build Status](https://travis-ci.org/tsurai/eris-disass.svg?branch=master)](https://travis-ci.org/tsurai/eris-disass)
Simple x86 disassembler supporting a very limited subset of the x86 instruction set. For educational purposes only.

## Purpose
This project has been created as part of a reverse engineering course. The students had to pick a disassembler to use and I natrually decided to make my own.

**Warning:** The codebase has evolved and grown with my knowledge and
understanding of the Intel x86 architecture and instruction set. In other words, it is very messy, dirty and badly designed but uses intentionally
verbose code for better comprehension. 


## Usage
```rust
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
```
```
0x1000:    55                  	push	ebp
0x1001:    8b ec               	mov	ebp, esp
0x1003:    51                  	push	ecx
0x1004:    53                  	push	ebx
0x1005:    8b 5d 0c            	mov	ebx, DWORD PTR [ebp+0xc]
0x1008:    56                  	push	esi
0x1009:    8d 43 01            	lea	eax, DWORD PTR [ebx+0x1]
0x100c:    50                  	push	eax
0x100d:    e8 59 0e 00 00      	call	0x1e6b
0x1012:    8b f0               	mov	esi, eax
0x1014:    33 c0               	xor	eax, eax
0x1016:    89 45 0c            	mov	DWORD PTR [ebp+0xc], eax
0x1019:    59                  	pop	ecx
0x101a:    85 db               	test	ebx, ebx
0x101c:    7e 2c               	jle	0x104a
0x101e:    57                  	push	edi
0x101f:    8b 7d 08            	mov	edi, DWORD PTR [ebp+0x8]
```

use datatypes::*;
use address::*;
use failure::*;
use util;

fn parse_prefix(data: &[u8]) -> (u16, usize) {
    let mut prefix = 0;
    let mut offset = 0;

    while offset < data.len() {
        prefix |= match data[offset] {
            0xf0 => Prefix::Lock,
            0xf2 => Prefix::RepnBound,
            0xf3 => Prefix::Rep,
            0x2e => Prefix::OverrideCs,
            0x36 => Prefix::OverrideSs,
            0x3e => Prefix::OverrideDs,
            0x26 => Prefix::OverrideEs,
            0x64 => Prefix::OverrideFs,
            0x65 => Prefix::OverrideGs,
            0x66 => Prefix::OverrideOpSize,
            0x67 => Prefix::OverrideAddrSize,
            _ => return (prefix, offset),
        } as u16;
        offset += 1
    }
    (prefix, offset)
}

fn get_immediate_value(op_size: OperandSize, data: &[u8]) -> (ImmediateValue, usize) {
    match op_size {
        OperandSize::Bit8 => (ImmediateValue::Imm8(data[0] as i8), 1),
        OperandSize::Bit16 => (util::read_imm16(data), 2),
        OperandSize::Bit32 => (util::read_imm32(data), 4),
        _ => panic!("invalid immediate size")
    }
}

pub struct Insn {
    pub addr: i32,
    pub mnemonic: String,
    pub operands: OperandList,
    pub bytes: Vec<u8>
}

impl Insn {
    fn new(mnemonic: &str, operands: Vec<Operand>, addr: i32, bytes: Vec<u8>) -> Insn {
        Insn {
            addr: addr,
            mnemonic: mnemonic.to_owned(),
            operands: operands,
            bytes: bytes,
        }
    }

    fn get_operand(addr: i32, op_size: OperandSize, addr_size: OperandSize, opcode: u8, offset: usize, data: &[u8], encoding: InsnEncoding) -> Result<(Operand, usize), Error> {
        use self::InsnEncoding::*;

        match encoding {
            StaticR(ref reg) => {
                Ok((Operand::Register(reg.clone()), 0))
            },
            OpR => {
                let reg = get_register_operand(op_size, opcode);
                Ok((Operand::Register(reg), 0))
            },
            OpXMM => {
                let reg = get_register_operand(OperandSize::Xmm128, opcode);
                Ok((Operand::Register(reg), 0))
            },
            R8 => {
                let reg = get_register_operand(OperandSize::Bit8, data[0] >> 3);
                let size = if offset == 0 { 1 } else { 0 };
                Ok((Operand::Register(reg), size))
            },
            R32 => {
                let reg = get_register_operand(op_size, data[0] >> 3);
                let size = if offset == 0 { 1 } else { 0 };
                Ok((Operand::Register(reg), size))
            },
            Rm8 => {
                let (eff_addr, size) = get_effective_address(OperandSize::Bit8, addr_size, data)
                    .context("failed to get effective address")?;
                let size = if offset > 0 { size - 1 } else { size };
                Ok((Operand::EffectiveAddress(eff_addr), size))
            },
            Rm32 => {
                let (eff_addr, size) = get_effective_address(op_size, addr_size, data)
                    .context("failed to get effective address")?;
                let size = if offset > 0 { size - 1 } else { size };
                Ok((Operand::EffectiveAddress(eff_addr), size))
            },
            M32 => {
                let (eff_addr, size) = get_effective_address(op_size, addr_size, data)
                    .context("failed to get effective address")?;

                if !eff_addr.is_memory_addr() {
                    bail!("expected memory address");
                }

                let size = if offset > 0 { size - 1 } else { size };
                Ok((Operand::EffectiveAddress(eff_addr), size))
           },
           Imm8 => {
                let (imm, size) = get_immediate_value(OperandSize::Bit8, &data[offset..]);
                Ok((Operand::ImmediateValue(imm), size))
            },
            Imm32 => {
                let (imm, size) = get_immediate_value(op_size, &data[offset..]);
                Ok((Operand::ImmediateValue(imm), size))
            },
            Rel8 => {
                let rel32 = RelativeAddress::Rel32(addr + offset as i32 + 1 + (data[offset] as i8) as i32);
                Ok((Operand::RelativeAddress(rel32), 1))
            },
            Rel32 => {
                let (rel, size) = get_immediate_value(op_size, &data[offset..]);
                let addr = addr + offset as i32 + size as i32 + rel.to_inner();
                Ok((Operand::RelativeAddress(RelativeAddress::Rel32(addr)), size))
            },
            _ => {
                panic!("unknown operand encoding");
            }
        }
    }

    fn get_opcodes<'a>(data: &'a [u8]) -> Result<&'a [u8], Error> {
        if data.len() == 0 {
            bail!("not enough data left");
        }

        Ok(if data.len() > 1 && data[0] == 0x0f {
            &data[0..2]
        } else {
            &data[0..1]
        })
    }

    pub fn parse(mode: BitMode, addr: i32, data: &[u8]) -> Result<(Insn, usize), Error> {
        let (prefix, mut offset) = parse_prefix(data);

        let opcodes = Self::get_opcodes(&data[offset..])
            .context("failed to get opcodes")?;

        offset += opcodes.len();

        let mut embedded_ops = Vec::new();

        let (mut op_size, addr_size) = util::get_override_size(mode, prefix);

        let (mnemonic, encoding): (&str, Option<&[InsnEncoding]>) = match opcodes {
            // ADD r/m8,r8 - 0x00 /r
            &[0x00] => {
                let enc = &[InsnEncoding::Rm8, InsnEncoding::R8];
                ("add", Some(enc))
            },
            // ADD r/m32,r32 / r/m16,r16 - 0x01 /r
            &[0x01] => {
                let enc = &[InsnEncoding::Rm32, InsnEncoding::R32];
                ("add", Some(enc))
            },
            // ADD r/m8,r8 - 0x02 /r
            &[0x02] => {
                let enc = &[InsnEncoding::R8, InsnEncoding::Rm8];
                ("add", Some(enc))
            },
            // ADD r32,r/m32 - 0x03 /r
            &[0x03] => {
                let enc = &[InsnEncoding::R8, InsnEncoding::Rm8];
                ("add", Some(enc))
            },
            // ADD AL,imm8 - 0x04 ib
            &[0x04] => {
                let enc = &[InsnEncoding::StaticR(Register::AL), InsnEncoding::Imm8];
                ("add", Some(enc))
            },
            // ADD AX/EAX,imm32 - 0x05 iw / id
            &[0x05] => {
                let enc = if op_size == OperandSize::Bit16 {
                    &[InsnEncoding::StaticR(Register::AX), InsnEncoding::Imm32]
                } else {
                    &[InsnEncoding::StaticR(Register::EAX), InsnEncoding::Imm32]
                };
                ("add", Some(enc))
            },
            // PUSH ES - 0x06
            &[0x06] => {
                let enc = &[InsnEncoding::StaticR(Register::ES)];
                ("push", Some(enc))
            },
            // POP ES - 0x07
            &[0x07] => {
                let enc = &[InsnEncoding::StaticR(Register::ES)];
                ("pop", Some(enc))
            },
            // OR r/m8, r8 - 0x08 /r
            &[0x08] => {
                let enc = &[InsnEncoding::Rm8, InsnEncoding::R8];
                ("or", Some(enc))
            },
            // OR r/m32, r32 - 0x09 /r
            &[0x09] => {
                let enc = &[InsnEncoding::Rm32, InsnEncoding::R32];
                ("or", Some(enc))
            },
            // OR r8, r/m8 - 0x0a /r
            &[0x0a] => {
                let enc = &[InsnEncoding::R8, InsnEncoding::Rm8];
                ("or", Some(enc))
            },
            // OR rel32, r/m32 - 0x0b /r
            &[0x0b] => {
                let enc = &[InsnEncoding::R8, InsnEncoding::Rm8];
                ("or", Some(enc))
            },
            // OR AL, imm8 - 0x0c ib
            &[0x0c] => {
                let enc = &[InsnEncoding::StaticR(Register::AL), InsnEncoding::Imm8];
                ("or", Some(enc))
            },
            // OR AX/EAX, imm32 - 0x0d iw / id
            &[0x0d] => {
                let enc = if op_size == OperandSize::Bit16 {
                    &[InsnEncoding::StaticR(Register::AX), InsnEncoding::Imm32]
                } else {
                    &[InsnEncoding::StaticR(Register::EAX), InsnEncoding::Imm32]
                };
                ("or", Some(enc))
            },
            // PUSH CS - 0x0e
            &[0x0e] => {
                let enc = &[InsnEncoding::StaticR(Register::CS)];
                ("push", Some(enc))
            },
            // ADC r/m8,r8
            &[0x10] => {
                let enc = &[InsnEncoding::Rm8, InsnEncoding::R8];
                ("adc", Some(enc))
            },
            // ADC r/m32,r32
            &[0x11] => {
                let enc = &[InsnEncoding::Rm32, InsnEncoding::R32];
                ("adc", Some(enc))
            },
            // ADC r8, r/m8
            &[0x12] => {
                let enc = &[InsnEncoding::R8, InsnEncoding::Rm8];
                ("adc", Some(enc))
            },
            // ADC r32, r/m32
            &[0x13] => {
                let enc = &[InsnEncoding::R32, InsnEncoding::Rm32];
                ("adc", Some(enc))
            },
            // ADC AL, imm8
            &[0x14] => {
                let enc = &[InsnEncoding::StaticR(Register::AL), InsnEncoding::Imm8];
                ("adc", Some(enc))
            },
            // ADC AX/EAX, imm32
            &[0x15] => {
                let enc = if op_size == OperandSize::Bit16 {
                    &[InsnEncoding::StaticR(Register::AX), InsnEncoding::Imm32]
                } else {
                    &[InsnEncoding::StaticR(Register::EAX), InsnEncoding::Imm32]
                };
                ("adc", Some(enc))
            },
            // PUSH SS
            &[0x16] => {
                let enc = &[InsnEncoding::StaticR(Register::SS)];
                ("push", Some(enc))
            },
            // POP SS
            &[0x17] => {
                let enc = &[InsnEncoding::StaticR(Register::SS)];
                ("pop", Some(enc))
            },
            // SBB r/m8, r8
            &[0x18] => {
                let enc = &[InsnEncoding::Rm8, InsnEncoding::R8];
                ("sbb", Some(enc))
            },
            // SBB r/m32, r32
            &[0x19] => {
                let enc = &[InsnEncoding::Rm32, InsnEncoding::R32];
                ("sbb", Some(enc))
            },
            // SBB r8, r/m8
            &[0x1a] => {
                let enc = &[InsnEncoding::R8, InsnEncoding::Rm8];
                ("sbb", Some(enc))
            },
            // SBB r32, r/m32
            &[0x1b] => {
                let enc = &[InsnEncoding::R32, InsnEncoding::Rm32];
                ("sbb", Some(enc))
            },
            // SBB AL, imm8
            &[0x1c] => {
                let enc = &[InsnEncoding::StaticR(Register::AL), InsnEncoding::Imm8];
                ("sbb", Some(enc))
            },
            // SBB AX/EAX, imm32
            &[0x1d] => {
                let enc = if op_size == OperandSize::Bit16 {
                    &[InsnEncoding::StaticR(Register::AX), InsnEncoding::Imm32]
                } else {
                    &[InsnEncoding::StaticR(Register::EAX), InsnEncoding::Imm32]
                };
                ("sbb", Some(enc))
            },
            // IMUL r32 / rn32 / imm32
            &[0x69] => {
                let enc = &[InsnEncoding::R32, InsnEncoding::Rm32, InsnEncoding::Imm32];
                ("imul", Some(enc))
            },
            // PUSH imm8 - 0x6a ib
            &[0x6a] => {
                let enc = &[InsnEncoding::Imm8];
                ("push", Some(enc))
            },
            // JBE rel8 - 0x76 cb
            &[0x76] => {
                let enc = &[InsnEncoding::Rel8];
                ("jbe", Some(enc))
            },
            // TEST r/m16,r16 / r/m32,r32 - 0x85 /r
            &[0x85] => {
                let enc = &[InsnEncoding::Rm32, InsnEncoding::R32];
                ("test", Some(enc))
            },
            // MOV r/m8,r8 - 0x88 /r
            &[0x88] => {
                let enc = &[InsnEncoding::Rm8, InsnEncoding::R8];
                ("mov", Some(enc))
            },
            // MOV r/m16,r16 / r/m32,r32 - 0x8b /r
            &[0x89] => {
                let enc = &[InsnEncoding::Rm32, InsnEncoding::R32];
                ("mov", Some(enc))
            },
            // MOV r8 / r/m8 - 0x8a /r
            &[0x8a] => {
                let enc = &[InsnEncoding::R8, InsnEncoding::Rm8];
                ("mov", Some(enc))
            },
            // MOV r16,r/m16 / r16,r/m32 - 0x8b /r
            &[0x8b] => {
                let enc = &[InsnEncoding::R32, InsnEncoding::Rm32];
                ("mov", Some(enc))
            },
            // MOV r/m16,imm16 / r/m32,imm32 - 0xc7 /0 iw
            &[0xc7] => {
                let enc = &[InsnEncoding::Rm32, InsnEncoding::Imm32];
                ("mov", Some(enc))
            },
            // MOV r/m16,imm16 / r/m32,imm32 - 0xc7 /0 iw
            &[0xb8] => {
                let enc = &[InsnEncoding::R32, InsnEncoding::Imm32];
                ("mov", Some(enc))
            },
            // LEA r16,m / r32,m - 0x8d /r
            &[0x8d] => {
                let enc = &[InsnEncoding::R32, InsnEncoding::M32];
                ("lea", Some(enc))
            },
            // OUT imm8 / AL - 0xe6
            &[0xe6] => {
                let enc = &[InsnEncoding::Imm8, InsnEncoding::StaticR(Register::AL)];
                ("out", Some(enc))
            },
            // OUT imm8 / eAX - 0xe7
            &[0xe7] => {
                let enc = if op_size == OperandSize::Bit16 {
                    &[InsnEncoding::Imm8, InsnEncoding::StaticR(Register::AX)]
                } else {
                    &[InsnEncoding::Imm8, InsnEncoding::StaticR(Register::EAX)]
                };
                ("out", Some(enc))
            },
            // CALL rel16 / rel32 - 0xe8 cw / cd
            &[0xe8] => {
                let enc = &[InsnEncoding::Rel32];
                ("call", Some(enc))
            },
            // JL rel8 - 0x7c cb
            &[0x7c] => {
                let enc = &[InsnEncoding::Rel8];
                ("jl", Some(enc))
            },
            // JLE rel8 - 0x7e cb
            &[0x7e] => {
                let enc = &[InsnEncoding::Rel8];
                ("jle", Some(enc))
            },
            // XOR  r8,r/m8 - 0x32 /r
            &[0x32] => {
                let enc = &[InsnEncoding::R8, InsnEncoding::Rm8];
                ("xor", Some(enc))
            },
            // XOR r16,r/m16 / r32,r/n32 - 0x33 /r
            &[0x33] => {
                let enc = &[InsnEncoding::R32, InsnEncoding::Rm32];
                ("xor", Some(enc))
            },
            // XOR AL, imm8
            &[0x34] => {
                embedded_ops.push(Operand::Register(Register::AL));
                let enc = &[InsnEncoding::Imm8];
                ("xor", Some(enc))
            },
            &[0x3b] => {
                let enc = &[InsnEncoding::R32, InsnEncoding::Rm32];
                ("cmp", Some(enc))
            }
            // SUB r16,r/m16 / r32,r/m32 - 0x2b /r
            &[0x2b] => {
                let enc = &[InsnEncoding::R32, InsnEncoding::Rm32];
                ("sub", Some(enc))
            },
            // SUB r/m16,imm8, r/m32,imm8 - 0x83 /5 ib
            &[0x83] => {
                let enc = &[InsnEncoding::Rm32, InsnEncoding::Imm8];
                ("sub", Some(enc))
            },
            // DIV r/m16 / r/m32 - 0xf7 /6
            &[0xf7] => {
                let enc = &[InsnEncoding::Rm32];
                ("div", Some(enc))
            },
            &[0xfe] => {
                let enc = &[InsnEncoding::Rm8];
                ("inc", Some(enc))
            },
            &[0xff] => {
                let reg: u8 = (data[offset] & 0b00111000) >> 3;

                match reg {
                    0x0 => {
                        // INC r/m16 / rm/32 - 0xff /0
                        let enc = &[InsnEncoding::Rm32];
                        ("inc", Some(enc))
                    },
                    0x6 => {
                        // PUSH r/m16 / rm/32 - 0xff /6
                        let enc = &[InsnEncoding::Rm32];
                        ("push", Some(enc))
                    },
                    _ => {
                        bail!("unknown instruction")
                    }
                }
            },
            // JMP rel8 - 0xeb rel8
            &[0xeb] => {
                let enc = &[InsnEncoding::Rel8];
                ("jmp", Some(enc))
            },
            // JMP rel32 - 0xe9 rel32
            &[0xe9] => {
                let enc = &[InsnEncoding::Rel32];
                ("jmp", Some(enc))
            },
            // RET - 0xc3
            &[0xc3] => {
                ("ret", None)
            },
            // LEAVE - 0xc9
            &[0xc9] => {
                ("leave", None)
            },
            // MOVUPS xmm / xmm/m128 - 0x0f 0x10
            &[0x0f, 0x10] => {
                let enc = &[InsnEncoding::R32, InsnEncoding::Rm32];
                op_size = OperandSize::Xmm128;
                ("movups", Some(enc))
            },
            // MOVUPS xmm/m128 / xmm - 0x0f 0x11
            &[0x0f, 0x11] => {
                let enc = &[InsnEncoding::Rm32, InsnEncoding::R32];
                op_size = OperandSize::Xmm128;
                ("movups", Some(enc))
            },
            //  CVTP12PS xmm / xmm/m64 - 0x0f 0x2a
            &[0x0f, 0x2A] => {
                let enc = &[InsnEncoding::R32, InsnEncoding::Rm32];
                op_size = OperandSize::Bit64;
                ("cvtp12ps", Some(enc))
            },
            // CMOVO R32 / RM32 - 0x0f 0x40
            &[0x0f, 0x40] => {
                let enc = &[InsnEncoding::R32, InsnEncoding::Rm32];
                ("cmovo", Some(enc))
            },
            // POP r16 / r32 / r64 - 0x58 +rw / +rd / +rd
            x if (x[0] & 0x58) == 0x58 => {
                let enc = &[InsnEncoding::OpR];
                ("pop", Some(enc))
            },
            // PUSH r16 / r32 / r64 - 0x50 +rw / +rd / +rd
            x if (x[0] & 0x50) == 0x50 => {
                let enc = &[InsnEncoding::OpR];
                ("push", Some(enc))
            },
            // INC r16 / r32 - 0x40 +rw / +rd
            x if (x[0] & 0x40) == 0x40 => {
                let enc = &[InsnEncoding::OpR];
                ("inc", Some(enc))
            },
            _ => {
                bail!("unknown instruction")
            }
        };

        let (operands, size) = if let Some(enc) = encoding {
            let mut op_offset = 0;

            for e in enc {
                let (ops, op_size) = Self::get_operand(addr+offset as i32, op_size, addr_size, data[offset-1], op_offset, &data[offset..], e.clone())?;
                embedded_ops.push(ops);
                op_offset += op_size;
            }
            (embedded_ops, op_offset)
        } else {
            (embedded_ops, 0)
        };

        let bytes = Vec::from(&data[..offset+size]);
        let insn = Insn::new(mnemonic, operands, addr, bytes);

        Ok((insn, offset+size))
    }
}

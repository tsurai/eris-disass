use datatypes::*;
use util::*;
use failure::*;

pub(crate) fn get_effective_address(op_size: OperandSize, addr_size: OperandSize, data: &[u8]) -> Result<(EffectiveAddress, usize), Error> {
    let _mod = (data[0] & 0b11000000) >> 6;
    let r_m = data[0] & 0b00000111;
    let data = &data[1..];

    let (addr, size) = if _mod == 0b11 {
        (EffectiveAddress::Register(get_register_operand(op_size, r_m)), 1)
    } else {
        match addr_size {
            OperandSize::Bit16 => get_16bit_address(_mod, r_m, data, op_size),
            OperandSize::Bit32 => get_32bit_address(_mod, r_m, data, op_size)
                .context("failed to get 32bit address")?,
            _ => panic!("invalid address encoding"),
        }
    };

    Ok((addr, size))
}

pub(crate) fn get_register_operand(opsize: OperandSize, reg_op: u8) -> Register {
    use self::Register::*;

    let reg_op = reg_op & 0b00000111;

    match opsize {
        OperandSize::Bit8 => {
            match reg_op {
                0b000 => {
                    AL
                },
                0b001 => {
                    CL
                },
                0b010 => {
                    DL
                },
                0b011 => {
                    BL
                },
                0b100 => {
                    AH
                },
                0b101 => {
                    CH
                },
                0b110 => {
                    DH
                },
                0b111 => {
                    BH
                },
                _ => {
                    panic!("failed to parse ModRM")
                }
            }
        },
        OperandSize::Bit16 => {
            match reg_op {
                0b000 => {
                    AX
                },
                0b001 => {
                    CX
                },
                0b010 => {
                    DX
                },
                0b011 => {
                    BX
                },
                0b100 => {
                    SP
                },
                0b101 => {
                    BP
                },
                0b110 => {
                    SI
                },
                0b111 => {
                    DI
                },
                _ => {
                    panic!("failed to parse ModRM")
                }
            }
        },
        OperandSize::Bit32 => {
            match reg_op {
                0b000 => {
                    EAX
                },
                0b001 => {
                    ECX
                },
                0b010 => {
                    EDX
                },
                0b011 => {
                    EBX
                },
                0b100 => {
                    ESP
                },
                0b101 => {
                    EBP
                },
                0b110 => {
                    ESI
                },
                0b111 => {
                    EDI
                },
                _ => {
                    panic!("failed to parse ModRM")
                }
            }
        },
        OperandSize::Bit64 => {
            unimplemented!("64 bit mode")
        },
        OperandSize::Xmm128 => {
            match reg_op {
                0b000 => {
                    XMM0
                },
                0b001 => {
                    XMM1
                },
                0b010 => {
                    XMM2
                },
                0b011 => {
                    XMM3
                },
                0b100 => {
                    XMM4
                },
                0b101 => {
                    XMM5
                },
                0b110 => {
                    XMM6
                },
                0b111 => {
                    XMM7
                },
                _ => {
                    panic!("failed to parse ModRM")
                }
            }
        }
    }
}

fn get_sib_address(_mod: u8, data: &[u8]) -> Result<(Sib, usize), Error> {
    use self::Register::*;

    let scale = 2isize.pow(((data[0] & 0b11000000) >> 6) as u32) as u8;
    let index = (data[0] & 0b00111000) >> 3;
    let base = data[0] & 0b00000111;

    let index_reg = match index {
        0b000 => {
            EAX
        },
        0b001 => {
            ECX
        },
        0b010 => {
            EDX
        },
        0b011 => {
            EBX
        },
        0b100 => {
            bail!("invalid SIB index")
        },
        0b101 => {
            EBP
        },
        0b110 => {
            ESI
        },
        0b111 => {
            EDI
        },
        _ => {
            panic!("failed to parse SIB")
        }
    };

    let base_reg = match base {
        0b000 => {
            Some(EAX)
        },
        0b001 => {
            Some(ECX)
        },
        0b010 => {
            Some(EDX)
        },
        0b011 => {
            Some(EBX)
        },
        0b100 => {
            Some(ESP)
        },
        0b101 => {
            None
        },
        0b110 => {
            Some(ESI)
        },
        0b111 => {
            Some(EDI)
        },
        _ => {
            panic!("failed to parse SIB")
        }
    };

    if let Some(base_reg) = base_reg {
        match _mod {
            0b00 => {
                let sib = Sib::RegBase((scale, index_reg, base_reg));
                Ok((sib, 1))
            },
            0b01 => {
                let disp = data[1] as i8;
                let sib = Sib::RegBaseDisp((scale, index_reg, base_reg, Displacement::Disp8(disp)));
                Ok((sib, 2))
            },
            0b10 => {
                let disp = read_i16(&data[1..]);
                let sib = Sib::RegBaseDisp((scale, index_reg, base_reg, Displacement::Disp16(disp)));
                Ok((sib, 3))
            },
            0b11 => {
                let disp = read_i32(&data[1..]);
                let sib = Sib::RegBaseDisp((scale, index_reg, base_reg, Displacement::Disp32(disp)));
                Ok((sib, 5))
            },
            _ => {
                panic!("invalid SIB encoding")
            }
        }
    } else {
        match _mod {
            0b00 => {
                let base_disp = read_i32(&data[1..]);
                let sib = Sib::DispBase((scale, index_reg, Displacement::Disp32(base_disp)));
                Ok((sib, 5))
            },
            0b01 => {
                let disp = data[1] as i8;
                let sib = Sib::RegBaseDisp((scale, index_reg, EBP, Displacement::Disp8(disp)));
                Ok((sib, 2))

            },
            0b10 => {
                let disp = read_i32(&data[1..]);
                let sib = Sib::RegBaseDisp((scale, index_reg, EBP, Displacement::Disp32(disp)));
                Ok((sib, 5))

            },
            0b11 => {
                bail!("invalid baseless SIB encoding")
            },
            _ => {
                panic!("invalid SIB encoding")
            }
        }
    }
}

fn get_16bit_address(_mod: u8, r_m: u8, data: &[u8], op_size: OperandSize) -> (EffectiveAddress, usize) {
    use self::Displacement::*;
    use self::EffectiveAddress::*;
    use self::Register::*;

    let mut offset = 1;

    let rmn = match _mod {
        0b00 => {
            match r_m {
                0b000 => {
                    RegisterValue16((BX, SI, op_size))
                },
                0b001 => {
                    RegisterValue16((BX, DI, op_size))
                },
                0b010 => {
                    RegisterValue16((BP, SI, op_size))
                },
                0b011 => {
                    RegisterValue16((BP, DI, op_size))
                },
                0b100 => {
                    RegisterValue((SI, op_size))
                },
                0b101 => {
                    RegisterValue((DI, op_size))
                },
                0b110 => {
                    let disp = read_i16(data);
                    offset = 3;
                    Displacement((Disp16(disp), op_size))
                },
                0b111 => {
                    RegisterValue((BX, op_size))
                },
                _ => {
                    panic!("failed to parse ModRM")
                }
            }
        },
        0b01 => {
            offset = 2;
            let disp = data[0] as i8;

            match r_m {
                0b000 => {
                    DisplacedRegister16((BX, SI, Disp8(disp), op_size))
                },
                0b001 => {
                    DisplacedRegister16((BX, DI, Disp8(disp), op_size))
                },
                0b010 => {
                    DisplacedRegister16((BP, SI, Disp8(disp), op_size))
                },
                0b011 => {
                    DisplacedRegister16((BP, DI, Disp8(disp), op_size))
                },
                0b100 => {
                    DisplacedRegister((SI, Disp8(disp), op_size))
                },
                0b101 => {
                    DisplacedRegister((DI, Disp8(disp), op_size))
                },
                0b110 => {
                    DisplacedRegister((BP, Disp8(disp), op_size))
                },
                0b111 => {
                    DisplacedRegister((BX, Disp8(disp), op_size))
                },
                _ => {
                    panic!("failed to parse ModRM")
                }
            }
        },
        0b10 => {
            offset = 3;
            let disp = read_i16(data);
            match r_m {
                0b000 => {
                    DisplacedRegister16((BX, SI, Disp16(disp), op_size))
                },
                0b001 => {
                    DisplacedRegister16((BX, DI, Disp16(disp), op_size))
                },
                0b010 => {
                    DisplacedRegister16((BP, SI, Disp16(disp), op_size))
                },
                0b011 => {
                    DisplacedRegister16((BP, SI, Disp16(disp), op_size))
                },
                0b100 => {
                    DisplacedRegister((SI, Disp16(disp), op_size))
                },
                0b101 => {
                    DisplacedRegister((DI, Disp16(disp), op_size))
                },
                0b110 => {
                    DisplacedRegister((BP, Disp16(disp), op_size))
                },
                0b111 => {
                    DisplacedRegister((BX, Disp16(disp), op_size))
                },
                _ => {
                    panic!("failed to parse ModRM")
                }
            }
        },
        _ => {
            panic!("failed to parse ModRM")
        }
    };

    (rmn, offset)
}

fn get_32bit_address(_mod: u8, r_m: u8, data: &[u8], op_size: OperandSize) -> Result<(EffectiveAddress, usize), Error> {
    use self::Displacement::*;
    use self::EffectiveAddress::*;
    use self::Register::*;

    let mut offset = 1;

    let rmn = match _mod {
        0b00 => {
           match r_m {
                0b000 => {
                    RegisterValue((EAX, op_size))
                },
                0b001 => {
                    RegisterValue((ECX, op_size))
                },
                0b010 => {
                    RegisterValue((EDX, op_size))
                },
                0b011 => {
                    RegisterValue((EBX, op_size))
                },
                0b100 => {
                    let (sib, sib_size) = get_sib_address(_mod, data)
                        .context("failed to get SIB address")?;
                    offset = sib_size + 1;
                    EffectiveAddress::Sib((sib, op_size))
                },
                0b101 => {
                    let disp = read_i32(data);
                    offset = 5;
                    Displacement((Disp32(disp), op_size))
                },
                0b110 => {
                    RegisterValue((ESI, op_size))
                },
                0b111 => {
                    RegisterValue((EDI, op_size))
                },
                _ => {
                    panic!("failed to parse ModRM")
                }
            }
        },
        0b01 => {
            let disp = data[0] as i8;
            offset = 2;
            match r_m {
                0b000 => {
                    DisplacedRegister((EAX, Disp8(disp), op_size))
                },
                0b001 => {
                    DisplacedRegister((ECX, Disp8(disp), op_size))
                },
                0b010 => {
                    DisplacedRegister((EDX, Disp8(disp), op_size))
                },
                0b011 => {
                    DisplacedRegister((EBX, Disp8(disp), op_size))
                },
                0b100 => {
                    let (sib, sib_size) = get_sib_address(_mod, data)
                        .context("failed to get SIB address")?;
                    offset = sib_size + 1;
                    EffectiveAddress::Sib((sib, op_size))
                },
                0b101 => {
                    DisplacedRegister((EBP, Disp8(disp), op_size))
                },
                0b110 => {
                    DisplacedRegister((ESI, Disp8(disp), op_size))
                },
                0b111 => {
                    DisplacedRegister((EDI, Disp8(disp), op_size))
                },
                _ => {
                    panic!("failed to parse ModRM")
                }
            }
        },
        0b10 => {
           let disp = read_i32(data);
           offset = 5;
            match r_m {
                0b000 => {
                    DisplacedRegister((EAX, Disp32(disp), op_size))
                },
                0b001 => {
                    DisplacedRegister((ECX, Disp32(disp), op_size))
                },
                0b010 => {
                    DisplacedRegister((EDX, Disp32(disp), op_size))
                },
                0b011 => {
                    DisplacedRegister((EBX, Disp32(disp), op_size))
                },
                0b100 => {
                    let (sib, sib_size) = get_sib_address(_mod, data)
                        .context("failed to get SIB address")?;
                    offset = sib_size + 1;
                    EffectiveAddress::Sib((sib, op_size))
                },
                0b101 => {
                    DisplacedRegister((EBP, Disp32(disp), op_size))
                },
                0b110 => {
                    DisplacedRegister((ESI, Disp32(disp), op_size))
                },
                0b111 => {
                    DisplacedRegister((EDI, Disp32(disp), op_size))
                },
                _ => {
                    panic!("failed to parse ModRM")
                }
            }
        },
        _ => {
            panic!("failed to parse ModRM")
        }
    };

    Ok((rmn, offset))
}


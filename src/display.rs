use datatypes::*;
use instruction::Insn;
use std::fmt;

impl fmt::Display for OperandSize {
     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match *self {
            OperandSize::Bit8 => "BYTE",
            OperandSize::Bit16 => "WORD",
            OperandSize::Bit32 => "DWORD",
            OperandSize::Bit64 => "QWORD",
            OperandSize::Xmm128 => "XMMWORD",
        };

        write!(f, "{}", name)
    }
}

impl fmt::Display for RelativeAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.to_inner())
    }
}

fn get_sign(number: i32) -> char {
    if number.is_negative() {
        '-'
    } else {
        '+'
    }
}

impl fmt::Display for Displacement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.to_inner())
    }
}

impl fmt::Debug for Displacement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let disp = self.to_inner();
        let sign = get_sign(disp);

        write!(f, "{}{:#x}", sign, disp * disp.signum())
    }
}

impl fmt::Display for Sib {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Sib::RegBase((scale, ref index, ref base)) => {
                write!(f, "[{}+{}*{}]", base, index, scale)
            },
            &Sib::DispBase((scale, ref index, ref disp)) => {
                write!(f, "[{}*{}{:?}]", index, scale, disp)
            },
            &Sib::RegBaseDisp((scale, ref index, ref base, ref disp)) => {
                write!(f, "[{}+{}*{}{:?}]", base, index, scale, disp)
            }
        }
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Register::*;

        let name = match *self {
            AL => "al",
            AH => "ah",
            AX => "ax",
            EAX => "eax",
            CL => "cl",
            CH => "ch",
            CX => "cx",
            ECX => "ecx",
            DL => "dl",
            DH => "dh",
            DX => "dx",
            EDX => "edx",
            BL => "bl",
            BH => "bh",
            BX => "bx",
            SI => "si",
            DI => "di",
            BP => "bp",
            EBX => "ebx",
            BPL => "bpl",
            SPL => "spl",
            DIL => "dil",
            SIL => "sil",
            ESP => "esp",
            EBP => "ebp",
            ESI => "esi",
            EDI => "edi",
            CS => "cs",
            DS => "ds",
            SS => "ss",
            SP => "sp",
            ES => "es",
            XMM0 => "xmm0",
            XMM1 => "xmm1",
            XMM2 => "xmm2",
            XMM3 => "xmm3",
            XMM4 => "xmm4",
            XMM5 => "xmm5",
            XMM6 => "xmm6",
            XMM7 => "xmm7",
        };
        write!(f, "{}", name)
    }
}

impl fmt::Display for EffectiveAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::EffectiveAddress::*;

        match self {
            &Register(ref reg) => {
                write!(f, "{}", reg)
            },
            &RegisterValue((ref reg, ref size)) => {
                write!(f, "{} PTR [{}]", size, reg)
            },
            &RegisterValue16((ref reg1, ref reg2, ref size)) => {
                write!(f, "{} PTR [{}+{}]", size, reg1, reg2)
            },
            &Sib((ref sib, ref size)) => {
                write!(f, "{} PTR {}", size, sib)
            }
            &Displacement((ref disp, ref size)) => {
                write!(f, "{} PTR [{}]", size, disp)
            },
            &DisplacedRegister((ref reg, ref disp, ref size)) => {
                write!(f, "{} PTR [{}{:?}]", size, reg, disp)
            },
            &DisplacedRegister16((ref reg1, ref reg2, ref disp, ref size)) => {
                write!(f, "{} PTR [{}+{}{:?}]", size, reg1, reg2, disp)
            },
        }
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Operand::*;

        match self {
            &EffectiveAddress(ref v) => write!(f, "{}", v),
            &Register(ref v) => write!(f, "{}", v),
            &RelativeAddress(ref v) => write!(f, "{}", v),
            &ImmediateValue(ref v) => write!(f, "{:#x}", v.to_inner()),
        }
    }
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ops = self.operands.iter().map(|x| format!("{}", x)).collect::<Vec<String>>().as_slice().join(", ");
        let bytes = self.bytes.iter().map(|x| format!("{:02x}", x)).collect::<Vec<String>>().as_slice().join(" ");

        write!(f, "{:>#9x}:    {:20}\t{}\t{}", self.addr, bytes, self.mnemonic, ops)
    }
}

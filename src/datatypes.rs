#![allow(dead_code)]

#![allow(non_camel_case_types)]
pub type OperandList = Vec<Operand>;

#[derive(PartialEq,Clone,Copy)]
pub enum BitMode {
    X86_32,
    x86_64,
}

#[derive(PartialEq,Clone,Copy)]
pub enum OperandSize {
    Bit8,
    Bit16,
    Bit32,
    Bit64,
    Xmm128,
}

#[derive(PartialEq,Clone,Copy)]
#[repr(u16)]
pub enum Prefix {
    None                = 0,
    // forces an operation that ensures exclusive use of shared memory
    Lock                = 1,
    // REPNE/REPNZ if applied to string or input/output instructions
    // BOUND if the following conditions are true:
    // * CPUID.(EAX=07h, ECX=0):EBX.MPX[bit 14] is set
    // * BNDCFGU.EN and/or IA32_BNDCFGS.EN is set
    // * precedes a near CALL, near RET, near JMP or near JCC
    RepnBound           = 2,
    // mandatory prefix for POPCNT, LZCNT and ADOX
    Rep                 = 4,
    OverrideCs          = 8,
    OverrideSs          = 16,
    OverrideDs          = 32,
    OverrideEs          = 64,
    OverrideFs          = 128,
    OverrideGs          = 256,
    // 0x66 allows switching between 16- and 32-bit operand sizes
    OverrideOpSize      = 512,
    // 0x67 allows switching between 16- and 32-bit address sizes
    OverrideAddrSize    = 1024,
}

#[derive(PartialEq,Clone)]
pub enum Register {
    AL,
    AH,
    AX,
    EAX,
    CL,
    CH,
    CX,
    ECX,
    DL,
    DH,
    DX,
    EDX,
    BL,
    BH,
    BX,
    EBX,
    BP,
    BPL,
    SP,
    SPL,
    DIL,
    SIL,
    ESP,
    EBP,
    // index registers
    SI,
    DI,
    ESI,
    EDI,
    // segment register
    CS,
    DS,
    SS,
    ES,
    // SSE
    XMM0,
    XMM1,
    XMM2,
    XMM3,
    XMM4,
    XMM5,
    XMM6,
    XMM7,
}

#[derive(Clone)]
pub enum InsnEncoding {
    R8,
    R16,
    R32,
    R64,
    Rel8,
    Rel16,
    Rel32,
    Imm8,
    Imm16,
    Imm32,
    Imm64,
    Rm8,
    Rm16,
    Rm32,
    Rm64,
    M8,
    M16,
    M32,
    M64,
    OpXMM,
    StaticR(Register),
    OpR,
}
pub enum RelativeAddress {
    Rel8(i8),
    Rel16(i16),
    Rel32(i32),
}

impl RelativeAddress {
    pub fn to_inner(&self) -> i32 {
        use self::RelativeAddress::*;

        match self {
            &Rel8(x) => x as i32,
            &Rel16(x) => x as i32,
            &Rel32(x) => x,
        }
    }
}

pub enum ImmediateValue {
    Imm8(i8),
    Imm16(i16),
    Imm32(i32),
}

impl ImmediateValue {
    pub fn to_inner(&self) -> i32 {
        use self::ImmediateValue::*;

        match self {
            &Imm8(x) => x as i32,
            &Imm16(x) => x as i32,
            &Imm32(x) => x,
        }
    }
}

pub enum Displacement {
    Disp8(i8),
    Disp16(i16),
    Disp32(i32),
}

impl Displacement {
    pub fn to_inner(&self) -> i32 {
        use self::Displacement::*;

        match self {
            &Disp8(x) => x as i32,
            &Disp16(x) => x as i32,
            &Disp32(x) => x,
        }
    }
}

pub enum Sib {
    RegBase((u8, Register, Register)),
    DispBase((u8, Register, Displacement)),
    RegBaseDisp((u8, Register, Register, Displacement)),
}

pub enum EffectiveAddress {
    Register(Register),
    RegisterValue((Register, OperandSize)),
    RegisterValue16((Register, Register, OperandSize)),
    Displacement((Displacement, OperandSize)),
    DisplacedRegister((Register, Displacement, OperandSize)),
    DisplacedRegister16((Register, Register, Displacement, OperandSize)),
    Sib((Sib, OperandSize)),
}

impl EffectiveAddress {
    pub fn is_memory_addr(&self) -> bool {
        match self {
            EffectiveAddress::Register(_) => false,
            _ => true,
        }
    }
}

pub enum Operand {
    RelativeAddress(RelativeAddress),
    ImmediateValue(ImmediateValue),
    Register(Register),
    EffectiveAddress(EffectiveAddress),
}

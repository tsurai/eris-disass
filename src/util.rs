use datatypes::*;

pub fn read_u16(data: &[u8]) -> u16 {
    (data[0] as u16) | ((data[1] as u16) << 8)
}

pub fn read_i16(data: &[u8]) -> i16 {
    read_u16(data) as i16
}

pub fn read_imm16(data: &[u8]) -> ImmediateValue {
    ImmediateValue::Imm16(read_i16(data))
}

pub fn read_u32(data: &[u8]) -> u32 {
    (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16) | ((data[3] as u32) << 24)
}

pub fn read_i32(data: &[u8]) -> i32 {
    read_u32(data) as i32
}

pub fn read_imm32(data: &[u8]) -> ImmediateValue {
    ImmediateValue::Imm32(read_i32(data))
}

pub fn get_override_size(mode: BitMode, prefix: u16) -> (OperandSize, OperandSize) {
    let is_op_overridden = (prefix & Prefix::OverrideOpSize as u16) != 0;
    let is_addr_overridden = (prefix & Prefix::OverrideAddrSize as u16) != 0;

    let op_size = if mode == BitMode::X86_32 {
        if is_op_overridden {
            OperandSize::Bit16
        } else {
            OperandSize::Bit32
        }
    } else {
        unimplemented!("64 bit mode");
    };

    let addr_size = if mode == BitMode::X86_32 {
        if is_addr_overridden {
            OperandSize::Bit16
        } else {
            OperandSize::Bit32
        }
    } else {
        unimplemented!("64 bit mode");
    };

    (op_size, addr_size)
}

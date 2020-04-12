//use std::error::Error;
use crate::FixUpKind::{Const16HI, Const16LO, PcRel16};
use crate::InstFormat::{FromatBO, FormatR, FormatRI, FormatRRI};
use std::fs::File;
use std::io::prelude::*;

pub struct Config {
    pub filename: String,
    pub flags: u32,
}

#[derive(Debug)]
pub struct ASContext {
    pub symbol_table: Vec<Symbol>,
    pub in_data_section: bool,
    pub in_text_section: bool,
    pub data_section_size: u32,
    pub current_inst_address: u32,
    pub fix_ups: Vec<FixUp>,
}

#[derive(Debug)]
pub struct Symbol {
    pub name: String,
    pub position: u32,
    pub in_data_section: bool,
}

#[derive(Debug, PartialEq)]
pub enum FixUpKind {
    Const16LO,
    Const16HI,
    PcRel16,
}

#[derive(Debug)]
pub struct FixUp {
    pub kind: FixUpKind,
    pub position: u32,
    pub symbol: String,
}

pub struct Inst {
    pub mnemonic: String,
    pub operands: Vec<Operand>,
}

pub enum Operand {
    Register(u8),
    Immediate(i32),
    Memory(u8, i32),
    SymbolExpression(String),
}

// RRR type: <mnemonic> r[c], r[a], r[b]
//      | c |   -   | b | a | opcode[7:0] |
//      31  27      15  11  7             0

// RRI type: <mnemonic> r[c], r[a], imm
//      | c | imm[15:0] | a | opcode[7:0] |
//      31  27          11  7             0

// RI type: <mnemonic> r[c], imm
//      | c | imm[15:0] | - | opcode[7:0] |
//      31  27          11  7             0

// BO type: <mnemonic> r[b], imm(r[a])
//      | imm[15:0] | b | a | opcode[7:0] |
//      31          15  11  7             0

#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum InstFormat {
    FormatR,
    FormatRRI,
    FormatRI,
    FromatBO,
}

const INSTR_COUNT: usize = 9;
static INSTRUCTIONS: [(&str, u8, InstFormat); INSTR_COUNT] = [
    ("add", 0b0000_0000, FormatR),
    ("addi", 0b0000_0001, FormatRRI),
    ("div", 0b0000_0000, FormatR),
    ("ldw", 0b0000_0010, FromatBO),
    ("jne", 0b0000_0011, FormatRRI),
    ("movh", 0b0000_0100, FormatRI),
    ("mul", 0b0000_0111, FormatR),
    ("stw", 0b0000_0101, FromatBO),
    ("xor", 0b0000_0110, FormatR),
];

impl Config {
    pub fn new(args: &[String]) -> Result<Config, &'static str> {
        if args.len() < 2 {
            return Err("not enough arguments");
        }
        let filename = args[1].clone();
        let flags: u32 = 0;
        Ok(Config { filename, flags })
    }
}

impl ASContext {
    pub fn new() -> ASContext {
        let symbol_table: Vec<Symbol> = Vec::new();
        let in_data_section: bool = false;
        let in_text_section: bool = false;
        let data_section_size: u32 = 0;
        let current_inst_address: u32 = 0;
        let fix_ups: Vec<FixUp> = Vec::new();
        ASContext {
            symbol_table,
            in_data_section,
            in_text_section,
            data_section_size,
            current_inst_address,
            fix_ups,
        }
    }
}

pub fn parse_directive(line: &str, as_ctx: &mut ASContext) {
    let pieces: Vec<&str> = line.split(" ").collect();
    let directive: &str = pieces[0];

    match directive {
        "data" => {
            as_ctx.in_data_section = true;
            as_ctx.in_text_section = false;
        }
        "text" => {
            as_ctx.in_data_section = false;
            as_ctx.in_text_section = true;
        }
        "word" => {
            if pieces.len() < 2 {
                panic!("Operands is missing");
            }
            let value = match pieces[1].parse::<u32>() {
                Ok(i) => i,
                Err(_) => {
                    panic!("Operand must be an an unsigned integer");
                }
            };
            if as_ctx.in_data_section {
                as_ctx.data_section_size += value * 4;
            }
        }
        _ => panic!("Unknown directive"),
    }
}

pub fn parse_label(line: &str, as_ctx: &mut ASContext) -> bool {
    let pieces: Vec<&str> = line.split(" ").collect();
    let label: &str = pieces[0];
    let label = label.trim_end();

    if !label.ends_with(":") {
        return false;
    }
    if !label[..label.len() - 1].chars().all(char::is_alphanumeric) {
        return false;
    }

    let label = &label[..label.len() - 1];

    let mut symbol = Symbol {
        name: String::from(label),
        position: 0,
        in_data_section: as_ctx.in_data_section,
    };
    if as_ctx.in_data_section {
        symbol.position = as_ctx.data_section_size;
    } else if as_ctx.in_text_section {
        symbol.position = as_ctx.current_inst_address;
    } else {
        return false;
    }
    as_ctx.symbol_table.push(symbol);
    true
}

// for now only parsing simple symbols
pub fn parse_symbol_expression(sym_exp: &str, operand: &mut Operand) -> bool {
    if sym_exp.chars().all(char::is_alphanumeric) {
        *operand = Operand::SymbolExpression(String::from(sym_exp));
        return true;
    }
    false
}

// parsing operands like "<constant>(<register>)" OR "(<register>)" in this
// case the immediate is 0 implicitly
pub fn parse_memory_operand(mem_op: &str, operand: &mut Operand) -> bool {
    let mut immediate = 0;
    let mut register: u8 = 0;
    let mut start_pos = 0;
    if mem_op.starts_with("(") {
        immediate = 0;
    } else {
        // parse the immediate part
        match mem_op.find("(") {
            Some(i) => start_pos = i,
            None => return false,
        };
        if !parse_immediate(&mem_op[..start_pos], operand) {
            return false;
        }
        if let Operand::Immediate(imm) = operand {
            immediate = *imm;
        }
    }
    // parse the register
    let end_pos;
    match mem_op.find(")") {
        Some(i) => end_pos = i,
        None => return false,
    };
    if !parse_register(&mem_op[start_pos + 1..end_pos], operand) {
        return false;
    }
    if let Operand::Register(reg) = operand {
        register = *reg;
    }
    *operand = Operand::Memory(register, immediate);
    true
}

pub fn parse_immediate(immediate: &str, operand: &mut Operand) -> bool {
    let immediate = match immediate.parse::<i32>() {
        Ok(i) => i,
        Err(_) => {
            return false;
        }
    };
    *operand = Operand::Immediate(immediate);
    true
}

pub fn parse_register(register: &str, operand: &mut Operand) -> bool {
    if !register.starts_with("%") && !register[1..].to_lowercase().starts_with("r") {
        return false;
    }
    let reg_number = match register[2..].parse::<u8>() {
        Ok(i) => i,
        Err(_) => {
            return false;
        }
    };
    if reg_number > 15 {
        return false;
    }
    *operand = Operand::Register(reg_number);
    true
}

pub fn parse_operands(operands: &str) -> Vec<Operand> {
    let mut operands = operands.trim_start();
    // remove comments
    match operands.find("#") {
        Some(i) => operands = &operands[..i],
        None => (),
    };
    let operands: Vec<&str> = operands.split(",").collect();
    let mut parsed_operands: Vec<Operand> = Vec::new();

    for operand in operands {
        let operand = operand.trim_start();
        let operand = operand.split_whitespace().next().expect("O-oo");
        println!("\t>> {}", operand);
        let mut parsed_operand: Operand = Operand::Register(0);

        if parse_register(operand, &mut parsed_operand)
            || parse_immediate(operand, &mut parsed_operand)
            || parse_memory_operand(operand, &mut parsed_operand)
            || parse_symbol_expression(operand, &mut parsed_operand)
        {
            parsed_operands.push(parsed_operand);
        } else {
            println!("Error: Operand parsing: {}", operand);
        }
    }
    for operand in &parsed_operands {
        match operand {
            Operand::Register(i) => print!("[reg:{}]", i),
            Operand::Immediate(i) => print!("[imm:{}]", i),
            Operand::Memory(i, j) => print!("[reg:{} + imm:{}]", i, j),
            Operand::SymbolExpression(s) => print!("[sym:{}]", s),
        }
    }
    if !parsed_operands.is_empty() {
        println!(" ");
    }
    parsed_operands
}

#[allow(unused_assignments)]
pub fn parse_instruction(inst: &str, as_ctx: &mut ASContext) -> u32 {
    let pieces: Vec<&str> = inst.split(" ").collect();
    let instruction: &str = pieces[0];
    let mut operands: Vec<Operand> = Vec::new();
    let mut inst_index: usize = INSTR_COUNT + 1;
    let mut opcode = 0u32;

    match instruction {
        "add" | "addi" | "div" | "jne" | "ldw" | "movh" | "mul"| "stw" | "xor" => {
            let size = instruction.chars().count();
            operands = parse_operands(&inst[size..]);
        }
        _ => (),
    }
    for (idx, (name, _, _)) in INSTRUCTIONS.iter().enumerate() {
        if *name == instruction {
            inst_index = idx;
            break;
        }
    }
    if inst_index == INSTR_COUNT + 1 {
        panic!(
            "Instruction not found at line {}",
            as_ctx.current_inst_address
        );
    }
    match INSTRUCTIONS[inst_index].2 {
        FormatR => opcode = get_encoding_type_r(inst_index, operands, as_ctx),
        FormatRRI => opcode = get_encoding_type_rri(inst_index, &mut operands, as_ctx),
        FormatRI => opcode = get_encoding_type_ri(inst_index, &mut operands, as_ctx),
        FromatBO => opcode = get_encoding_type_m(inst_index, operands, as_ctx),
    }
    as_ctx.current_inst_address += 4;
    opcode
}

#[allow(unused_assignments)]
pub fn get_encoding_type_r(
    inst_index: usize,
    operands: Vec<Operand>,
    as_ctx: &mut ASContext,
) -> u32 {
    use std::mem::discriminant;
    let mut opcode = 0;

    if operands.len() != 3 {
        panic!("Operand number mismatch {}", as_ctx.current_inst_address);
    }
    let reg_type = Operand::Register(0);

    if discriminant(&operands[0]) != discriminant(&reg_type)
        || discriminant(&operands[1]) != discriminant(&reg_type)
        || discriminant(&operands[2]) != discriminant(&reg_type)
    {
        panic!("Operand type mismatch {}", as_ctx.current_inst_address);
    }
    opcode = INSTRUCTIONS[inst_index].1 as u32; // adding opcode
    if let Operand::Register(register_num) = operands[0] {
        opcode |= (register_num as u32) << 28;
    }
    if let Operand::Register(register_num) = operands[1] {
        opcode |= (register_num as u32) << 8;
    }
    if let Operand::Register(register_num) = operands[2] {
        opcode |= (register_num as u32) << 12;
    }
    opcode
}

#[allow(unused_assignments)]
pub fn get_encoding_type_rri(
    inst_index: usize,
    operands: &mut Vec<Operand>,
    as_ctx: &mut ASContext,
) -> u32 {
    use std::mem::discriminant;
    let mut opcode = 0;

    if operands.len() != 3 {
        panic!("Operand number mismatch {}", as_ctx.current_inst_address);
    }
    let reg_type = Operand::Register(0);
    let imm_type = Operand::Immediate(0);
    let sym_type = Operand::SymbolExpression(String::from(""));

    if discriminant(&operands[0]) != discriminant(&reg_type)
        || discriminant(&operands[1]) != discriminant(&reg_type)
        || (discriminant(&operands[2]) != discriminant(&imm_type)
            && discriminant(&operands[2]) != discriminant(&sym_type))
    {
        panic!("Operand type mismatch {}", as_ctx.current_inst_address);
    }
    opcode = INSTRUCTIONS[inst_index].1 as u32; // adding opcode
    if let Operand::Register(register_num) = operands[0] {
        opcode |= (register_num as u32) << 28;
    }
    if let Operand::Register(register_num) = operands[1] {
        opcode |= (register_num as u32) << 8;
    }
    if discriminant(&operands[2]) == discriminant(&imm_type) {
        if let Operand::Immediate(imm) = operands[2] {
            opcode |= ((imm as u32) & 0xFFFFFu32) << 12;
        }
    } else {
        let mut fix_up;
        let mut symbol: &str = "";

        if let Operand::SymbolExpression(s) = &operands[2] {
            symbol = s;
        }

        fix_up = FixUp {
            kind: PcRel16,
            position: as_ctx.current_inst_address,
            symbol: String::from(symbol),
        };

        match INSTRUCTIONS[inst_index].0 {
            "jne" => fix_up.kind = PcRel16,
            _ => fix_up.kind = Const16LO,
        }
        operands[2] = Operand::Immediate(0);
        as_ctx.fix_ups.push(fix_up);
    }
    opcode
}

#[allow(unused_assignments)]
pub fn get_encoding_type_ri(
    inst_index: usize,
    operands: &mut Vec<Operand>,
    as_ctx: &mut ASContext,
) -> u32 {
    use std::mem::discriminant;
    let mut opcode = 0;

    if operands.len() != 2 {
        panic!("Operand number mismatch {}", as_ctx.current_inst_address);
    }
    let reg_type = Operand::Register(0);
    let imm_type = Operand::Immediate(0);
    let sym_type = Operand::SymbolExpression(String::from(""));

    if discriminant(&operands[0]) != discriminant(&reg_type)
        || (discriminant(&operands[1]) != discriminant(&imm_type)
            && discriminant(&operands[1]) != discriminant(&sym_type))
    {
        panic!("Operand type mismatch {}", as_ctx.current_inst_address);
    }
    opcode = INSTRUCTIONS[inst_index].1 as u32; // adding opcode
    if let Operand::Register(register_num) = operands[0] {
        opcode |= (register_num as u32) << 28;
    }
    if discriminant(&operands[1]) == discriminant(&imm_type) {
        if let Operand::Immediate(imm) = operands[1] {
            opcode |= ((imm as u32) & 0xFFFFFu32) << 12;
        }
    } else {
        let mut symbol: &str = "";

        if let Operand::SymbolExpression(s) = &operands[1] {
            symbol = s;
        }

        let fix_up = FixUp {
            kind: Const16HI,
            position: as_ctx.current_inst_address,
            symbol: String::from(symbol),
        };
        operands[1] = Operand::Immediate(0);
        as_ctx.fix_ups.push(fix_up);
    }
    opcode
}

#[allow(unused_assignments)]
pub fn get_encoding_type_m(
    inst_index: usize,
    operands: Vec<Operand>,
    as_ctx: &mut ASContext,
) -> u32 {
    use std::mem::discriminant;
    let mut opcode = 0;

    if operands.len() != 2 {
        panic!("Operand number mismatch {}", as_ctx.current_inst_address);
    }

    let reg_type = Operand::Register(0);
    let mem_type = Operand::Memory(0, 0);

    if discriminant(&operands[0]) != discriminant(&reg_type)
        || discriminant(&operands[1]) != discriminant(&mem_type)
    {
        panic!("Operand type mismatch {}", as_ctx.current_inst_address);
    }
    opcode = INSTRUCTIONS[inst_index].1 as u32; // adding opcode
    if let Operand::Register(register_num) = operands[0] {
        opcode |= (register_num as u32) << 12;
    }
    if let Operand::Memory(register_num, imm) = operands[1] {
        opcode |= (register_num as u32) << 8;
        opcode |= ((imm as u32) & 0xFFFFFu32) << 16;
    }
    opcode
}

pub fn resolve_fix_ups(result: &mut Vec<u32>, as_ctx: &ASContext) {
    for fix_up in &as_ctx.fix_ups {
        let mut found = false;
        for symbol_entry in &as_ctx.symbol_table {
            if fix_up.symbol == symbol_entry.name {
                found = true;
                let value: u32;

                if symbol_entry.in_data_section {
                    value = symbol_entry.position;
                    println!("In data section");
                } else {
                    value = as_ctx.data_section_size + symbol_entry.position;
                    println!("In text section");
                }
                println!("Fixup value: {}", value);
                match fix_up.kind {
                    Const16LO => result[(fix_up.position / 4) as usize] |= value << 12,
                    Const16HI => result[(fix_up.position / 4) as usize] |= (value >> 16) << 12,
                    PcRel16 => result[(fix_up.position / 4) as usize] |= (value >> 2) << 12,
                }
            }
        }
        if !found {
            panic!("Undefined reference to '{}'", fix_up.symbol);
        }
    }
}

pub fn emulate_program(program: &Vec<u32>, as_ctx: ASContext) {
    let mut memory: Vec<u32> = vec![0; 2048];
    let mut reg_bank: Vec<u32> = vec![0; 16];
    let data_section_size = (as_ctx.data_section_size / 4) as usize;
    let mut pc: u32 = data_section_size as u32;

    // loading the program into memory
    for (idx, i) in program.iter().enumerate() {
        memory[idx + data_section_size] = *i;
    }

    loop {
        let instruction = memory[pc as usize];
        pc += 1;
        let current_opcode: u8 = (instruction & 0xff) as u8;
        let mut inst_index = INSTR_COUNT + 1;

        // finding the instruction index
        for (idx, (_, op_code, _)) in INSTRUCTIONS.iter().enumerate() {
            if current_opcode == *op_code {
                inst_index = idx;
            }
        }
        if inst_index == INSTR_COUNT + 1 {
            panic!("Unknown Instruction: {:#010x}", instruction);
        }

        // decode and execute
        match INSTRUCTIONS[inst_index].2 {
            FormatR => {
                let dest = (instruction >> 28) as usize;
                let left_op = ((instruction >> 8) & 0xf) as usize;
                let right_op = ((instruction >> 12) & 0xf) as usize;

                match INSTRUCTIONS[inst_index].0 {
                    "add" => reg_bank[dest] = reg_bank[left_op] + reg_bank[right_op],
                    "div" => reg_bank[dest] = reg_bank[left_op] / reg_bank[right_op],
                    "mul" => reg_bank[dest] = reg_bank[left_op] * reg_bank[right_op],
                    "xor" => reg_bank[dest] = reg_bank[left_op] ^ reg_bank[right_op],
                    _ => panic!(
                        "Unknown FormatR instruction: {}",
                        INSTRUCTIONS[inst_index].0
                    ),
                }
            }
            FormatRRI => {
                let dest = (instruction >> 28) as usize;
                let left_op = ((instruction >> 8) & 0xf) as usize;
                let right_op = ((instruction >> 12) & 0xffff) as i16;

                match INSTRUCTIONS[inst_index].0 {
                    "addi" => reg_bank[dest] = (reg_bank[left_op] as i32 + right_op as i32) as u32,
                    "jne" => {
                        if reg_bank[dest] != reg_bank[left_op] {
                            pc = right_op as u32;
                        }
                    }
                    _ => panic!(
                        "Unknown FormatRRI instruction: {}",
                        INSTRUCTIONS[inst_index].0
                    ),
                }
            }
            FormatRI => {
                let dest = (instruction >> 28) as usize;
                let src_op = (((instruction >> 12) & 0xffff) << 16) as u32;

                match INSTRUCTIONS[inst_index].0 {
                    "movh" => reg_bank[dest] = src_op,
                    _ => panic!(
                        "Unknown FormatRI instruction: {}",
                        INSTRUCTIONS[inst_index].0
                    ),
                }
            }
            FromatBO => {
                let dest_src = ((instruction >> 12) & 0xf) as usize;
                let base = ((instruction >> 8) & 0xf) as usize;
                let offset = (((instruction >> 16) & 0xffff) as i16) as i32;

                match INSTRUCTIONS[inst_index].0 {
                    "ldw" => {
                        reg_bank[dest_src] =
                            memory[((reg_bank[base] >> 2) as i32 + (offset >> 2)) as usize]
                    }
                    "stw" => {
                        memory[((reg_bank[base] >> 2) as i32 + (offset >> 2)) as usize] =
                            reg_bank[dest_src]
                    }
                    _ => panic!(
                        "Unknown FromatBO instruction: {}",
                        INSTRUCTIONS[inst_index].0
                    ),
                }
            }
        }
        println!("pc: {}, inst: {}", pc, INSTRUCTIONS[inst_index].0);
        println!("+----------+-----------+-----------+-----------+");
        for i in 0..4 {
            for j in 0..4 {
                print!("{:#010x}\t", reg_bank[i * 4 + j]);
            }
            println!();
        }
        println!("+----------+-----------+-----------+-----------+");
        if pc as usize >= data_section_size + program.len() {
            println!("\n\n\t\t###############################");
            println!("\t\t# Program execution finished. #");
            println!("\t\t###############################");
            println!("\n\t\t\tRegister bank content\n");
            println!("+----------+-----------+-----------+-----------+");
            for i in 0..4 {
                for j in 0..4 {
                    print!("{:#010x}\t", reg_bank[i * 4 + j]);
                }
                println!();
            }

            println!("+----------+-----------+-----------+-----------+");
            println!("\n\t\t\tMemory content\n");
            println!("+----------+-----------+-----------+-----------+");
            for i in 0..10 {
                for j in 0..4 {
                    print!("{:#010x}\t", memory[i * 4 + j]);
                }
                println!();
            }
            println!("+----------+-----------+-----------+-----------+");

            break;
        }
    }
}

pub fn assembler_main(input: &str) {
    let mut as_ctx = ASContext::new();
    let mut result: Vec<u32> = Vec::new();

    for line in input.lines() {
        let line = line.trim_start();
        println!(">> {}", line);

        if line.starts_with('#') || line.is_empty() {
            continue;
        } else if line.starts_with('.') {
            parse_directive(&line[1..], &mut as_ctx);
        } else if line.contains(":") {
            parse_label(line, &mut as_ctx);
        } else {
            result.push(parse_instruction(line, &mut as_ctx));
        }
    }
    resolve_fix_ups(&mut result, &as_ctx);
    println!("\n+---- Resulting binary code ----+\n");
    for u in &result {
        println!("\t{:#010x}", *u);
    }

    emulate_program(&result, as_ctx);
}

pub fn run(config: Config) {
    let mut f = File::open(config.filename).expect("file not found");

    let mut contents = String::new();
    f.read_to_string(&mut contents)
        .expect("something went wrong reading the file");

    println!("Read in...\n{}", contents);
    assembler_main(&contents);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_register_parsing() {
        let query = "%r0";
        let mut reg_num = 255u8;
        let mut operand: Operand = Operand::Register(reg_num);
        let success = parse_register(query, &mut operand);
        if let Operand::Register(reg) = &operand {
            reg_num = *reg;
        }
        assert!(success);
        assert_eq!(reg_num, 0);
    }

    #[test]
    fn test_invalid_register_parsing_with_whitespace() {
        let query = "  %r0  ";
        let mut reg_num = 255u8;
        let mut operand: Operand = Operand::Register(reg_num);
        let success = parse_register(query, &mut operand);
        if let Operand::Register(reg) = &operand {
            reg_num = *reg;
        }
        assert!(!success);
        assert_ne!(reg_num, 0);
    }

    #[test]
    fn test_valid_immediate_parsing() {
        let query = "-1234";
        let mut imm = 0;
        let mut operand: Operand = Operand::Immediate(imm);
        let success = parse_immediate(query, &mut operand);
        if let Operand::Immediate(i) = &operand {
            imm = *i;
        }
        assert!(success);
        assert_eq!(imm, -1234);
    }

    #[test]
    fn test_valid_immediate_parsing_big_pos_num() {
        let query = "50000";
        let mut imm = 0;
        let mut operand: Operand = Operand::Immediate(imm);
        let success = parse_immediate(query, &mut operand);
        if let Operand::Immediate(i) = &operand {
            imm = *i;
        }
        assert!(success);
        assert_eq!(imm, 50000);
    }

    #[test]
    fn test_invalid_immediate_parsing() {
        let query = "foo";
        let mut imm = 0;
        let mut operand: Operand = Operand::Immediate(imm);
        let success = parse_immediate(query, &mut operand);
        if let Operand::Immediate(i) = &operand {
            imm = *i;
        }
        assert!(!success);
        assert_eq!(imm, 0);
    }

    #[test]
    fn test_valid_memory_operand_parsing() {
        let query = "1024(%r4)";
        let mut imm = 0;
        let mut reg_num = 0u8;
        let mut operand: Operand = Operand::Memory(reg_num, imm);
        let success = parse_memory_operand(query, &mut operand);
        if let Operand::Memory(r, i) = &operand {
            reg_num = *r;
            imm = *i;
        }
        assert!(success);
        assert_eq!(reg_num, 4);
        assert_eq!(imm, 1024);
    }

    #[test]
    fn test_valid_memory_operand_parsing_omitted_immediate() {
        let query = "(%r4)";
        let mut imm = -1;
        let mut reg_num = 0u8;
        let mut operand: Operand = Operand::Memory(reg_num, imm);
        let success = parse_memory_operand(query, &mut operand);
        if let Operand::Memory(r, i) = &operand {
            reg_num = *r;
            imm = *i;
        }
        assert!(success);
        assert_eq!(reg_num, 4);
        assert_eq!(imm, 0);
    }

    #[test]
    fn test_parse_instruction_type_r() {
        let instr = "xor %r12, %r10, %r11";
        let mut as_ctx = ASContext::new();
        let encode = parse_instruction(instr, &mut as_ctx);

        assert_eq!(encode, 0xc0_00_ba_06);
    }

    #[test]
    fn test_parse_instruction_type_i_ri() {
        let instr = "movh %r14, 65520";
        let mut as_ctx = ASContext::new();
        let encode = parse_instruction(instr, &mut as_ctx);

        assert_eq!(encode, 0xef_ff_00_04);

        let instr = "movh %r14, foo";
        let encode = parse_instruction(instr, &mut as_ctx);

        assert_eq!(encode, 0xe0_00_00_04);
        assert_eq!(as_ctx.fix_ups[0].kind, Const16LO);
    }

    #[test]
    fn test_parse_instruction_type_i_rri() {
        let instr = "addi %r14, %r7, 2047";
        let mut as_ctx = ASContext::new();
        let encode = parse_instruction(instr, &mut as_ctx);

        assert_eq!(encode, 0xe0_7f_f7_01);

        let instr = "addi %r14, %r7, foo";
        let encode = parse_instruction(instr, &mut as_ctx);

        assert_eq!(encode, 0xe0_00_07_01);
        assert_eq!(as_ctx.fix_ups[0].kind, Const16LO);

        let instr = "jne %r14, %r7, foo";
        let encode = parse_instruction(instr, &mut as_ctx);

        assert_eq!(encode, 0xe0_00_07_03);
        assert_eq!(as_ctx.fix_ups[1].kind, PcRel16);
    }

    #[test]
    fn test_parse_instruction_type_m() {
        let instr = "ldw %r11, 1023(%r10)";
        let mut as_ctx = ASContext::new();
        let encode = parse_instruction(instr, &mut as_ctx);

        assert_eq!(encode, 0x03_ff_ba_02);
    }

    #[test]
    fn test_parse_directive() {
        let input = "data";
        let mut as_ctx = ASContext::new();

        parse_directive(input, &mut as_ctx);

        assert!(as_ctx.in_data_section);
        assert!(!as_ctx.in_text_section);

        let input = "word 10";
        parse_directive(input, &mut as_ctx);

        assert_eq!(as_ctx.data_section_size, 40);

        let input = "text";
        parse_directive(input, &mut as_ctx);

        assert!(!as_ctx.in_data_section);
        assert!(as_ctx.in_text_section);
    }

    #[test]
    fn test_parse_label() {
        let input = "foo:";
        let mut as_ctx = ASContext::new();
        as_ctx.in_data_section = true;

        parse_label(input, &mut as_ctx);

        assert_eq!(as_ctx.symbol_table[0].name, "foo".to_string());
        assert_eq!(as_ctx.symbol_table[0].position, 0u32);
    }
}

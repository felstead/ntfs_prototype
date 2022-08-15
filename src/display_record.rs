
use std::ops::Range;

use ntfs_mft::common::*;
use ntfs_mft::mft_types::*;
use ntfs_mft::mft_parser::*;
use ntfs_mft::direct_volume_reader;
use ntfs_mft::slice_utils::*;

use colored::*;
use encoding_rs::{WINDOWS_1252};

pub fn display_record(target : &str, record_id : u64, resolve_parents : bool) -> Result<(), String> {
    let mut mft_reader = direct_volume_reader::create_mft_reader(target)?;

    let mut buffer = [0u8 ; MFT_RECORD_SIZE];

    mft_reader.read_records_into_buffer(record_id, 1, &mut buffer[..])?;

    // TODO: Let this handle "None" properly
    let record = MftRecord::new(&mut buffer, record_id)?.unwrap();

    println!("Record: #{}       Base record ID: #{}", record_id, record.get_base_record_id());
    println!("Entry type: {:?}  Usage status: {:?}  Hard link count: {:?}", record.file_type, record.usage_status, record.get_hard_link_count());
    println!("Fixup okay: {}  Expected: {:#04x}  Replacements: {:#04x} @ offset 0x1FE, {:#04x} @ offset 0x3FE", record.fixup_okay, record.fixup_expected_value, record.fixup_replacement1, record.fixup_replacement2);

    println!("Attributes: ");
    // Iterate through the attributes and display info about them

    for attr in record.iter() {
        
        let attr_type = match attr.get_attribute_type() {
            0x10 => "$STANDARD_INFORMATION",
            0x20 => "$ATTRIBUTE_LIST",
            0x30 => "$FILE_NAME",
            0x40 => "$OBJECT_ID",
            0x50 => "$SECURITY_DESCRIPTOR",
            0x60 => "$VOLUME_NAME",
            0x70 => "$VOLUME_INFORMATION",
            0x80 => "$DATA",
            0x90 => "$INDEX_ROOT",
            0xA0 => "$INDEX_ALLOCATION",
            0xB0 => "$BITMAP",
            0xC0 => "$REPARSE_POINT",
            0xD0 => "$EA_INFORMATION",
            0xE0 => "$EA",
            0xF0 => "$PROPERTY_SET",
            0x100 => "$LOGGED_UTILITY_STREAM",
            _ => "UNKNOWN"
        };

        match attr {
            MftAttribute::Base(attr) => {
                println!("== {:#x} ({}) of length {} (data is {})", 
                attr.get_attribute_type(),
                attr_type,
                attr.get_data_slice().len(),
                if attr.get_form_code() == FORM_CODE_NONRESIDENT { "non-resident" } else { "resident" });

                if resolve_parents && attr.get_attribute_type() == ATTR_FILE_NAME && attr.get_form_code() == FORM_CODE_RESIDENT {
                    let file_name = MftFileNameInfo::new(attr.get_data_slice());
                    let mut parent_buffer = [0u8 ; MFT_RECORD_SIZE];

                    let mut full_path = file_name.get_file_name();
                    full_path.insert(0, '\\');

                    let mut parent_id = file_name.get_parent_directory_id();

                    while parent_id != 5 {
                        mft_reader.read_records_into_buffer(parent_id, 1, &mut parent_buffer)?;
                        let parent_record = MftRecord::new(&mut parent_buffer, parent_id)?.unwrap();

                        let parent_file_name = parent_record.get_file_name_info().unwrap();
                        full_path.insert_str(0, parent_file_name.get_file_name().as_str());
                        full_path.insert(0, '\\');

                        parent_id = parent_file_name.get_parent_directory_id();
                    }

                    println!("Full path: {}", full_path);
                }    

                println!();
        
                let mut ranges : Vec::<Range<usize>> = vec!();
                let field_display_info : Vec<FieldDisplayInfo> = attr.get_display_info();
        
                if !field_display_info.is_empty() {
                    for (index, f) in field_display_info.iter().enumerate() {
                        let range_string = format!("0x{:02x}-0x{:02x}", f.range.start, f.range.end - 1).on_color(PALETTE[index]).color(Color::Black);
                        if index % 2 == 0 {
                            print!("{:>25} : {}", f.name.bold(), range_string);
                        } else {
                            println!("{:>25} : {}", f.name.bold(), range_string);
                        }    
                        ranges.push(f.range.start..f.range.end); // Ugh, can't copy??
                    }
        
                    if field_display_info.len() % 2 == 1 { 
                        println!(); 
                    }
                }
        
                println!();
                hexdump(attr.get_data_slice(), 16, 4, &ranges);    
            },
            MftAttribute::Extension(attr_ref) => {
                println!("== {:#x} ({}), present in extension record: #{}", 
                    attr_ref.get_attribute_type(),
                    attr_type,
                    attr_ref.get_extension_record_id());
            }
        }

        println!();
    }

    Ok(())
}

fn index_for_range(offset : usize, ranges : &[Range<usize>]) -> Option<usize> {
    for (index, range) in ranges.iter().enumerate() {
        if range.contains(&offset) {
            //println!("{:02x} in {:02x}-{:02x} ({})", offset, range.start, range.end, index);
            return Some(index)
        }
    }
    None
}

// This is the Tableau 20 palette
// https://public.tableau.com/views/TableauColors/ColorPaletteswithRGBValues?%3Aembed=y&%3AshowVizHome=no&%3Adisplay_count=y&%3Adisplay_static_image=y
const PALETTE : [Color ; 20] = [
    Color::TrueColor { r: 255, g: 187, b: 120 },
    Color::TrueColor { r: 255, g: 127, b: 14 },
    Color::TrueColor { r: 174, g: 199, b: 232 },
    Color::TrueColor { r: 44, g: 160, b: 44 },
    Color::TrueColor { r: 31, g: 119, b: 180 },
    Color::TrueColor { r: 255, g: 152, b: 150 },
    Color::TrueColor { r: 214, g: 39, b: 40 },
    Color::TrueColor { r: 197, g: 176, b: 213 },
    Color::TrueColor { r: 152, g: 223, b: 138 },
    Color::TrueColor { r: 148, g: 103, b: 189 },
    Color::TrueColor { r: 247, g: 182, b: 210 },
    Color::TrueColor { r: 227, g: 119, b: 194 },
    Color::TrueColor { r: 196, g: 156, b: 148 },
    Color::TrueColor { r: 140, g: 86, b: 75 },
    Color::TrueColor { r: 127, g: 127, b: 127 },
    Color::TrueColor { r: 219, g: 219, b: 141 },
    Color::TrueColor { r: 199, g: 199, b: 199 },
    Color::TrueColor { r: 188, g: 189, b: 34 },
    Color::TrueColor { r: 158, g: 218, b: 229 },
    Color::TrueColor { r: 23, g: 190, b: 207 }];

fn hexdump(slice : &[u8], column_count : usize, indent : usize, ranges : &[Range<usize>]) {

    let header : Vec<String> = (0..column_count).map(|col| format!("{:02x}", col)).collect();
    println!("{:indent$}     {}", "", header.join(" ").bold());

    // This is really ugly and inefficient, come back to this
    for row_offset in (0..slice.len()).step_by(column_count) {
        let data_range = row_offset..std::cmp::min(slice.len(), row_offset + column_count);
        let hex_row : Vec<String> = data_range.clone().map(|i| {
            if let Some(index) = index_for_range(i, ranges) {
                format!("{:02x}", slice[i]).on_color(PALETTE[index]).color(Color::Black).to_string()
            } else {
                format!("{:02x}", slice[i])
            }
        }).collect();
        
        let ascii_row = String::from_iter(data_range.clone().map(|i| {
            if let Some(index) = index_for_range(i, ranges) {
                format!("{}", u8_to_char(slice[i])).on_color(PALETTE[index]).color(Color::Black).to_string()
            } else {
                format!("{}", u8_to_char(slice[i]))
            }
        }));

        let hex_row_width = column_count * 3 - 1;
        let padding = hex_row_width - ((data_range.end - data_range.start) * 3 - 1);

        println!("{:indent$}{} {}{:padding$}  {}", "", format!("{:04x}", row_offset).bold(), hex_row.join(" "), "", ascii_row);
    }
}

fn u8_to_char(byte : u8) -> char {
    // From https://en.wikipedia.org/wiki/Unicode_control_characters
    const CONTROL_CHARS : [char ;  32] = 
        ['␀','␁','␂','␃','␄','␅','␆','␇','␈','␉','␊','␋','␌','␍','␎','␏',
        '␐','␑','␒','␓','␔','␕','␖','␗','␘','␙','␚','␛','␜','␝','␞','␟'];
   
    match byte {
        0..=0x1F => CONTROL_CHARS[byte as usize],
        0x20..=0x7E => byte as char,
        0x7F => '␡',
        0x81 | 0x8D | 0x8F | 0x90 | 0x9D => '�',
        _ => WINDOWS_1252.decode_without_bom_handling_and_without_replacement(&[byte ; 1]).unwrap().chars().next().unwrap()
    }
}
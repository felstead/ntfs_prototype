
use std::fs::FileType;
use std::io::Write;
use std::time::{Instant};
use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Range;

use ntfs_mft::direct_volume_reader;
use ntfs_mft::common::{MFT_RECORD_SIZE, FORM_CODE_NONRESIDENT};
use ntfs_mft::mft_types::{FileType as MftFileType, FileUsageStatus, MftStandardInformation, MftNonResidentFileData };
use ntfs_mft::mft_parser::{MftRecord, enumerate_mft_records, MftRecordsChunkBuffer, read_single_mft_record};

use clap::{Parser, Subcommand};
use ntfs_mft::mft_types::MftFileNameInfo;

use encoding_rs::{WINDOWS_1252};

use colored::*;
use ntfs_mft::slice_utils::AttributeDisplayInfo;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Extracts an MFT from a live volume and dumps it (in its original binary format) to a file.
    /// Requires running as Administrator
    DumpRaw {
        /// The target volume to dump the MFT from, e.g. C:, D:, etc
        #[clap(value_parser)]
        target: String,
        /// The output file to write to, defaults to "mft.bin" and (optionally) "mft.bin.ranges" if only certain ranges were selected.
        #[clap(value_parser, default_value_t = String::from("mft.bin"))]
        output_file: String,
        /// The range(s) of records to dump based on the MFT record indicies.
        /// Examples: 
        /// - 0-16,23,36,1000-2100 will dump records 0-16, 23, 36 and 1000-2000
        #[clap(long, value_parser)]
        ranges: Option<String>,
    },
    /// Displays information about the MFT
    Info {
        /// The target volume or file to read.
        #[clap(value_parser)]
        target: String,
    },
    /// Dumps information about a single record from the MFT
    DisplayRecord {
        /// The target volume or file to read.
        #[clap(value_parser)]
        target: String,

        /// The ID of the record to dump
        #[clap(value_parser)]
        record_id: u64
    }
}

fn main() {
    let cli = Cli::parse();

    let start = Instant::now();
    let result = match &cli.command {
        Commands::DumpRaw { target, output_file, ranges } => {
            dump_raw(target, output_file, ranges)
        },
        Commands::Info { target } => {
            info(target)
        },
        Commands::DisplayRecord { target, record_id } => {
            display_record(target, *record_id)
        }
    };
    
    if let Err(err) = result {
        println!("Error during execution: {}", err);
    }

    println!("Execution time: {:?}", start.elapsed());
    return;
}

fn err_typeify<T, E : Display>(result : Result<T, E>) -> Result<T, String> {
    match result {
        Ok(t) => Ok(t),
        Err(e) => Err(e.to_string())
    }
}

fn dump_raw(target : &String, output_file_name : &String, _ranges : &Option<String>) -> Result<(), String>
{
    // Validate
    let mut mft_reader = direct_volume_reader::create_mft_reader(target)?;

    let mut output_file = err_typeify(std::fs::File::create(output_file_name))?;

    let buffer_size_in_records : usize = 32768; // TODO: Make configurable

    let mut buffer = vec![0_u8; MFT_RECORD_SIZE * buffer_size_in_records].into_boxed_slice();

    println!("Dumping MFT for {} to file {}...", target, output_file_name);

    for record_index in (0..mft_reader.get_max_number_of_records()).step_by(buffer_size_in_records) {
        println!("Reading record {} / {}", record_index, mft_reader.get_max_number_of_records());
        let records_read = mft_reader.read_records_into_buffer(record_index as i64, buffer_size_in_records, &mut buffer[..])?;
     
        err_typeify(output_file.write(&buffer[0..records_read]))?;
    }
    println!("Done!");

    Ok(())
}

#[derive(Default)]
struct MftInfo {
    records : Vec<Item>,
    record_id_to_index : HashMap<u64, usize>,
    unparented_items : HashMap<u64, Vec<usize>>
}

impl MftInfo {

    const ROOT_ID : u64 = 5;

    fn new() -> Self {
        MftInfo::default()
    }

    fn get_item_by_record_id(&self, record_id : u64) -> Option<&Item> {
        match self.record_id_to_index.get(&record_id) {
            Some(index) => Some(&self.records[*index]),
            None => None
        }
    }

    fn get_item_by_index(&self, index : usize) -> Option<&Item> {
        if index < self.records.len() {
            Some(&self.records[index])
        } else {
            None
        }
    }
 
    fn get_root_item(&self) -> Option<&Item> { 
        self.get_item_by_record_id(MftInfo::ROOT_ID)
    }

    fn add_item(&mut self, mut item : Item) {
        // Check for children and add their info if we have them
        if item.is_directory {
            if let Some(new_children) = self.unparented_items.remove(&item.id) {
                for item_index in new_children {
                    let child_record = &self.records[item_index];
                    item.sub_items_size += child_record.self_size;
                    item.sub_item_indexes.push(item_index);
                }
            }
        }

        let new_item_index = self.records.len();

        // Aggregate this to parents
        let mut parent_id = item.parent_id;
        let mut parent_count = 0;
        while let Some(parent_record_index) = self.record_id_to_index.get(&parent_id) {
            let mut parent_record = &mut self.records[*parent_record_index];

            // If this is the direct parent, add the item to the sub item IDs
            if parent_record.id == item.parent_id {
                parent_record.sub_item_indexes.push(new_item_index)
            }

            parent_record.sub_items_size += item.get_total_size();

            if parent_id == parent_record.id  {
                break;
            } else {
                parent_id = parent_record.id;
                parent_count += 1;
            }
        }

        if parent_count == 0 && item.id != 5 {
            // This item is unparented, add it to the unparented list
            let unparented_items = self.unparented_items.entry(item.parent_id).or_default();
            unparented_items.push(new_item_index);
        }
        
        //println!("Adding {} - {}", &item.id, &item.name);

        // Add item to collections
        self.record_id_to_index.insert(item.id, self.records.len());
        self.records.push(item);
    }
}

struct Item {
    id : u64,
    parent_id : u64,
    name : String,
    is_directory : bool,
    sub_item_indexes : Vec<usize>,
    // Aggregates
    sub_items_size : u64,
    self_size : u64,
    sub_item_count : u64
}

impl Item {
    fn new(mft_record : &MftRecord) -> Option<Self> {

        if mft_record.usage_status == FileUsageStatus::InUse {
            if let Some(file_name) = mft_record.get_file_name_info() {
                let mut file_size = 0;
                if let Some(file_data) = mft_record.get_file_data_info() {
                    file_size = file_data.get_file_size();
                }

                return Some(Item {
                    id : mft_record.id,
                    parent_id : file_name.get_parent_directory_id(),
                    name : file_name.get_file_name().to_owned(),
                    is_directory : mft_record.file_type == MftFileType::Directory,
                    sub_item_indexes : vec!(),
                    sub_items_size : 0,
                    self_size : file_size,
                    sub_item_count : 0
                });
            }
        }

        return None;
    }

    fn get_total_size(&self) -> u64 {
        return self.self_size + self.sub_items_size;
    }
}

fn info(target : &String) -> Result<(), String> {
    let mut mft_reader = direct_volume_reader::create_mft_reader(target)?;

    let buffer_size_in_records : usize = 32768; // TODO: Make configurable

    let mut buffer = vec![0_u8; MFT_RECORD_SIZE * buffer_size_in_records].into_boxed_slice();

    let mut mft_info = MftInfo::new();

    for record_index in (0..mft_reader.get_max_number_of_records()).step_by(buffer_size_in_records) {
        
        let _records_read = mft_reader.read_records_into_buffer(record_index as i64, buffer_size_in_records, &mut buffer[..])?;

        let record_buffer = MftRecordsChunkBuffer::new(&mut buffer[..], record_index as u64);

        for mft_record in record_buffer.iter() {
            match mft_record {
                Ok(Some(record)) => {
                    if let Some(item) = Item::new(&record) {
                        mft_info.add_item(item);
                    }

                    //println!("#{} -> {:?} {:?}", record.id, record.file_type, record.usage_status);
                },
                Ok(None) => {
                    //println!("NONENONE");
                }
                Err(err) => {
                    //println!("Error: {}", err)
                },
                _ => {}
            }
        }
    }

    if let Some(item) = mft_info.get_root_item() {
        println!("* {}  ({} bytes)", item.name, item.get_total_size());
        for item_index in &item.sub_item_indexes {
            if let Some(sub_item) = mft_info.get_item_by_index(*item_index) {
                println!("|- {}{}  ({} bytes) #{}", sub_item.name, if sub_item.is_directory { "/" } else { " " }, sub_item.get_total_size(), sub_item.id);
            }
        }
    }


    Ok(())
}

fn display_record(target : &String, record_id : u64) -> Result<(), String> {
    let mut mft_reader = direct_volume_reader::create_mft_reader(target)?;

    let buffer_size_in_records : usize = MFT_RECORD_SIZE; // TODO: Make configurable

    let mut buffer = [0u8 ; MFT_RECORD_SIZE];

    let records_read = mft_reader.read_records_into_buffer(record_id as i64, 1, &mut buffer[..])?;

    // TODO: Let this handle "None" properly
    let record = read_single_mft_record(&buffer, record_id)?.unwrap();

    println!("Record: #{}", record_id);
    println!("Entry type: {:?}  Usage status: {:?}", record.file_type, record.usage_status);

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

        println!("== {:#x} ({}) of length {} (data is {})", 
            attr.get_attribute_type(),
            attr_type,
            attr.get_data_slice().len(),
            if attr.get_form_code() == FORM_CODE_NONRESIDENT { "non-resident" } else { "resident" });

        println!();

        let mut ranges : Vec::<Range<usize>> = vec!();
        let mut field_display_info : Vec<AttributeDisplayInfo> = vec!();
        if attr.get_attribute_type() == 0x30 {
            let filename = MftFileNameInfo::new(attr.get_data_slice());
            field_display_info = filename.get_field_display_info();
        } else if attr.get_attribute_type() == 0x10 {
            let stdinfo = MftStandardInformation::new(attr.get_data_slice());
            field_display_info = stdinfo.get_field_display_info();
        } else if attr.get_attribute_type() == 0x80 && attr.get_form_code() == FORM_CODE_NONRESIDENT {
            let data = MftNonResidentFileData::new(attr.get_data_slice());
            field_display_info = data.get_field_display_info();
        }

        if field_display_info.len() > 0 {
            for (index, f) in field_display_info.iter().enumerate() {
                let range_string = format!("0x{:02x}-0x{:02x}", f.range.start, f.range.end - 1).on_color(PALETTE[index]).color(Color::Black);
                if index % 2 == 0 {
                    print!("{:>25} : {}", f.name.bold(), range_string);
                } else {
                    println!("{:>25} : {}", f.name.bold(), range_string);
                }    
                ranges.push(f.range.start..f.range.end); // Ugh
            }

            if field_display_info.len() % 2 == 1 { 
                println!(); 
            }
        }

        println!();
        hexdump(attr.get_data_slice(), 16, 4, &ranges);

        println!();
    }

    Ok(())
}

fn index_for_range(offset : usize, ranges : &Vec<Range<usize>>) -> Option<usize> {
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

fn hexdump(slice : &[u8], column_count : usize, indent : usize, ranges : &Vec<Range<usize>>) {

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
        0x80 | _ => WINDOWS_1252.decode_without_bom_handling_and_without_replacement(&[byte ; 1]).unwrap().chars().nth(0).unwrap()
    }
}
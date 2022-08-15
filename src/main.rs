
use std::io::Write;
use std::time::{Instant};
use std::collections::HashMap;
use std::fmt::Display;

use ntfs_mft::direct_volume_reader;
use ntfs_mft::common::*;
use ntfs_mft::mft_types::*;
use ntfs_mft::mft_parser::*;

use clap::{Parser, Subcommand};

mod display_record;
use crate::display_record::*;

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
        record_id: u64,

        #[clap(value_parser, short, long, default_value_t = true)]
        resolve_parents: bool
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
        Commands::DisplayRecord { target, record_id, resolve_parents } => {
            display_record(target, *record_id, *resolve_parents)
        }
    };
    
    if let Err(err) = result {
        println!("Error during execution: {}", err);
    }

    println!("Execution time: {:?}", start.elapsed());
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
        let records_read = mft_reader.read_records_into_buffer(record_index as u64, buffer_size_in_records, &mut buffer[..])?;
     
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
                for child_index in new_children {
                    let child_record = &self.records[child_index];
                    item.add_child(child_record, child_index, true)
                }
            }
        }

        let new_item_index = self.records.len();

        // Aggregate this to parents
        let mut parent_id = item.parent_id;
        let mut parent_count = 0;

        while let Some(parent_record_index) = self.record_id_to_index.get(&parent_id) {
            let parent_record = &mut self.records[*parent_record_index];

            let is_direct_parent = parent_record.id == item.parent_id;

            parent_record.add_child(&item, new_item_index, is_direct_parent);

            parent_count += 1;
            if parent_id == parent_record.parent_id {
                break;
            } else {
                parent_id = parent_record.parent_id;
            }            
        }

        if parent_count == 0 && item.id != 5 {
            // This item is unparented, add it to the unparented list
            let unparented_items = self.unparented_items.entry(item.parent_id).or_default();
            unparented_items.push(new_item_index);
        }

        // Add item to collections
        self.record_id_to_index.insert(item.id, new_item_index);
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
                    name : file_name.get_file_name(),
                    is_directory : mft_record.file_type == MftFileType::Directory,
                    sub_item_indexes : vec!(),
                    sub_items_size : 0,
                    self_size : file_size,
                    sub_item_count : 0
                });
            }
        }

        None
    }

    fn add_child(&mut self, child : &Item, child_index : usize, is_direct_parent : bool) {
        if !self.is_directory {
            panic!("Adding child to non-directory!")
        }

        if is_direct_parent {
            self.sub_item_indexes.push(child_index);
        }
        self.sub_item_count += child.get_total_count();
        self.sub_items_size += child.get_total_size();
    }

    fn get_total_size(&self) -> u64 {
        self.self_size + self.sub_items_size
    }

    fn get_total_count(&self) -> u64 {
        self.sub_item_count + 1
    }
 }

fn info(target : &str) -> Result<(), String> {
    let mut mft_reader = direct_volume_reader::create_mft_reader(target)?;

    let buffer_size_in_records : usize = 32768; // TODO: Make configurable

    let mut buffer = vec![0_u8; MFT_RECORD_SIZE * buffer_size_in_records].into_boxed_slice();

    let mut mft_info = MftInfo::new();

    for record_index in (0..mft_reader.get_max_number_of_records()).step_by(buffer_size_in_records) {
        
        let records_read = mft_reader.read_records_into_buffer(record_index as u64, buffer_size_in_records, &mut buffer[..])?;

        let mut record_buffer = MftRecordsChunkBuffer::new(&mut buffer[..], record_index as u64, records_read);

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
                Err(_err) => {
                    //println!("Error: {}", err)
                }
            }
        }
    }

    if let Some(item) = mft_info.get_root_item() {
        println!("* {}  ({} bytes)", item.name, item.get_total_size());
        for item_index in &item.sub_item_indexes {
            if let Some(sub_item) = mft_info.get_item_by_index(*item_index) {
                println!("|- {}{}  ({} bytes, {} items) #{}", sub_item.name, if sub_item.is_directory { "/" } else { " " }, sub_item.get_total_size(), sub_item.get_total_count(), sub_item.id);
                
                for sub_item_index in &sub_item.sub_item_indexes {
                    if let Some(sub_sub_item) = mft_info.get_item_by_index(*sub_item_index) {
                        println!("  |- {}{}  ({} bytes, {} items) #{}", sub_sub_item.name, if sub_sub_item.is_directory { "/" } else { " " }, sub_sub_item.get_total_size(), sub_sub_item.get_total_count(), sub_sub_item.id);
                    }
                }
            }
        }
    }

    for (parent_id, uplist) in mft_info.unparented_items.iter() {
        if let Some(parent_item) = mft_info.get_item_by_record_id(*parent_id) {
            println!("Parent index: #{} -> [{}] {}", parent_id, parent_item.id, parent_item.name);

            for unparented in uplist {
                let child_item = mft_info.get_item_by_index(*unparented as usize).unwrap();
                println!(" - {} -> #{} {}", unparented, child_item.id, child_item.name);
            }    
        } else {
            println!("NOT FOUND: #{}", *parent_id);
        }
    }


    Ok(())
}


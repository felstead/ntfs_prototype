
use std::time::{Instant};
use std::collections::HashMap;

use crate::mft_parser::{enumerate_mft_records, FileUsageStatus, FileType };

mod direct_volume_reader;
mod mft_parser;
mod mft_types;
mod ntfs_file_reader;
mod common;

fn main() {

    {
        let mut mft_reader = direct_volume_reader::DirectVolumeMftReader::default();

        mft_reader.open_mft("c:").unwrap();
    
        println!("MFT byte offset: {:#x}  Size: {}", mft_reader.get_mft_start_offset_bytes(), mft_reader.get_mft_size_bytes());

        let buffer_size_in_records : usize = 100;

        let mut buffer = vec![0_u8; 1024 * buffer_size_in_records].into_boxed_slice();

        let read_start = Instant::now();
        mft_reader.read_records_into_buffer(0, buffer_size_in_records, &mut buffer[..]).unwrap();
        let read_time = read_start.elapsed();

        let mut directories = HashMap::<u64, String>::new();

        let enumerate_start = Instant::now();
        enumerate_mft_records(&buffer[..], 0, |record_id, read_result| {
            match read_result {
                Ok(Some(record )) => {
                    println!("Record {}", record_id);
                    match record.file_name_info.as_ref() {
                        Some(filename) => {
                            println!("{}", filename.get_file_name());
                        }
                        ,
                        _ => {}
                    };


                    if record.usage_status == FileUsageStatus::InUse {
                        match record.file_type {
                            FileType::File => {
                                match record.standard_information.as_ref() {
                                    Some(std_info) => {
                                        println!("Created: {:#x}", std_info.get_create_timestamp().dwLowDateTime);
                                    },
                                    _ => {}
                                }
                            },
                            FileType::Directory => {
                                match record.file_name_info.as_ref() {
                                    Some(filename) => {
                                        let dir_name = filename.get_file_name();
                                        println!("Directory {} with parent {} -> parent name: {:?}",  &dir_name, filename.get_parent_directory_id(), directories.get(&filename.get_parent_directory_id()));
                                        directories.insert(record.id, dir_name);
                                        
                                    },
                                    _ => {}
                                }

                                /*directories.insert(record.id, record.file_name.unwrap_or_default().file_name);

                                //let file_name = record.file_name.as_ref();
                                if record.file_name.is_some() {
                                    println!("Directory {} with parent {} -> parent name: {:?}", 
                                        record.file_name.unwrap_or_default().file_name, 
                                        record.file_name.unwrap_or_default().parent_dir_id, 
                                        directories.get(&record.file_name.unwrap_or_default().parent_dir_id))
                                }*/
                                
                            },
                            _ => {}
                        }
                    }
                },
                Ok(None) => {
                    //println!("# {}: Empty, skipping", record_id)
                }
                Err(err) => println!("# {}: Error: {}", record_id, err)
            }
        });

        let enumerate_time = enumerate_start.elapsed();

        println!("Read time: {:?}  Enumerate time: {:?}", read_time, enumerate_time);
        //println!("Directories: {:#?}", directories);

        // Little benchmark for reading entire MFT, on the SATA SSD it's about 450 MB/s unoptimized, on the NVMe it's about 1300MB/s unoptimized
        /*let read_start = Instant::now();
        let mut offset : i64 = 0;
        let mut bytes_read :i64 = 0;
        while true {
            let result = mft_reader.read_records_into_buffer(offset as i64, buffer_size_in_records, &mut buffer[..]);
            if result.is_err() {
                break;
            }
            offset += buffer_size_in_records as i64;
            bytes_read += buffer.len() as i64;
        }

        println!("ReadFile duration for buffer of size {} to read {} bytes: {:?}", buffer.len(), bytes_read, read_start.elapsed());

        println!("{} {} {} {}", buffer[0] as char, buffer[1] as char, buffer[2] as char, buffer[3] as char)*/


    }
}

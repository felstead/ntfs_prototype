
//use std::time::{Duration, Instant};

use crate::mft_parser::enumerate_mft_records;

mod direct_volume_reader;
mod mft_parser;

fn main() {

    {
        let mut mft_reader = direct_volume_reader::DirectVolumeMftReader::default();

        mft_reader.open_mft("d:").unwrap();
    
        println!("MFT byte offset: {:#x}  Size: {}", mft_reader.get_mft_start_offset_bytes(), mft_reader.get_mft_size_bytes());

        let buffer_size_in_records : usize = 1024;

        let mut buffer = vec![0 as u8; 1024 * buffer_size_in_records].into_boxed_slice();

        mft_reader.read_records_into_buffer(0, buffer_size_in_records, &mut buffer[..]).unwrap();

        enumerate_mft_records(&buffer[..]);

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

    return;
}

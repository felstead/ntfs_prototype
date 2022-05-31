use byteorder::*;
use std::slice;

use crate::direct_volume_reader::NtfsFileReader;

pub const MFT_RECORD_SIZE : usize = 1024;

pub fn enumerate_mft_records(buffer : &[u8]) {
    read_single_mft_record(&buffer[0..MFT_RECORD_SIZE]);
}

pub fn read_single_mft_record(record : &[u8]) {
    // Now we have a buffer, we can operate on it safely
    // This can also be done unsafely by plonking structs on top of it, but the whole point of Rust is to be safe, so ¯\_(ツ)_/¯
    // Struct plonking using something like this may be faster, but need to measure:
    // let header = buffer.as_ptr().offset(MFT_RECORD_SIZE as isize) as *const FILE_RECORD_SEGMENT_HEADER;

    const EXPECTED_SIGNATURE : u32 = 0x454c4946; // The ASCII string "FILE" converted to a u32

    // Offsets into the FILE_RECORD_SEGMENT_HEADER structure
    // From https://docs.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header
    const FRSH_FIRST_ATTRIBUTE_OFFSET : usize = 20;
    const FRSH_FLAGS_OFFSET : usize = 22;

    // File record flags
    const FILE_RECORD_SEGMENT_IN_USE : u16 = 0x01;
    const _FILE_FILE_NAME_INDEX_PRESENT : u16 = 0x02;

    // Attribute form code
    const _FORM_CODE_RESIDENT : u8 = 0x0;
    const FORM_CODE_NONRESIDENT : u8 = 0x1;

    // Offsets into the ATTRIBUTE_RECORD_HEADER structure
    // From https://docs.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header
    const _ARH_TYPE_CODE_OFFSET : usize = 0;
    const ARH_FORM_CODE_OFFSET : usize = 8;
    const ARH_RECORD_LENGTH_OFFSET : usize = 4;
    const ARH_RES_LENGTH : usize = 24; // The offset to the end of a "resident" type header

    // Non-resident attributes mark where the data for the attribute lives, which could include the data for the file
    const ARH_NONRES_LOWEST_VCN_OFFSET : usize = 16;
    const ARH_NONRES_HIGHEST_VCN_OFFSET : usize = 24;
    const ARH_NONRES_MAPPING_PAIRS_OFFSET_OFFSET : usize = 32;
    const ARH_NONRES_ALLOCATED_LENGTH_OFFSET : usize = 40;
    const ARH_NONRES_FILE_SIZE_OFFSET : usize = 48;
    const ARH_NONRES_VALID_DATA_LENGTH_OFFSET : usize = 56;



    // From https://docs.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header
    const ATTR_STANDARD_INFORMATION : u32 = 0x10;
    const _ATTR_ATTRIBUTE_LIST : u32 = 0x20;
    const ATTR_FILE_NAME : u32 = 0x30;
    const ATTR_DATA : u32 = 0x80;

    // Offsets into the FILE_NAME attribute
    // From https://docs.microsoft.com/en-us/windows/win32/devnotes/file-name
    const FN_FILE_NAME_LENGTH_CHARS_OFFSET : usize = 0x40;
    const FN_FILE_NAME_DATA_OFFSET : usize = 0x42;

    let signature : u32 = LittleEndian::read_u32(&record[0..4]);

    if signature == EXPECTED_SIGNATURE {
        println!("Signature was good");

        let flags : u16 = LittleEndian::read_u16(&record[FRSH_FLAGS_OFFSET..FRSH_FLAGS_OFFSET+2]);
        let _file_in_use = flags & FILE_RECORD_SEGMENT_IN_USE > 0;

        let first_attribute_offset = LittleEndian::read_u16(&record[FRSH_FIRST_ATTRIBUTE_OFFSET..FRSH_FIRST_ATTRIBUTE_OFFSET+4]);

        println!("First attribute offset: {:#x}", first_attribute_offset);

        let mut attribute_offset = first_attribute_offset as usize;

        while attribute_offset < MFT_RECORD_SIZE {
            let attribute_type_code = LittleEndian::read_u32(&record[attribute_offset..attribute_offset+4]);
            if attribute_type_code == 0xffffffff {
                break;
            }
            let record_length = LittleEndian::read_u32(&record[attribute_offset+ARH_RECORD_LENGTH_OFFSET..attribute_offset+ARH_RECORD_LENGTH_OFFSET+4]) as usize;
            println!("Reading attribute at offset {:#x}-{:#x}, type code {:#x}, record length: {}", attribute_offset, attribute_offset + record_length, attribute_type_code, record_length);

            if record_length > 0 && record_length <= MFT_RECORD_SIZE {

                let attribute = &record[attribute_offset..attribute_offset+record_length];

                //println!("{:?}", attribute);

                match attribute_type_code {
                    ATTR_STANDARD_INFORMATION => {
                        // We don't really care about this
                        //println!("Standard information: ");
                    },
                    ATTR_FILE_NAME => {
                        // Only the top 48 bits are the actual file reference
                        let parent_directory_id = LittleEndian::read_u48(&attribute[ARH_RES_LENGTH..ARH_RES_LENGTH+6]);

                        let file_name_length : usize = attribute[ARH_RES_LENGTH + FN_FILE_NAME_LENGTH_CHARS_OFFSET] as usize;
                        let file_name_data_bytes = &attribute[ARH_RES_LENGTH + FN_FILE_NAME_DATA_OFFSET..ARH_RES_LENGTH + FN_FILE_NAME_DATA_OFFSET + file_name_length];

                        // This is "unsafe" but it really isn't assuming the slice is good
                        let file_name_data_utf16 = unsafe { slice::from_raw_parts(file_name_data_bytes.as_ptr() as *const u16, file_name_length) };

                        let file_name = String::from_utf16_lossy(file_name_data_utf16);
                        println!("File name {}   Parent dir: {}", file_name, parent_directory_id);

                        //file_names.push(file_name);
                    },
                    ATTR_DATA => {
                        let formcode : u8 = attribute[ARH_FORM_CODE_OFFSET];
                        println!("Data form code: {}", formcode);
                        if formcode == FORM_CODE_NONRESIDENT {
                            let lowest_vcn = LittleEndian::read_u64(&attribute[ARH_NONRES_LOWEST_VCN_OFFSET..ARH_NONRES_LOWEST_VCN_OFFSET+8]);
                            let highest_vcn = LittleEndian::read_u64(&attribute[ARH_NONRES_HIGHEST_VCN_OFFSET..ARH_NONRES_HIGHEST_VCN_OFFSET+8]);

                            let mapping_pairs_offset = LittleEndian::read_u16(&attribute[ARH_NONRES_MAPPING_PAIRS_OFFSET_OFFSET..ARH_NONRES_MAPPING_PAIRS_OFFSET_OFFSET+2]);

                            let allocated_length = LittleEndian::read_i64(&attribute[ARH_NONRES_ALLOCATED_LENGTH_OFFSET..ARH_NONRES_ALLOCATED_LENGTH_OFFSET+8]);
                            let file_size = LittleEndian::read_i64(&attribute[ARH_NONRES_FILE_SIZE_OFFSET..ARH_NONRES_FILE_SIZE_OFFSET+8]);
                            let valid_data_length = LittleEndian::read_i64(&attribute[ARH_NONRES_VALID_DATA_LENGTH_OFFSET..ARH_NONRES_VALID_DATA_LENGTH_OFFSET+8]);

                            println!("LVCN: {}  HVCN: {}", lowest_vcn, highest_vcn);
                            println!("Allocated length: {}  File size: {}  Valid data len: {}", allocated_length, file_size, valid_data_length);

                            println!("Mapping pairs offset: {:#x}", mapping_pairs_offset);

                            // Decode the runs
                            let mut run_offset = mapping_pairs_offset as usize;

                            let mut runs : NtfsFileReader = NtfsFileReader::new(4096, file_size);

                            while run_offset < attribute.len() {
                                let current_run = &attribute[run_offset..];
                                
                                match read_run(current_run) {
                                    Ok((0,0,0)) => {
                                        // End of runs, break!
                                        println!("End of runs!");
                                        println!("{:?}", runs);
                                        break;
                                    },
                                    Ok(res) => {
                                        println!("Got run! length: {:#x}  offset: {:#x}  run_size: {}", res.0, res.1, res.2);
                                        run_offset += res.2;
                                        runs.add_run(res.1, res.0);
                                    },
                                    Err(()) => {
                                        println!("Error reading run!!");
                                        break;
                                    }
                                }
                            }
                        }
                    },
                    _ => {
                        println!("Unhandled attribute type: {:#x}", attribute_type_code);
                    }
                }

            } else {
                println!("Read invalid attribute record size of {}, skipping the rest of the record", record_length);
                break;
            }

            attribute_offset += record_length as usize;
        }
    }
}


fn read_run(run_slice : &[u8]) -> Result<(i64, i64, usize), ()> {
    let header = run_slice[0] as usize;

    if header == 0 {
        return Ok((0, 0, 0));
    }

    let length_size = header & 0x0F; // Low nibble
    let offset_size = header >> 4; // High nibble

    if length_size > 8 || offset_size > 8 {
        return Err(());
    }

    let run_length = length_size + offset_size + 1;

    if run_slice.len() < run_length {
        Err(())
    } else {
        Ok(
            (read_run_varbyte_i64(&run_slice[1..length_size+1], length_size),
            read_run_varbyte_i64(&run_slice[length_size+1..length_size+offset_size+1], offset_size),
            run_length)
        )
    }
}

fn read_run_varbyte_i64(run_slice : &[u8], length : usize) -> i64 {
    assert_eq!(run_slice.len(), length);

    let mut result : i64 = 0;
    let mut bytes_remaining : i8 = length as i8;
    let mut is_negative : bool = false;

    while bytes_remaining > 0 {
        let index = (length as i8 - bytes_remaining) as usize;

        let current_byte = run_slice[index];

        result |= (current_byte as i64) << index * 8;

        is_negative = (current_byte & 0x80) > 0;

        bytes_remaining -= 1;
    }

    if is_negative {
        // Highest bit is negative, this means we need to pad out the rest of the bytes with 0xFF to make the result negative
        result |= -1i64 << length * 8;
    }

    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_run_varbyte_read_basic() {
        let simple_run : [u8; 4] = [0x21, 0x18, 0x34, 0x56];

        let result = super::read_run(&simple_run[..]).unwrap();

        assert_eq!(result.0, 0x18);
        assert_eq!(result.1, 0x5634);
        assert_eq!(result.2, 4);

        let longer_run_1 : [u8; 11] = [0x28, 0x12, 0x23, 0x34, 0x45, 0x54, 0x43, 0x32, 0x21, 0x34, 0x56];
        let longer_result_1 = super::read_run(&longer_run_1[..]).unwrap();

        assert_eq!(longer_result_1.0, 0x2132435445342312);
        assert_eq!(longer_result_1.1, 0x5634);
        assert_eq!(longer_result_1.2, 11);

        let longer_run_2 : [u8; 11] = [0x82, 0x34, 0x56, 0x12, 0x23, 0x34, 0x45, 0x54, 0x43, 0x32, 0x21];
        let longer_result_2 = super::read_run(&longer_run_2[..]).unwrap();

        assert_eq!(longer_result_2.0, 0x5634);
        assert_eq!(longer_result_2.1, 0x2132435445342312);
        assert_eq!(longer_result_2.2, 11);
    }

    #[test]
    fn run_varbyte_read_negative() {
        let negative_run_1 : [u8; 4] = [0x21, 0x87, 0x34, 0xF6];
        let result_1 = super::read_run(&negative_run_1[..]).unwrap();

        assert_eq!(result_1.0, -121); // 0x87 == -121
        assert_eq!(result_1.1, -2508); // 0xF634 == -2508
        assert_eq!(result_1.2, 4);
    }

    #[test]
    fn test_run_invalid_len() {
        // First nibble is too large for slice
        let invalid_run_1 : [u8; 4] = [0x31, 0x18, 0x34, 0x56];
        let result_1 = super::read_run(&invalid_run_1[..]);
        assert!(result_1.is_err());

        // Second nibble is too large for slice
        let invalid_run_2 : [u8; 4] = [0x13, 0x18, 0x34, 0x56];
        let result_2 = super::read_run(&invalid_run_2[..]);
        assert!(result_2.is_err());

        // Low nibble is straight up out of range
        let invalid_run_3 : [u8; 13] = [0x19, 0x18, 0x34, 0x56, 0x18, 0x34, 0x56, 0x18, 0x34, 0x56, 0x18, 0x34, 0x56];
        let result_3 = super::read_run(&invalid_run_3[..]);
        assert!(result_3.is_err());

        // High nibble is straight up out of range
        let invalid_run_4 : [u8; 13] = [0x91, 0x18, 0x34, 0x56, 0x18, 0x34, 0x56, 0x18, 0x34, 0x56, 0x18, 0x34, 0x56];
        let result_4 = super::read_run(&invalid_run_4[..]);
        assert!(result_4.is_err());
    }
}
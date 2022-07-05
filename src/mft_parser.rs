use byteorder::*;
use crate::common::*;
use crate::mft_types::*;

pub enum MftFileDataInfo<'a> {
    _Resident, // Not implemented
    NonResident(MftNonResidentFileData<'a>)
}

#[derive(Debug, PartialEq)]
pub enum FileUsageStatus {
    Unknown,
    InUse,
    Deleted
}

impl Default for FileUsageStatus {
    fn default() -> Self {
        FileUsageStatus::Unknown
    }
}

#[derive(Debug, PartialEq)]
pub enum FileType {
    Unknown,
    File,
    Directory
}

impl Default for FileType {
    fn default() -> Self {
        FileType::Unknown
    }
}

#[derive(Default)]
pub struct MftRecord<'a> {
    pub id : u64,
    pub file_type : FileType,
    pub usage_status : FileUsageStatus,
    pub standard_information : Option<MftStandardInformation<'a>>,
    pub file_name_info : Option<MftFileNameInfo<'a>>,
    pub short_file_name_info : Option<MftFileNameInfo<'a>>,
    pub file_data_info : Option<MftFileDataInfo<'a>>
}

pub fn enumerate_mft_records(buffer : &[u8], record_id_start : u64, mut reader_func: impl FnMut(u64, Result<Option<MftRecord>, String>)) {
    let mut offset = 0;
    let max_offset = buffer.len() - MFT_RECORD_SIZE;
    let mut current_record_id = record_id_start;
    while offset < max_offset
    {
        let mft_record_result= read_single_mft_record(&buffer[offset..offset+MFT_RECORD_SIZE], current_record_id);

        reader_func(current_record_id, mft_record_result);

        offset += MFT_RECORD_SIZE;
        current_record_id += 1;
    }
}

pub fn read_single_mft_record(record : &[u8], record_id : u64) -> Result<Option<MftRecord>, String> {
    // Now we have a buffer, we can operate on it safely
    // This can also be done unsafely by plonking structs on top of it, but the whole point of Rust is to be safe, so ¯\_(ツ)_/¯
    // Struct plonking using something like this may be faster, but need to measure:
    // let header = buffer.as_ptr().offset(MFT_RECORD_SIZE as isize) as *const FILE_RECORD_SEGMENT_HEADER;

     let signature : u32 = LittleEndian::read_u32(&record[0..4]);

    if signature == EXPECTED_SIGNATURE {
        //println!("Record {:#x}: Signature was good", record_id);

        let flags : u16 = LittleEndian::read_u16(&record[FRSH_FLAGS_OFFSET..FRSH_FLAGS_OFFSET+2]);

        let usage_status = match flags {
            FILE_RECORD_FLAG_DELETED_FILE | FILE_RECORD_FLAG_DELETED_DIR => FileUsageStatus::Deleted,
            FILE_RECORD_FLAG_EXISTING_FILE | FILE_RECORD_FLAG_EXISTING_DIR => FileUsageStatus::InUse,
            _ => FileUsageStatus::Unknown
        };

        let file_type = match flags {
            FILE_RECORD_FLAG_DELETED_DIR | FILE_RECORD_FLAG_EXISTING_DIR => FileType::Directory,
            FILE_RECORD_FLAG_DELETED_FILE | FILE_RECORD_FLAG_EXISTING_FILE => FileType::File,
            _ => FileType::Unknown
        };

        let mut mft_record = MftRecord {
            id: record_id,
            usage_status,
            file_type,
            ..Default::default()
        };

        let first_attribute_offset = LittleEndian::read_u16(&record[FRSH_FIRST_ATTRIBUTE_OFFSET..FRSH_FIRST_ATTRIBUTE_OFFSET+4]);

        //println!("First attribute offset: {:#x}", first_attribute_offset);

        let mut attribute_offset = first_attribute_offset as usize;

        let mut is_compressed = false;

        while attribute_offset < MFT_RECORD_SIZE {
            let attribute_type_code = LittleEndian::read_u32(&record[attribute_offset..attribute_offset+4]);
            if attribute_type_code == 0xffffffff {
                break;
            }
            // While the record length is a u32, it seems like only the bottom 16 bits are the record length.
            // Am I messing this up with an ATTRIBUTE_LIST_ENTRY?
            let record_length = LittleEndian::read_u16(&record[attribute_offset+ARH_RECORD_LENGTH_OFFSET..attribute_offset+ARH_RECORD_LENGTH_OFFSET+2]) as usize;
            //println!("Reading attribute at offset {:#x}-{:#x}, type code {:#x}, record length: {}", attribute_offset, attribute_offset + record_length, attribute_type_code, record_length);

            if record_length > 0 && record_length <= MFT_RECORD_SIZE {

                let attribute = &record[attribute_offset..attribute_offset+record_length];
                let resident_attribute_slice = &attribute[ARH_RES_LENGTH..];
                let nonresident_attribute_slice = &attribute[ARH_NONRES_START_OFFSET..];
                let formcode : u8 = attribute[ARH_FORM_CODE_OFFSET];

                //println!("{:?}", attribute);

                match attribute_type_code {
                    ATTR_STANDARD_INFORMATION => {
                        let std_info = MftStandardInformation::new(resident_attribute_slice);
                        is_compressed = std_info.get_permissions() & 0x800u32 > 0;

                        mft_record.standard_information = Some(std_info);
                    },
                    ATTR_FILE_NAME => {
                        // If there is only one FILE_NAME attribute, it is both the short and long name, if there are two, the first
                        // is the short name and the second is the lone one
                        if mft_record.file_name_info.is_none() {
                            //println!("FIRST: {}", &file_name_info.get_file_name());
                            mft_record.file_name_info = Some(MftFileNameInfo::new(resident_attribute_slice));
                            mft_record.short_file_name_info = Some(MftFileNameInfo::new(resident_attribute_slice));
                        } else {
                            //println!("SECOND: {}", &file_name_info.get_file_name());
                            mft_record.file_name_info = Some(MftFileNameInfo::new(resident_attribute_slice));
                        }
                    },
                    ATTR_DATA => {
                        //println!("Data form code: {}", formcode);
                        if formcode == FORM_CODE_NONRESIDENT {

                            mft_record.file_data_info = Some(MftFileDataInfo::NonResident(MftNonResidentFileData::new(nonresident_attribute_slice)));

                            /*let _lowest_vcn = LittleEndian::read_u64(&attribute[ARH_NONRES_LOWEST_VCN_OFFSET..ARH_NONRES_LOWEST_VCN_OFFSET+8]);
                            let _highest_vcn = LittleEndian::read_u64(&attribute[ARH_NONRES_HIGHEST_VCN_OFFSET..ARH_NONRES_HIGHEST_VCN_OFFSET+8]);

                            let mapping_pairs_offset = LittleEndian::read_u16(&attribute[ARH_NONRES_MAPPING_PAIRS_OFFSET_OFFSET..ARH_NONRES_MAPPING_PAIRS_OFFSET_OFFSET+2]);

                            let _allocated_length = LittleEndian::read_i64(&attribute[ARH_NONRES_ALLOCATED_LENGTH_OFFSET..ARH_NONRES_ALLOCATED_LENGTH_OFFSET+8]);
                            let file_size = LittleEndian::read_i64(&attribute[ARH_NONRES_FILE_SIZE_OFFSET..ARH_NONRES_FILE_SIZE_OFFSET+8]);
                            let _valid_data_length = LittleEndian::read_i64(&attribute[ARH_NONRES_VALID_DATA_LENGTH_OFFSET..ARH_NONRES_VALID_DATA_LENGTH_OFFSET+8]);

                            //println!("LVCN: {}  HVCN: {}", lowest_vcn, highest_vcn);
                            //println!("Allocated length: {}  File size: {}  Valid data len: {}", allocated_length, file_size, valid_data_length);

                            //println!("Mapping pairs offset: {:#x}", mapping_pairs_offset);

                            // Decode the runs
                            // I don't know how to decode a compressed file yet
                            if !is_compressed {
                                let mut run_offset = mapping_pairs_offset as usize;

                                let mut runs : NtfsFileReader = NtfsFileReader::new(4096, file_size);
    
                                while run_offset < attribute.len() {
                                    let current_run = &attribute[run_offset..];
                                    
                                    match read_run(current_run) {
                                        Ok((0,0,0)) => {
                                            // End of runs, break!
                                            //println!("End of runs!");
                                            //println!("{:?}", runs);
                                            break;
                                        },
                                        Ok(res) => {
                                            //println!("Got run! length: {:#x}  offset: {:#x}  run_size: {}", res.0, res.1, res.2);
                                            run_offset += res.2;
                                            runs.add_run(res.1, res.0);
                                        },
                                        Err(()) => {
                                            return Err("Error reading run!!".to_owned());
                                        }
                                    }
                                }
    
                                mft_record.file_data_info = Some(MftFileDataInfo::NonResident(runs));    
                            }*/
                        }
                    },
                    _ => {
                        //println!("Unhandled attribute type: {:#x}", attribute_type_code);
                    }
                }
            } else {
                println!("Record {}: Read invalid attribute record size of {} for attribute type {:#x} at offset {:#x}, skipping the rest of the record", record_id, record_length, attribute_type_code, attribute_offset+ARH_RECORD_LENGTH_OFFSET);
                break;
            }

            attribute_offset += record_length as usize;
        }

        Ok(Some(mft_record))
    } else if signature == 0 {
        Ok(None)
    } else {
        // Bad/corrupt signature
        Err(format!("Signature was corrupt, expected 0x{:#x} got 0x{:#x}", EXPECTED_SIGNATURE, signature))
    }
}

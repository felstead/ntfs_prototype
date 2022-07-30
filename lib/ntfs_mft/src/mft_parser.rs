use byteorder::*;
use crate::common::*;
use crate::mft_types::*;

#[derive(Default)]
pub struct MftRecord<'a> {
    pub id : u64,
    pub file_type : FileType,
    pub usage_status : FileUsageStatus,

    all_attributes : [Option<MftAttributeBuffer<'a>>; 16],
    attribute_count : usize,

    // Special lookups - TODO: benchmark with and without these
    /*
    standard_information_index : Option<usize>,
    file_name_info_index : Option<usize>,
    short_file_name_info_index : Option<usize>,
    */

}

impl<'a> MftRecord<'a> {

    pub fn get_all_attributes(&self) -> &[Option<MftAttributeBuffer<'a>>; 16] {
        &self.all_attributes
    }

    pub fn get_attribute_count(&self) -> usize {
        self.attribute_count
    }

    pub fn add_attribute(&mut self, slice : &'a [u8]) -> Result<(), String> {
        if self.attribute_count < self.all_attributes.len() {
            let attr = MftAttributeBuffer::new(slice)?;
            self.all_attributes[self.attribute_count] = Some(attr);
            self.attribute_count += 1;

            return Ok(())
        }

        panic!("Too many attributes!!");
    }

    pub fn get_standard_information(&'a self) -> Option<MftStandardInformation<'a>> {
        if let Some(&buffer) = self.get_first_attribute(ATTR_STANDARD_INFORMATION).as_ref() {
            Some(MftStandardInformation::new(&buffer.get_data_slice()))
        } else {
            None
        }
    }

    pub fn get_file_name_info(&'a self) -> Option<MftFileNameInfo<'a>> {
        if let Some(&buffer) = self.get_first_attribute(ATTR_FILE_NAME).as_ref() {
            // TODO: Get short vs long
            Some(MftFileNameInfo::new(&buffer.get_data_slice()))
        } else {
            None
        }
    }

    pub fn get_file_data_info(&'a self) -> Option<MftFileDataInfo<'a>> {
        if let Some(&buffer) = self.get_first_attribute(ATTR_DATA).as_ref() {
            if buffer.get_form_code() == FORM_CODE_NONRESIDENT {
                Some(MftFileDataInfo::NonResident(MftNonResidentFileData::new(buffer.get_data_slice())))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn get_first_attribute(&'a self, attr_type : u32) -> Option<&MftAttributeBuffer<'a>> {
        self.iter().find(|a| a.get_attribute_type() == attr_type )
    }

    pub fn iter(&'a self) -> MftRecordAttributeIterator<'a> {
        MftRecordAttributeIterator { parent: &self, current_record_offset: 0 }
    }
}

pub struct MftRecordAttributeIterator<'a> {
    parent : &'a MftRecord<'a>,
    current_record_offset: usize
}

impl<'a> Iterator for MftRecordAttributeIterator<'a> {
    type Item = &'a MftAttributeBuffer<'a>;
    
    fn next(&mut self) -> Option<&'a MftAttributeBuffer<'a>> {
        if self.current_record_offset < self.parent.get_attribute_count() {
            self.current_record_offset += 1;
            Some(&self.parent.all_attributes[self.current_record_offset - 1].as_ref().unwrap())
        } else {
            None
        }
    }
}

pub struct MftRecordsChunkBuffer<'a> {
    first_record_id : u64,
    buffer : &'a mut [u8]
}

impl<'a> MftRecordsChunkBuffer<'a> {
    pub fn new(buffer : &'a mut [u8], first_record_id : u64) -> Self {
        MftRecordsChunkBuffer {
            first_record_id,
            buffer
        }
    }

    pub fn get_mutable_buffer(&mut self) -> &mut[u8] {
        &mut self.buffer
    }

    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub fn set_first_record_id(&mut self, id : u64) {
        self.first_record_id = id;
    }

    pub fn iter(&'a self) -> MftRecordsChunkBufferIterator<'a> {
        MftRecordsChunkBufferIterator::<'a> { parent: &self, current_record_offset: 0 }
    }
}

pub struct MftRecordsChunkBufferIterator<'a> {
    parent : &'a MftRecordsChunkBuffer<'a>,
    current_record_offset: usize
}

impl<'a> Iterator for MftRecordsChunkBufferIterator<'a> {
    type Item = Result<Option<MftRecord<'a>>, String>;

    fn next(&mut self) -> Option<Result<Option<MftRecord<'a>>, String>> {
        let max_offset = self.parent.buffer.len() - MFT_RECORD_SIZE;
        let current_record_id = (self.current_record_offset / MFT_RECORD_SIZE) as u64 + self.parent.first_record_id; 
        
        if self.current_record_offset < max_offset {
            let record_slice : &'a [u8] = &self.parent.buffer[self.current_record_offset..self.current_record_offset+MFT_RECORD_SIZE];
            let result = read_single_mft_record(record_slice, current_record_id);

            self.current_record_offset += MFT_RECORD_SIZE;

            Some(result)
        } else {
            None
        }
    }
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

        while attribute_offset < MFT_RECORD_SIZE {
            let attribute_type_code = LittleEndian::read_u32(&record[attribute_offset..attribute_offset+4]);
            if attribute_type_code == 0xffffffff {
                break;
            }
            // While the record length is a u32, it seems like only the bottom 16 bits are the record length.
            // Am I messing this up with an ATTRIBUTE_LIST_ENTRY?
            let record_length = LittleEndian::read_u16(&record[attribute_offset+ARH_RECORD_LENGTH_OFFSET..attribute_offset+ARH_RECORD_LENGTH_OFFSET+2]) as usize;
//            println!("Reading attribute at offset {:#x}-{:#x}, type code {:#x}, record length: {}", attribute_offset, attribute_offset + record_length, attribute_type_code, record_length);

            if record_length > 0 && record_length <= MFT_RECORD_SIZE {

                let attribute = &record[attribute_offset..attribute_offset+record_length];

                mft_record.add_attribute(attribute)?;

                /* 
                //println!("{:?}", attribute);
                match attribute_type_code {
                    ATTR_STANDARD_INFORMATION => {
                        let std_info = MftStandardInformation::new(resident_attribute_slice);

                        mft_record.standard_information = Some(std_info);
                    },
                    ATTR_FILE_NAME => {
                        let file_name_info = MftFileNameInfo::new(resident_attribute_slice);

                        // 2 is the short "DOS" namespace, e.g. SOMENA~1.TXT
                        if file_name_info.get_namespace() == 2 {
                            mft_record.short_file_name_info = Some(file_name_info);
                        } else {
                            mft_record.file_name_info = Some(file_name_info);
                        }
                    },
                    ATTR_DATA => {
                        //println!("Data form code: {}", formcode);
                        if formcode == FORM_CODE_NONRESIDENT {

                            mft_record.file_data_info = Some(MftFileDataInfo::NonResident(MftNonResidentFileData::new(nonresident_attribute_slice)));

                        }
                    },
                    _ => {
                        //println!("Unhandled attribute type: {:#x}", attribute_type_code);
                    }
                }*/
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

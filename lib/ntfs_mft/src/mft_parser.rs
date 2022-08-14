use byteorder::*;
use crate::common::*;
use crate::mft_types::*;
use crate::slice_utils::*;

#[derive(Default)]
pub struct MftRecord<'a> {
    pub id : u64,
    pub file_type : FileType,
    pub usage_status : FileUsageStatus,
    pub fixup_okay : bool,
    pub fixup_expected_value : u16,
    pub fixup_replacement1 : u16,
    pub fixup_replacement2 : u16,

    full_record_slice : &'a [u8],
    all_attributes : [Option<MftAttribute<'a>>; 16],
    attribute_count : usize,
}

impl<'a> MftRecord<'a> {

    const MR_SIGNATURE : MftDataField<'a, u32> = MftDataField::<u32>::new("Signature", 0x00);
    const MR_FIXUP_ARRAY_OFFSET : MftDataField<'a, u16> = MftDataField::<u16>::new("FixupArrayOffset", 0x04);
    const MR_FIXUP_ARRAY_SIZE : MftDataField<'a, u16> = MftDataField::<u16>::new("FixupArraySize", 0x06);
    const MR_HARD_LINK_COUNT : MftDataField<'a, u16> = MftDataField::<u16>::new("HardLinkCount", 0x12);
    const MR_BASE_RECORD_ADDRESS : MftDataField<'a, u48> = MftDataField::<u48>::new("BaseRecordAddress", 0x20);
    const MR_BASE_RECORD_SEQ_ID : MftDataField<'a, u16> = MftDataField::<u16>::new("BaseRecordSequenceId", 0x26);
    const MR_RECORD_ID : MftDataField<'a, u32> = MftDataField::<u32>::new("MftRecordId", 0x2C);

    pub fn new(record : &'a mut [u8], record_id : u64) -> Result<Option<Self>, String> {
        // Now we have a buffer, we can operate on it safely
        // This can also be done unsafely by plonking structs on top of it, but the whole point of Rust is to be safe, so ¯\_(ツ)_/¯
        // Struct plonking using something like this may be faster, but need to measure:
        // let header = buffer.as_ptr().offset(MFT_RECORD_SIZE as isize) as *const FILE_RECORD_SEGMENT_HEADER;

        if record.len() != MFT_RECORD_SIZE {
            return Err(format!("Received buffer of invalid size, expected {}, got {}", MFT_RECORD_SIZE, record.len()))
        }

        let signature : u32 = MftRecord::MR_SIGNATURE.read(&record);

        if signature == EXPECTED_SIGNATURE {
            let internal_record_id = MftRecord::MR_RECORD_ID.read(record);
            if internal_record_id != record_id as u32 {
                panic!("Mft record ID doesn't match passed in record ID");
            }

            // Perform the fixup
            let mut fixup_okay = false;
            let fixup_array_offset = LittleEndian::read_u16(&record[4..6]);
            let fixup_array_size = LittleEndian::read_u16(&record[6..8]);

            let fixup_array = &record[fixup_array_offset as usize..fixup_array_offset as usize +(fixup_array_size as usize *2)];
            
            let expected_value = LittleEndian::read_u16(&fixup_array[0..2]);
            let replacement1 = LittleEndian::read_u16(&fixup_array[2..4]);
            let replacement2 = LittleEndian::read_u16(&fixup_array[4..6]);

            if expected_value == LittleEndian::read_u16(&record[510..512]) && expected_value == LittleEndian::read_u16(&record[1022..1024]) {
                //println!("Fixup okay!  Found {:#x} at both locations", expected_value);
                LittleEndian::write_u16(&mut record[510..512], replacement1);
                LittleEndian::write_u16(&mut record[1022..1024], replacement2);
                fixup_okay = true;
            } else {
                println!("BAD FIXUP #{} - expected {}, got {} and {}", record_id, expected_value, LittleEndian::read_u16(&record[510..512]), LittleEndian::read_u16(&record[1022..1024]));
            }

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
                full_record_slice : record,
                fixup_okay,
                fixup_expected_value: expected_value,
                fixup_replacement1 : replacement1,
                fixup_replacement2 : replacement2,
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

                let record_length = LittleEndian::read_u32(&record[attribute_offset+ARH_RECORD_LENGTH_OFFSET..attribute_offset+ARH_RECORD_LENGTH_OFFSET+4]) as usize;

                if record_length > 0 && record_length <= MFT_RECORD_SIZE {

                    let attribute = &record[attribute_offset..attribute_offset+record_length];

                    mft_record.add_base_attribute(attribute)?;
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

    pub fn get_all_attributes(&self) -> &[Option<MftAttribute<'a>>; 16] {
        &self.all_attributes
    }

    pub fn get_attribute_count(&self) -> usize {
        self.attribute_count
    }

    pub fn add_base_attribute(&mut self, slice : &'a [u8]) -> Result<(), String> {
        if self.attribute_count < self.all_attributes.len() {
            let attr = MftAttributeBuffer::new(slice)?;

            // Special case here - we need to populate the extension attributes if we have an ATTRIBUTE_LIST record
            if attr.get_attribute_type() == ATTR_ATTRIBUTE_LIST {
                if attr.get_form_code() == FORM_CODE_NONRESIDENT {
                    println!("Can't parse non-resident attribute list in record #{}", self.id);
                } else {
                    let attribute_list = MftAttributeList::new(attr.get_data_slice());

                    for attr in attribute_list.iter() {
                        if attr.get_record_id() != self.id {
                            // This is an extension record
                            self.add_extension_attribute(&attr)?;
                        }
                    }    
                }
            }

            // Take ownership of the attribute
            self.all_attributes[self.attribute_count] = Some(MftAttribute::Base(attr));
            self.attribute_count += 1;

            return Ok(())
        }

        panic!("Too many attributes!!");
    }

    pub fn add_extension_attribute(&mut self, extension_record : &MftAttributeListEntry) -> Result<(), String> {
        if self.attribute_count < self.all_attributes.len() {
            let ext_attr =  MftAttributeReference::new(extension_record);
            self.all_attributes[self.attribute_count] = Some(MftAttribute::Extension(ext_attr));
            self.attribute_count += 1;

            return Ok(())
        }

        panic!("Too many attributes!!");
    }

    pub fn is_base_record(&self) -> bool {
        self.get_base_record_id() != 0
    }

    pub fn get_base_record_id(&self) -> u64 {
        Self::MR_BASE_RECORD_ADDRESS.read(self.full_record_slice).into()
    }

    pub fn get_hard_link_count(&self) -> u16 {
        Self::MR_HARD_LINK_COUNT.read(self.full_record_slice)
    }

    pub fn get_standard_information(&'a self) -> Option<MftStandardInformation<'a>> {
        if let Some(MftAttribute::Base(buffer)) = self.get_first_attribute(ATTR_STANDARD_INFORMATION).as_ref() {
            Some(MftStandardInformation::new(&buffer.get_data_slice()))
        } else {
            None
        }
    }

    pub fn get_file_name_info(&'a self) -> Option<MftFileNameInfo<'a>> {
        self.iter()
            .filter_map(|a| 
                if let MftAttribute::Base(attr) = a {
                    if attr.get_attribute_type() == ATTR_FILE_NAME {
                        Some(MftFileNameInfo::new(attr.get_data_slice()))
                    } else {
                        None
                    }
                } else {
                    None
                })
            .find(|a| a.get_namespace() != 2) // 2 is DOS
    }

    pub fn get_file_data_info(&'a self) -> Option<MftFileDataInfo<'a>> {
        if let Some(MftAttribute::Base(buffer)) = self.get_first_attribute(ATTR_DATA).as_ref() {
            if buffer.get_form_code() == FORM_CODE_NONRESIDENT {
                Some(MftFileDataInfo::NonResident(MftNonResidentAttribute::new(buffer.get_data_slice())))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn get_first_attribute(&'a self, attr_type : u32) -> Option<&MftAttribute<'a>> {
        self.iter().find(|a| 
            match *a {
                MftAttribute::Base(attr) => attr.get_attribute_type() == attr_type,
                MftAttribute::Extension(attr) => attr.get_attribute_type() == attr_type
            }
        )
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
    type Item = &'a MftAttribute<'a>;
    
    fn next(&mut self) -> Option<Self::Item> {
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
    num_records : usize,
    buffer : &'a mut [u8]
}

impl<'a> MftRecordsChunkBuffer<'a> {
    pub fn new(buffer : &'a mut [u8], first_record_id : u64, num_records : usize) -> Self {
        MftRecordsChunkBuffer {
            first_record_id,
            buffer,
            num_records
        }
    }

    pub fn get_mutable_buffer(&'a mut self) -> &'a mut[u8] {
        &mut self.buffer
    }

    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub fn get_max_record_id(&self) -> u64 {
        self.first_record_id + self.num_records as u64
    }

    pub fn set_first_record_id(&mut self, id : u64) {
        self.first_record_id = id;
    }

    pub fn iter(&'a mut self) -> MftRecordsChunkBufferIterator<'a> {
        let record_id = self.first_record_id;
        MftRecordsChunkBufferIterator::<'a> { parent: self, current_record_id: record_id }
    }
}

pub struct MftRecordsChunkBufferIterator<'a> {
    parent : &'a mut MftRecordsChunkBuffer<'a>,
    current_record_id: u64
}

impl<'a> Iterator for MftRecordsChunkBufferIterator<'a> {
    type Item = Result<Option<MftRecord<'a>>, String>;

    fn next(&mut self) -> Option<Result<Option<MftRecord<'a>>, String>> {
        if self.parent.buffer.len() == 0 || self.current_record_id >= self.parent.get_max_record_id() {
            None
        } else {
            // Crazy shenanigans referenced from here: https://users.rust-lang.org/t/magic-lifetime-using-iterator-next/34729/4
            let slice = std::mem::replace(&mut self.parent.buffer, &mut []);
            
            let (record, remainder) = slice.split_at_mut(MFT_RECORD_SIZE);

            let result = MftRecord::new(record, self.current_record_id);

            self.parent.buffer = remainder;
    
            self.current_record_id += 1;

            Some(result)
        }
    }
}

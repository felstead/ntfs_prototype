use windows_sys::Win32::Foundation::FILETIME;
use byteorder::*;
use std::mem::size_of;
use std::ops::Range;

use crate::common::*;
use crate::ntfs_file_reader::NtfsFileReader;
use crate::slice_utils::*;

pub struct MftAttributeBuffer<'a> {
    attribute_type : u32,
    slice_data : &'a[u8]
}

impl<'a> MftAttributeBuffer<'a> {
    pub fn new(slice : &'a [u8]) -> Result<Self, String> {
        const MIN_ATTRIBUTE_SIZE : usize = 8; // Get this for real
        if slice.len() < MIN_ATTRIBUTE_SIZE {
            Err(format!("Attribute slice was not of expected size, got {}, expected at least {}", slice.len(), MIN_ATTRIBUTE_SIZE))

        } else {
            let attr = MftAttributeBuffer {
                attribute_type : LittleEndian::read_u32(slice),
                slice_data : slice
            };
            Ok(attr)
        }
    }

    pub fn get_attribute_type(&self) -> u32 {
        self.attribute_type
    }

    pub fn get_form_code(&self) -> u8 {
        self.slice_data[ARH_FORM_CODE_OFFSET]
    }

    /// Returns the data slice for this attribute dependent on the formcode
    /// If the form code indicates a nonresident attribute it will get the slice from
    /// the offset of ARH_NONRES_START_OFFSET, and if resident from ARH_RES_LENGTH
    pub fn get_data_slice(&self) -> &'a [u8] {
        if self.get_form_code() == FORM_CODE_NONRESIDENT {
            &self.slice_data[ARH_NONRES_START_OFFSET..]
        } else {
            &self.slice_data[ARH_RES_LENGTH..]
        }
    }
}

pub enum MftFileDataInfo<'a> {
    Resident(MftResidentFileData<'a>),
    NonResident(MftNonResidentFileData<'a>)
}

impl<'a> MftFileDataInfo<'a> {
    pub fn get_file_size(&self) -> u64 { 
        match self {
            Self::NonResident(nr) => nr.get_file_size(),
            Self::Resident(r) => r.get_file_size(),
        } 
    }
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

pub struct MftStandardInformation<'a> {
    slice_data : &'a[u8]
}

#[allow(dead_code)]
impl<'a> MftStandardInformation<'a> {
    // == STANDARD_INFORMATION offsets
    const SI_CREATE_TIMESTAMP : AttributeDataField<'a, FILETIME> = AttributeDataField::<FILETIME>::new( "CreatedTimestamp", 0x00);
    const SI_ALTERED_TIMESTAMP : AttributeDataField<'a, FILETIME> = AttributeDataField::<FILETIME>::new( "AlteredTimestamp", 0x08);
    const SI_MFT_CHANGED_TIMESTAMP : AttributeDataField<'a, FILETIME> = AttributeDataField::<FILETIME>::new( "ChangedTimestamp", 0x10);
    const SI_READ_TIMESTAMP : AttributeDataField<'a, FILETIME> = AttributeDataField::<FILETIME>::new( "ReadTimestamp", 0x18);
    const SI_PERMISSIONS : AttributeDataField<'a, u32> = AttributeDataField::<u32>::new( "Permissions", 0x20);
    const SI_MAX_VERSIONS : AttributeDataField<'a, u32> = AttributeDataField::<u32>::new( "MaxVersions", 0x24);
    const SI_VERSION_NUMBER : AttributeDataField<'a, u32> = AttributeDataField::<u32>::new( "VersionNumber", 0x28);
    const SI_CLASS_ID : AttributeDataField<'a, u32> = AttributeDataField::<u32>::new( "ClassId", 0x2C);
    const SI_OWNER_ID : AttributeDataField<'a, u32> = AttributeDataField::<u32>::new( "OwnerId", 0x30);
    const SI_SECURITY_ID : AttributeDataField<'a, u32> = AttributeDataField::<u32>::new( "SecurityId", 0x34);
    const SI_QUOTA_CHARGED : AttributeDataField<'a, u64> = AttributeDataField::<u64>::new( "QuotaCharged", 0x38);
    const SI_USN : AttributeDataField<'a, u64> = AttributeDataField::<u64>::new( "Usn", 0x40);

    pub fn new(slice_data: &'a[u8]) -> Self {
        Self { slice_data }
    }

    pub fn get_field_display_info(&self) -> Vec<AttributeDisplayInfo> {
        vec!(
            MftStandardInformation::SI_CREATE_TIMESTAMP.get_display_info(self.slice_data),
            MftStandardInformation::SI_ALTERED_TIMESTAMP.get_display_info(self.slice_data),
            MftStandardInformation::SI_MFT_CHANGED_TIMESTAMP.get_display_info(self.slice_data),
            MftStandardInformation::SI_READ_TIMESTAMP.get_display_info(self.slice_data),
            MftStandardInformation::SI_PERMISSIONS.get_display_info(self.slice_data),
            MftStandardInformation::SI_MAX_VERSIONS.get_display_info(self.slice_data),
            MftStandardInformation::SI_VERSION_NUMBER.get_display_info(self.slice_data),
            MftStandardInformation::SI_CLASS_ID.get_display_info(self.slice_data),
            MftStandardInformation::SI_OWNER_ID.get_display_info(self.slice_data),
            MftStandardInformation::SI_SECURITY_ID.get_display_info(self.slice_data),
            MftStandardInformation::SI_QUOTA_CHARGED.get_display_info(self.slice_data),
            MftStandardInformation::SI_USN.get_display_info(self.slice_data),
        )
    }

    pub fn get_create_timestamp(&self) -> FILETIME { MftStandardInformation::SI_CREATE_TIMESTAMP.read(self.slice_data) }
    pub fn get_altered_timestamp(&self) -> FILETIME { MftStandardInformation::SI_ALTERED_TIMESTAMP.read(self.slice_data) }
    pub fn get_mft_changed_timestamp(&self) -> FILETIME { MftStandardInformation::SI_MFT_CHANGED_TIMESTAMP.read(self.slice_data) }
    pub fn get_read_timestamp(&self) -> FILETIME { MftStandardInformation::SI_READ_TIMESTAMP.read(self.slice_data) }

    pub fn get_permissions(&self) -> u32 { MftStandardInformation::SI_PERMISSIONS.read(self.slice_data) }
}


pub struct MftFileNameInfo <'a> {
    slice_data : &'a[u8]
}

#[allow(dead_code)]
impl<'a> MftFileNameInfo<'a> {
    // FILE_NAME offsets
    // From https://docs.microsoft.com/en-us/windows/win32/devnotes/file-name
    pub const FN_PARENT_DIR_REFERENCE_OFFSET : usize = 0;
    pub const FN_CREATE_TIMESTAMP_OFFSET : usize = 8;
    pub const FN_ALTERED_TIMESTAMP_OFFSET : usize = 16;
    pub const FN_MFT_CHANGED_TIMESTAMP_OFFSET : usize = 24;
    pub const FN_READ_TIMESTAMP_OFFSET : usize = 32;
    pub const FN_ALLOCATED_SIZE_OF_FILE_OFFSET : usize = 40;
    pub const FN_REAL_SIZE_OF_FILE_OFFSET : usize = 48;
    // Some others
    pub const FN_FILE_NAME_LENGTH_CHARS_OFFSET : usize = 64;
    pub const FN_FILE_NAME_NAMESPACE_OFFSET : usize = 65;
    pub const FN_FILE_NAME_DATA_OFFSET : usize = 66;

    const FN_PARENT_DIR_REFERENCE : AttributeDataField<'a, u48> = AttributeDataField::<u48>::new("ParentDataDirId", 0x0);
    const FN_ALLOCATED_SIZE_OF_FILE : AttributeDataField<'a, u64> = AttributeDataField::<u64>::new("AllocatedSizeOfFile", 0x28);
    const FN_REAL_SIZE_OF_FILE : AttributeDataField<'a, u64> = AttributeDataField::<u64>::new("RealSizeOfFile", 0x30);

    const FN_FILE_NAME_LENGTH : AttributeDataField<'a, u8> = AttributeDataField::<u8>::new("FileNameLengthInChars", 0x40);
    const FN_FILE_NAME_NAMESPACE : AttributeDataField<'a, u8> = AttributeDataField::<u8>::new("Namespace", 0x41);

    const FN_FILE_NAME : AttributeDataField<'a, &'a [u8]> = AttributeDataField::<&'a [u8]>::new_dynamic("FileNameData", 0x42, |slice| { MftFileNameInfo::FN_FILE_NAME_LENGTH.read(slice) as usize * 2 });

    pub fn new(slice_data: &'a[u8]) -> Self {
        Self { slice_data }
    }

    pub fn get_field_display_info(&self) -> Vec<AttributeDisplayInfo> {
        vec!(
            MftFileNameInfo::FN_PARENT_DIR_REFERENCE.get_display_info(self.slice_data),
            MftFileNameInfo::FN_ALLOCATED_SIZE_OF_FILE.get_display_info(self.slice_data),
            MftFileNameInfo::FN_REAL_SIZE_OF_FILE.get_display_info(self.slice_data),
            MftFileNameInfo::FN_FILE_NAME_LENGTH.get_display_info(self.slice_data),
            MftFileNameInfo::FN_FILE_NAME_NAMESPACE.get_display_info(self.slice_data),
            MftFileNameInfo::FN_FILE_NAME.get_display_info(self.slice_data),
        )
    }

    pub fn get_file_name(&self) -> String { 
        let file_name_data_bytes = MftFileNameInfo::FN_FILE_NAME.read(self.slice_data);

        // This is "unsafe" but it really isn't assuming the slice is good
        let file_name_data_utf16 = unsafe { std::slice::from_raw_parts(file_name_data_bytes.as_ptr() as *const u16, file_name_data_bytes.len() / 2) };

        String::from_utf16_lossy(file_name_data_utf16)
    }

    pub fn get_parent_directory_id(&self) -> u64 { 
        // Only the top 48 bits are the actual file reference
        MftFileNameInfo::FN_PARENT_DIR_REFERENCE.read(self.slice_data).into()
        //LittleEndian::read_u48(&self.slice_data[MftFileNameInfo::FN_PARENT_DIR_REFERENCE_OFFSET..MftFileNameInfo::FN_PARENT_DIR_REFERENCE_OFFSET+6]) 
    }

    pub fn get_allocated_size_of_file(&self) -> u64 { MftFileNameInfo::FN_ALLOCATED_SIZE_OF_FILE.read(self.slice_data) }

    pub fn get_real_size_of_file(&self) -> u64 { MftFileNameInfo::FN_REAL_SIZE_OF_FILE.read(self.slice_data) }

    pub fn get_namespace(&self) -> u8 { MftFileNameInfo::FN_FILE_NAME_NAMESPACE.read(self.slice_data) }
}

pub struct MftResidentFileData <'a> {
    slice_data : &'a[u8]
}

#[allow(dead_code)]
impl<'a> MftResidentFileData<'a> {
    const RFD_FILE_SIZE_OFFSET : usize = 0;

    const RFD_FILE_SIZE : AttributeDataField<'a, u64> = AttributeDataField::<u64>::new("FileSize", 0x0);

    pub fn get_field_display_info(&self) -> Vec<AttributeDisplayInfo> {
        vec!(
            MftResidentFileData::RFD_FILE_SIZE.get_display_info(self.slice_data)
        )
    }

    pub fn get_file_size(&self) -> u64 { MftResidentFileData::RFD_FILE_SIZE.read(self.slice_data) }
}

pub struct MftNonResidentFileData <'a> {
    slice_data : &'a[u8]
}

#[allow(dead_code)]
impl<'a> MftNonResidentFileData<'a> {
    pub const NRFD_LOWEST_VCN_OFFSET : usize = 0;
    pub const NRFD_HIGHEST_VCN_OFFSET : usize = 8;
    pub const NRFD_MAPPING_PAIRS_OFFSET_OFFSET : usize = 16;
    pub const NRFD_ALLOCATED_LENGTH_OFFSET : usize = 24;
    pub const NRFD_FILE_SIZE_OFFSET : usize = 32;
    pub const NRFD_VALID_DATA_LENGTH_OFFSET : usize = 40;
    pub const NRFD_TOTAL_ALLOCATED_OFFSET : usize = 48;
    
    const NRFD_LOWEST_VCN : AttributeDataField<'a, u64> = AttributeDataField::<u64>::new("LowestVcn", 0x00);
    const NRFD_HIGHEST_VCN : AttributeDataField<'a, u64> = AttributeDataField::<u64>::new("HighestVcn", 0x08);
    const NRFD_MAPPING_PAIRS_OFFSET : AttributeDataField<'a, u16> = AttributeDataField::<u16>::new("MappingPairsOffset", 0x10);
    const NRFD_ALLOCATED_LENGTH : AttributeDataField<'a, u64> = AttributeDataField::<u64>::new("AllocatedLength", 0x18);
    const NRFD_FILE_SIZE : AttributeDataField<'a, u64> = AttributeDataField::<u64>::new("FileSize", 0x20);
    const NRFD_VALID_DATA_LENGTH : AttributeDataField<'a, u64> = AttributeDataField::<u64>::new("ValidDataLength", 0x28);

    const NRFD_DATA_RUNS : AttributeDataField<'a, &'a [u8]> = AttributeDataField::<&'a [u8]>::new_dynamic("DataRuns", 0x30, |slice| { slice.len() - 0x30 });
    // This field is only valid for compressed data apparently
        //  Totally allocated.  This field is only present for the first
        //  file record of a compressed stream.  It represents the sum of
        //  the allocated clusters for a file.
    //const NRFD_TOTAL_ALLOCATED : AttributeDataField<'a, u64> = AttributeDataField::<u64>::new("TotalAllocated", 0x30);

    pub fn new(slice_data: &'a[u8]) -> Self {
        Self { slice_data }
    }

    pub fn get_field_display_info(&self) -> Vec<AttributeDisplayInfo> {
        vec!(
            MftNonResidentFileData::NRFD_LOWEST_VCN.get_display_info(self.slice_data),
            MftNonResidentFileData::NRFD_HIGHEST_VCN.get_display_info(self.slice_data),
            MftNonResidentFileData::NRFD_MAPPING_PAIRS_OFFSET.get_display_info(self.slice_data),
            MftNonResidentFileData::NRFD_ALLOCATED_LENGTH.get_display_info(self.slice_data),
            MftNonResidentFileData::NRFD_FILE_SIZE.get_display_info(self.slice_data),
            MftNonResidentFileData::NRFD_VALID_DATA_LENGTH.get_display_info(self.slice_data),
            MftNonResidentFileData::NRFD_DATA_RUNS.get_display_info(self.slice_data),
        )
    }

    pub fn get_lowest_vcn(&self) -> u64 { MftNonResidentFileData::NRFD_LOWEST_VCN.read(self.slice_data) }
    pub fn get_highest_vcn(&self) -> u64 { MftNonResidentFileData::NRFD_HIGHEST_VCN.read(self.slice_data) }

    pub fn get_mapping_pairs_offset(&self) -> u16 { MftNonResidentFileData::NRFD_MAPPING_PAIRS_OFFSET.read(self.slice_data) }

    pub fn get_allocated_length(&self) -> u64 { MftNonResidentFileData::NRFD_ALLOCATED_LENGTH.read(self.slice_data) }
    pub fn get_file_size(&self) -> u64 { MftNonResidentFileData::NRFD_FILE_SIZE.read(self.slice_data) }
    pub fn get_valid_data_length(&self) -> u64 { MftNonResidentFileData::NRFD_VALID_DATA_LENGTH.read(self.slice_data) }

    pub fn get_direct_file_reader(&self, bytes_per_cluster : usize) -> Result<NtfsFileReader, String> {
        let mut run_offset = self.get_mapping_pairs_offset() as usize - ARH_NONRES_START_OFFSET;

        let mut runs : NtfsFileReader = NtfsFileReader::new(bytes_per_cluster, self.get_file_size());

        while run_offset < self.slice_data.len() {
            let current_run = &self.slice_data[run_offset..];
            
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

        Ok(runs)
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

        result |= (current_byte as i64) << (index * 8);

        is_negative = (current_byte & 0x80) > 0;

        bytes_remaining -= 1;
    }

    if is_negative {
        // Highest bit is negative, this means we need to pad out the rest of the bytes with 0xFF to make the result negative
        result |= -1i64 << (length * 8);
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
    fn run_varbyte_read_sparse() {
        let sparse_run_1 : [u8; 2] = [0x01, 0x07];
        let result_1 = super::read_run(&sparse_run_1).unwrap();

        assert_eq!(result_1.0, 7);
        assert_eq!(result_1.1, 0);
        assert_eq!(result_1.2, 2);
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
use windows_sys::Win32::Foundation::FILETIME;
use byteorder::*;

pub struct MftStandardInformation<'a> {
    slice_data : &'a[u8]
}

fn filetime_from_slice(slice_data : &[u8], offset : usize) -> FILETIME {
    FILETIME { 
        dwLowDateTime : LittleEndian::read_u32(&slice_data[offset..offset+4]), 
        dwHighDateTime : LittleEndian::read_u32(&slice_data[offset+4..offset+8])
    }
}

#[allow(dead_code)]
impl<'a> MftStandardInformation<'a> {
    // == STANDARD_INFORMATION offsets
    pub const SI_CREATE_TIMESTAMP_OFFSET : usize = 0;
    pub const SI_ALTERED_TIMESTAMP_OFFSET : usize = 8;
    pub const SI_MFT_CHANGED_TIMESTAMP_OFFSET : usize = 16;
    pub const SI_READ_TIMESTAMP_OFFSET : usize = 24;
    pub const SI_PERMISSIONS_OFFSET : usize = 32;
    pub const SI_MAX_VERSIONS_OFFSET : usize = 36;
    pub const SI_VERSION_NUMBER_OFFSET : usize = 40;
    pub const SI_CLASS_ID_OFFSET : usize = 44;
    pub const SI_OWNER_ID_OFFSET : usize = 48;
    pub const SI_SECURITY_ID_OFFSET : usize = 52;
    pub const SI_QUOTA_CHARGED_OFFSET : usize = 56;
    pub const SI_USN_OFFSET : usize = 62;

    pub fn new(slice_data: &'a[u8]) -> Self {
        Self { slice_data }
    }

    pub fn get_create_timestamp(&self) -> FILETIME { filetime_from_slice(self.slice_data, MftStandardInformation::SI_CREATE_TIMESTAMP_OFFSET ) }
    pub fn get_altered_timestamp(&self) -> FILETIME { filetime_from_slice(self.slice_data, MftStandardInformation::SI_ALTERED_TIMESTAMP_OFFSET ) }
    pub fn get_mft_changed_timestamp(&self) -> FILETIME { filetime_from_slice(self.slice_data, MftStandardInformation::SI_MFT_CHANGED_TIMESTAMP_OFFSET ) }
    pub fn get_read_timestamp(&self) -> FILETIME { filetime_from_slice(self.slice_data, MftStandardInformation::SI_READ_TIMESTAMP_OFFSET ) }

    pub fn get_permissions(&self) -> u32 { LittleEndian::read_u32(&self.slice_data[MftStandardInformation::SI_PERMISSIONS_OFFSET..MftStandardInformation::SI_PERMISSIONS_OFFSET+4]) }
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
    pub const FN_ALLOCATED_SIZE_OF_FILE : usize = 40;
    pub const FN_REAL_SIZE_OF_FILE : usize = 48;
    // Some others
    pub const FN_FILE_NAME_LENGTH_CHARS_OFFSET : usize = 64;
    pub const FN_FILE_NAME_DATA_OFFSET : usize = 66;

    pub fn new(slice_data: &'a[u8]) -> Self {
        Self { slice_data }
    }

    pub fn get_file_name(&self) -> String { 
        let file_name_length : usize = self.slice_data[MftFileNameInfo::FN_FILE_NAME_LENGTH_CHARS_OFFSET] as usize;
        let file_name_data_bytes = &self.slice_data[MftFileNameInfo::FN_FILE_NAME_DATA_OFFSET..MftFileNameInfo::FN_FILE_NAME_DATA_OFFSET + file_name_length];

        // This is "unsafe" but it really isn't assuming the slice is good
        let file_name_data_utf16 = unsafe { std::slice::from_raw_parts(file_name_data_bytes.as_ptr() as *const u16, file_name_length) };

        String::from_utf16_lossy(file_name_data_utf16)
    }

    pub fn get_parent_directory_id(&self) -> u64 { 
        // Only the top 48 bits are the actual file reference
        LittleEndian::read_u48(&self.slice_data[MftFileNameInfo::FN_PARENT_DIR_REFERENCE_OFFSET..MftFileNameInfo::FN_PARENT_DIR_REFERENCE_OFFSET+6]) 
    }
}
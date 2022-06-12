
// pub constants
pub const MFT_RECORD_SIZE : usize = 1024;

pub const EXPECTED_SIGNATURE : u32 = 0x454c4946; // The ASCII string "FILE" converted to a u32

// Offsets into the FILE_RECORD_SEGMENT_HEADER structure
// From https://docs.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header
pub const FRSH_FIRST_ATTRIBUTE_OFFSET : usize = 20;
pub const FRSH_FLAGS_OFFSET : usize = 22;

// File record flags
pub const FILE_RECORD_FLAG_DELETED_FILE : u16 = 0x00;
pub const FILE_RECORD_FLAG_EXISTING_FILE : u16 = 0x01;
pub const FILE_RECORD_FLAG_DELETED_DIR : u16 = 0x02;
pub const FILE_RECORD_FLAG_EXISTING_DIR : u16 = 0x03;

// Attribute form code
pub const _FORM_CODE_RESIDENT : u8 = 0x0;
pub const FORM_CODE_NONRESIDENT : u8 = 0x1;

// Offsets into the ATTRIBUTE_RECORD_HEADER structure
// From https://docs.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header
pub const _ARH_TYPE_CODE_OFFSET : usize = 0;
pub const ARH_FORM_CODE_OFFSET : usize = 8;
pub const ARH_RECORD_LENGTH_OFFSET : usize = 4;
pub const ARH_RES_LENGTH : usize = 24; // The offset to the end of a "resident" type header

// Non-resident attributes mark where the data for the attribute lives, which could include the data for the file
pub const ARH_NONRES_LOWEST_VCN_OFFSET : usize = 16;
pub const ARH_NONRES_HIGHEST_VCN_OFFSET : usize = 24;
pub const ARH_NONRES_MAPPING_PAIRS_OFFSET_OFFSET : usize = 32;
pub const ARH_NONRES_ALLOCATED_LENGTH_OFFSET : usize = 40;
pub const ARH_NONRES_FILE_SIZE_OFFSET : usize = 48;
pub const ARH_NONRES_VALID_DATA_LENGTH_OFFSET : usize = 56;

// From https://docs.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header
pub const ATTR_STANDARD_INFORMATION : u32 = 0x10;
pub const _ATTR_ATTRIBUTE_LIST : u32 = 0x20;
pub const ATTR_FILE_NAME : u32 = 0x30;
pub const ATTR_DATA : u32 = 0x80;

// Offsets into the FILE_NAME attribute
// From https://docs.microsoft.com/en-us/windows/win32/devnotes/file-name
pub const FN_FILE_NAME_LENGTH_CHARS_OFFSET : usize = 0x40;
pub const FN_FILE_NAME_DATA_OFFSET : usize = 0x42;
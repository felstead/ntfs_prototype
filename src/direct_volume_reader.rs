use windows_sys::{
    Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, CloseHandle, GetLastError},
    Win32::Storage::FileSystem::{FILE_GENERIC_READ,FILE_SHARE_READ,FILE_SHARE_WRITE,OPEN_EXISTING,CreateFileA,ReadFile},
    Win32::System::Ioctl::{NTFS_VOLUME_DATA_BUFFER,FSCTL_GET_NTFS_VOLUME_DATA},
    Win32::System::IO::{OVERLAPPED,OVERLAPPED_0,OVERLAPPED_0_0,DeviceIoControl}
};

use std::ffi::{CString, c_void};
use std::ops::Range;

pub const MFT_RECORD_SIZE : usize = 1024;

#[derive(Default, Debug)]
pub struct NtfsFileReader {
    physical_offset_runs : Vec<Range<i64>>,
    last_physical_offset : i64,
    local_offset_runs : Vec<Range<i64>>,
    last_local_offset : i64,
    cluster_size : i64,
    actual_file_size : i64
}

impl NtfsFileReader {
    pub fn new(cluster_size : i64, actual_file_size : i64) -> Self {
        NtfsFileReader { 
            cluster_size: cluster_size,
            actual_file_size: actual_file_size,
            ..Default::default()
       }
    }

    pub fn add_run(&mut self, cluster_run_start : i64, cluster_run_length : i64) {
        //println!("{:#x} .. {:#x}", relative_run_start, run_length);
        //println!("{:?}", self);

        // Convert the runs (in clusters) to actual byte offsets on disk
        let physical_run_start = (cluster_run_start * self.cluster_size) + self.last_physical_offset;
        let physical_run_end = physical_run_start + (cluster_run_length * self.cluster_size);

        self.physical_offset_runs.push(physical_run_start..physical_run_end);
        self.last_physical_offset = physical_run_start;

        // Calculate the relative "local" offsets of these runs within the files themselves
        let local_run_end = self.last_local_offset+physical_run_end-physical_run_start;
        self.local_offset_runs.push(self.last_local_offset..local_run_end);
        self.last_local_offset = local_run_end;

        //println!("{:?}", self);
    }

    pub fn iterate_physical_blocks_for_file(&self, file_relative_offset : i64, num_bytes : usize, mut block_reader: impl FnMut(i64, Range<i64>)) -> usize {
        // Start at our first offset and read as many runs as are required to fill our buffer
        let mut target_range = file_relative_offset .. file_relative_offset + num_bytes as i64;
        let mut buffer_offset : usize = 0;
        let mut bytes_read : usize = 0;

        for (i, local_run) in self.local_offset_runs.iter().enumerate() {
            if local_run.contains(&target_range.start) {
                // Check if our end is within this range too
                let delta = self.physical_offset_runs[i].start - local_run.start;

                if local_run.contains(&target_range.end) {
                    // We have everything we need in this block, just read from here and break
                    // Output the physical range to read from
                    block_reader(buffer_offset as i64, target_range.start + delta .. target_range.end + delta);

                    bytes_read += (target_range.end - target_range.start) as usize;
                    break;
                } else {
                    // Only read to the end of this range and continue
                    let bytes_to_read = (local_run.end - target_range.start) as usize;

                    // Read bytes
                    block_reader(buffer_offset as i64, target_range.start + delta .. target_range.start + delta + bytes_to_read as i64);

                    // Adjust range
                    buffer_offset += bytes_to_read;
                    target_range.start = local_run.end;
                    bytes_read += bytes_to_read;
                }
            }
        }

        bytes_read

    }

    // This function will read chunks of a file into the provided buffer directly from the disk, taking into account the file runs
    pub fn read_file_bytes(&self, file_relative_offset : i64, num_bytes : usize, buffer : &mut [u8], volume_handle: HANDLE) {
    }

}

#[cfg(test)]
mod test_ntfs_file_reader {
    #[test]
    fn iterate_physical_blocks_for_file() {
        let mut reader = super::NtfsFileReader::new(4096, 500000);

        reader.add_run(0x100, 16); // 65536 bytes starting at 0x100000 (0..65536)
        reader.add_run(0x10000, 24); // 98304 bytes starting at 0x100000 + 0x10000000 (65536..163840)
        reader.add_run(0x20000, 83); // 339968 bytes starting at 0x20000000 + 0x10100000 (163840..503808)

        // Read 200,000 bytes from 0, we should get:
        // - a read of 65536 bytes starting at 0x100000, 
        // - then 98304 bytes starting at 0x10100000
        // - then 36160 bytes starting at 0x30100000

        let expected_results_1 = vec![
            (0i64, 0x100000i64..0x110000i64),
            (65536i64, 0x10100000i64..0x10118000i64),
            (163840i64, 0x30100000i64..0x30108d40i64)
        ];

        let mut result_index = 0;
        reader.iterate_physical_blocks_for_file(0, 200000, |buffer_offset, read_range| {
            //println!("{} {:#x}..{:#x} ({} bytes)", buffer_offset, read_range.start, read_range.end, read_range.end - read_range.start);
            let expected = &expected_results_1[result_index];
            assert_eq!((buffer_offset, read_range), *expected);
            result_index += 1;
        });

        // Read 350,000 bytes from 150,000, we should get:
        // - 13840 bytes starting at 0x101149f0
        // - then 339968-3808=336160 bytes starting at 0x30100000
        let expected_results_2 = vec![
            (0i64, 0x101149f0i64..0x10118000i64),
            (13840i64,0x30100000i64..0x30152120i64)
        ];

        result_index = 0;
        reader.iterate_physical_blocks_for_file(150000, 350000, |buffer_offset, read_range| {
            let expected = &expected_results_2[result_index];
            //println!("{} {:#x}..{:#x} ({} bytes)", buffer_offset, read_range.start, read_range.end, read_range.end - read_range.start);
            assert_eq!((buffer_offset, read_range), *expected);
            result_index += 1;
        });

        // Simple read wholly within a single run
        reader.iterate_physical_blocks_for_file(200000, 200000, |buffer_offset, read_range| {
            //println!("{} {:#x}..{:#x} ({} bytes)", buffer_offset, read_range.start, read_range.end, read_range.end - read_range.start);
            assert_eq!((buffer_offset, read_range), (0, 0x30108d40i64..0x30139a80i64))
        });

    }
}

pub struct DirectVolumeMftReader {
    drive_letter : String,
    volume_path : String,
    volume_handle : HANDLE,
    ntfs_volume_data : NTFS_VOLUME_DATA_BUFFER,
    is_open : bool,
    mft_reader : NtfsFileReader,
}

impl Default for DirectVolumeMftReader {
    #[inline]
    fn default() -> DirectVolumeMftReader {
        DirectVolumeMftReader { 
            drive_letter: String::default(), 
            volume_path: String::default(), 
            volume_handle: HANDLE::default(), 
            ntfs_volume_data: unsafe { std::mem::MaybeUninit::<NTFS_VOLUME_DATA_BUFFER>::zeroed().assume_init() },
            is_open: false,
            mft_reader: NtfsFileReader::default()
        }
    }
}

impl Drop for DirectVolumeMftReader {
    #[inline]
    fn drop(&mut self) {
        if self.volume_handle != HANDLE::default() {
            unsafe {
                let _ = CloseHandle(self.volume_handle);
            }
        }
    }
}

impl DirectVolumeMftReader {

    pub fn get_mft_start_offset_bytes(&self) -> i64 {
        if !self.is_open {
            panic!("MFT was not opened!")
        }
        self.ntfs_volume_data.BytesPerCluster as i64 * self.ntfs_volume_data.MftStartLcn
    }

    pub fn get_mft_size_bytes(&self) -> i64 {
        if !self.is_open {
            panic!("MFT was not opened!")
        }

        self.ntfs_volume_data.MftValidDataLength
    }

    pub fn get_max_number_of_records(&self) -> usize {
        (self.get_mft_size_bytes() / MFT_RECORD_SIZE as i64) as usize
    }

    pub fn open_mft(&mut self, drive_letter : &str) -> Result<(), String> {
        
        // Validate drive letter, should be something like "c: or "C:"
        let mut is_valid_drive_letter = false;
        if drive_letter.len() == 2 {
            // Should only be ascii, if not then yikes
            let chars  = drive_letter.as_bytes();

            let letter = chars[0] as char;
            if ((letter >= 'a' && letter <= 'z') || (letter > 'A' && letter < 'Z')) && chars[1] as char == ':' {
                is_valid_drive_letter = true;
            }
        }

        if !is_valid_drive_letter {
            return Err(format!("Invalid drive letter: {}", drive_letter));
        }

        self.drive_letter = drive_letter.to_owned();

        // This could all be in one function but I'm separating them for readability
        self.open_drive()?;
        self.read_mft_info()?;

        // Parse the MFT file

        self.is_open = true;

        Ok(())
    }

    fn open_drive(&mut self) -> Result<(), String> {
    
        self.volume_path = format!("\\\\.\\{}", self.drive_letter);

        let volume_path_cstr = CString::new(self.volume_path.as_bytes()).unwrap();

        self.volume_handle = unsafe {
            CreateFileA(
                volume_path_cstr.as_ptr() as *const u8,
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, // This actually means other processes CAN read and write
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0
            )
        };

        if self.volume_handle == INVALID_HANDLE_VALUE {
            // RETURN FAIL
            return Err(format!("CreateFileA failed: {:#x}", unsafe { GetLastError() } ));
        }

        Ok(())
    }

    fn read_mft_info(&mut self)  -> Result<(), String> {

        let result = unsafe { 
            DeviceIoControl(
                self.volume_handle,
                FSCTL_GET_NTFS_VOLUME_DATA,
                std::ptr::null(),
                0,
                std::ptr::addr_of_mut!(self.ntfs_volume_data) as *mut c_void,
                std::mem::size_of::<NTFS_VOLUME_DATA_BUFFER>() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut()
            )
        };

        if result == 0 {
            return Err(format!("DeviceIoControl error: {:#x}", unsafe { GetLastError() }));
        }

        Ok(())
    }

    pub fn read_records_into_buffer(&self, first_record_id : i64, num_records : usize, buffer : &mut [u8]) -> Result<u64, String> {
        if !self.is_open {
            return Err("MFT was not opened!".to_owned())
        }

        let buffer_record_capacity = buffer.len() / MFT_RECORD_SIZE;
        if buffer_record_capacity < num_records {
            return Err(format!("Requested {} records, but buffer of size {} can only fit {} records", num_records, buffer.len(), buffer_record_capacity).to_owned())
        }

        let max_requested_record_id = first_record_id + (num_records as i64);
        if max_requested_record_id > self.get_max_number_of_records() as i64 {
            return Err(format!("Tried to request records beyond end of MFT, requested record {}, max is {}", max_requested_record_id, self.get_max_number_of_records()))
        }

        let read_offset = self.get_mft_start_offset_bytes() + (first_record_id * MFT_RECORD_SIZE as i64);
        let mut overlapped  = OVERLAPPED {
            Anonymous: OVERLAPPED_0 {
                Anonymous: OVERLAPPED_0_0 {
                    Offset: read_offset as u32,
                    OffsetHigh: (read_offset >> 32) as u32
                },
            },
            hEvent: 0,
            Internal: 0,
            InternalHigh: 0,
        };


        let read_result = unsafe {
            ReadFile(
                self.volume_handle,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                std::ptr::null_mut(),
                std::ptr::addr_of_mut!(overlapped)
            )
        };

        if read_result == 0 {
            return Err(format!("ReadFile error: {:#x}", unsafe { GetLastError() }));
        }


        Ok(0)
    }

}




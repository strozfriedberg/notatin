use std::{
    mem,
    char::REPLACEMENT_CHARACTER,
    io::{BufWriter, Write},
    fmt::Write as FmtWrite,
    str
};
use serde::ser;
use chrono::{DateTime, Utc};
use winstructs::guid::Guid;
use nom::{
    IResult,
    take
};
use crate::err::Error;
use crate::parser::Parser;
use crate::log::{Logs, LogCode};

const SIZE_OF_UTF16_CHAR: usize = mem::size_of::<u16>();

fn from_utf16_le_string_single(slice: &[u8], count: usize, logs: &mut Logs, err_detail: &str) -> (String, usize) {
    let iter =
        (0..count / SIZE_OF_UTF16_CHAR)
            .map(|i| u16::from_le_bytes([slice[2*i], slice[2*i+1]]));
    let mut char_count = 0;
    let intermediate =
        std::char::decode_utf16(iter)
            .map(|r| {
                r.unwrap_or_else(|err| {
                    logs.add(LogCode::WarningConversion, &format!("{}: {}", err_detail, err.to_string()));
                    REPLACEMENT_CHARACTER
                })
            })
            .take_while(|c| {
                char_count += 1;
                c != &'\0'
            });
    let s = intermediate.collect::<String>();
    if char_count > 0 {
        char_count -= 1;
    }
    (s, char_count)
}

/// Reads a null-terminated UTF-16 string (REG_SZ)
pub(crate) fn from_utf16_le_string(slice: &[u8], count: usize, logs: &mut Logs, err_detail: &str) -> String {
    assert!(count <= slice.len());
    let (s, _) = from_utf16_le_string_single(slice, count, logs, err_detail);
    s
}

/// Reads a sequence of null-terminated UTF-16 strings, terminated by an empty string (\0). (REG_MULTI_SZ)
pub(crate) fn from_utf16_le_strings(slice: &[u8], count: usize, logs: &mut Logs, err_detail: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let mut offset = 0;

    while offset < count {
        let (decoded, size) = from_utf16_le_string_single(&slice[offset..], count - offset, logs, err_detail);
        if decoded.trim().is_empty() {
            break;
        }
        const NULL_TERMINATOR_LEN: usize = mem::size_of::<u16>();
        offset += (size * SIZE_OF_UTF16_CHAR) + NULL_TERMINATOR_LEN;
        strings.push(decoded);
    }
    strings
}

/// Converts a slice of ascii bytes into a String; invalid chars are encoded as utf16, converted to utf8, and added to the string. This matches Python's handling of invalid chars.
pub(crate) fn from_ascii(slice: &[u8], logs: &mut Logs, err_detail: &str) -> String {
    let mut result = String::new();
    for b in slice {
        let c = *b as char;
        if c.is_ascii() {
            result.push(c);
        }
        else {
            let u =
                std::char::decode_utf16(vec![u16::from_le_bytes([*b, 0])].iter().cloned())
                    .map(|r| {
                        r.unwrap_or_else(|err| {
                            // error shouldn't happen here since we're constructing a valid UTF-16 char
                            logs.add(LogCode::WarningConversion, &format!("{}: {}", err_detail, err.to_string()));
                            REPLACEMENT_CHARACTER
                        })
                    })
                    .collect::<String>();
            result += &u;
        }
    }
    result
}

pub(crate) fn string_from_bytes(is_ascii: bool, slice: &[u8], count: u16, logs: &mut Logs, err_detail: &str) -> String {
    if is_ascii {
        from_ascii(&slice, logs, err_detail)
    }
    else {
        from_utf16_le_string(slice, count.into(), logs, err_detail)
    }
}

/// Consumes any padding at the end of a hive bin cell.
pub(crate) fn parser_eat_remaining(
    input: &[u8],
    cell_size: u32,
    bytes_consumed: usize
) -> IResult<&[u8], &[u8]> {
    take!(input, cell_size as usize - bytes_consumed)
}

/// Converts a u64 filetime to a DateTime<Utc>
pub fn get_date_time_from_filetime(filetime: u64) -> DateTime<Utc> {
    const UNIX_EPOCH_SECONDS_SINCE_WINDOWS_EPOCH: i128 = 11644473600;
    const UNIX_EPOCH_NANOS: i128 = UNIX_EPOCH_SECONDS_SINCE_WINDOWS_EPOCH * 1_000_000_000;
    let filetime_nanos: i128 = filetime as i128 * 100;

    // Add nanoseconds to timestamp via Duration
    DateTime::<Utc>::from_utc(
        chrono::NaiveDate::from_ymd(1970, 1, 1).and_hms_nano(0, 0, 0, 0)
            + chrono::Duration::nanoseconds((filetime_nanos - UNIX_EPOCH_NANOS) as i64),
        Utc,
    )
}

/// Converts a DateTime<Utc> to ISO-8601/RFC-3339 format `%Y-%m-%dT%H:%M:%S%.7f` (manually, since Rust doesn't support `%.7f`)
pub fn format_date_time(date_time: DateTime<Utc>) -> String {
    let fractional_seconds = date_time.format("%9f").to_string();
    const EXPECTED_FRACTIONAL_SECONDS_LEN: usize = 9;
    if EXPECTED_FRACTIONAL_SECONDS_LEN == fractional_seconds.len() {
        let byte_slice = fractional_seconds.as_bytes(); // we know that the string is only ASCII, so this is safe
        // Make sure that our last two digits are 0, as we expect
        // Note that we aren't just using chrono::SecondsFormat::AutoSi because we want 7 digits to correspond to the original filetime's 100ns precision
        if byte_slice[EXPECTED_FRACTIONAL_SECONDS_LEN - 1] == b'0' && byte_slice[EXPECTED_FRACTIONAL_SECONDS_LEN - 2] == b'0' {
            return format!("{}.{}Z", date_time.format("%Y-%m-%dT%H:%M:%S"), &fractional_seconds[..7]);
        }
    }
    // We should nenver hit this when coming from a FILETIME; we don't have that much precision
    date_time.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

/// Converts a buffer to a guid; upon error, logs error to logs and returns an null guid
pub(crate) fn get_guid_from_buffer(buffer: &[u8], logs: &mut Logs) -> Guid {
    Guid::from_buffer(buffer)
        .or_else(
            |err| {
                logs.add(LogCode::WarningConversion, &err);
                Guid::from_buffer(&[0; 16])
            }
        ).expect("Error handled in or_else")
}

pub(crate) fn data_as_hex<S: ser::Serializer>(x: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&to_hex_string(x))
}

/// Adapted from https://github.com/omerbenamram/mft
pub(crate) fn to_hex_string(bytes: &[u8]) -> String {
    let len = bytes.len();
    let mut s = String::with_capacity(len * 3); // Each byte is represented by 2 ascii bytes, and then we add a space between them

    for byte in bytes {
        write!(s, "{:02X} ", byte).expect("Writing to an allocated string cannot fail");
    }
    s.trim_end().to_string()
}

#[allow(dead_code)]
pub fn write_common_export_format<W: Write>(parser: &mut Parser, output: W) -> Result<(), Error> {
    /* ## Registry common export format
    ## Key format
    ## key,Is Free (A for in use, U for unused),Absolute offset in decimal,KeyPath,,,,LastWriteTime in UTC
    ## Value format
    ## value,Is Free (A for in use, U for unused),Absolute offset in decimal,KeyPath,Value name,Data type (as decimal integer),Value data as bytes separated by a singe space,
    ##
    ## Comparison of deleted keys/values is done to compare recovery of vk and nk records, not the algorithm used to associate deleted keys to other keys and their values.
    ## When including deleted keys, only the recovered key name should be included, not the full path to the deleted key.
    ## When including deleted values, do not include the parent key information.
    ##
    ## The following totals should also be included
    ##
    ## total_keys: total in use key count
    ## total_values: total in use value count
    ## total_deleted_keys: total recovered free key count
    ## total_deleted_values: total recovered free value count
    ##
    ## Before comparison with other common export implementations, the files should be sorted
    ##*/

    fn escape_string(orig: &str) -> String {
        if orig.contains(",") || orig.contains("\""){
            let escaped = &str::replace(orig, "\"", "\"\"");
            format!("\"{}\"", escaped)
        }
        else {
            orig.to_string()
        }
    }

    let mut writer = BufWriter::new(output);
    let mut keys = 0;
    let mut values = 0;
    writeln!(
        &mut writer,
        "## Registry common export format\n\
        ## Key format\n\
        ## key,Is Free (A for in use, U for unused),Absolute offset in decimal,KeyPath,,,,LastWriteTime in UTC\n\
        ## Value format\n\
        ## value,Is Free (A for in use, U for unused),Absolute offset in decimal,KeyPath,Value name,Data type (as decimal integer),Value data as bytes separated by a singe space,\n\
        ##\n\
        ## Comparison of deleted keys/values is done to compare recovery of vk and nk records, not the algorithm used to associate deleted keys to other keys and their values.\n\
        ## When including deleted keys, only the recovered key name should be included, not the full path to the deleted key.\n\
        ## When including deleted values, do not include the parent key information.\n\
        ##\n\
        ## The following totals should also be included\n\
        ##\n\
        ## total_keys: total in use key count\n\
        ## total_values: total in use value count\n\
        ## total_deleted_keys: total recovered free key count\n\
        ## total_deleted_values: total recovered free value count\n\
        ##\n\
        ## Before comparison with other common export implementations, the files should be sorted\n\
        ##"
    )?;
    for key in parser.iter() {
        keys += 1;
        writeln!(
            &mut writer,
            "key,A,{},{},,,,{}",
            key.detail.file_offset_absolute,
            escape_string(&key.path[1..]), // drop the first slash to match EZ's formatting
            format_date_time(key.last_key_written_date_and_time)
        )?;
        for value in key.sub_values {
            let name;
            if value.value_name == "" {
                name = "(default)";
            }
            else {
                name = &value.value_name;
            }
            values += 1;
            writeln!(
                &mut writer,
                "value,A,{},{},{},{:?},{}",
                value.detail.file_offset_absolute,
                escape_string(&key.key_name),
                escape_string(name),
                value.data_type as u32,
                to_hex_string(&value.detail.value_bytes.unwrap_or_default()[..])
            )?;
        }
    }
    writeln!(&mut writer, "## total_keys: {}", keys)?;
    writeln!(&mut writer, "## total_values: {}", values)?;
    writeln!(&mut writer, "## total_deleted_keys")?;
    writeln!(&mut writer, "## total_deleted_values")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::Log;

    #[test]
    fn test_get_date_time_from_filetime() {
        assert_eq!(
            1333727545146808300,
            get_date_time_from_filetime(129782011451468083).timestamp_nanos()
        );
    }

    #[test]
    fn test_format_date_time() {
        assert_eq!(
            "2012-04-06T15:52:25.1468083Z",
            format_date_time(get_date_time_from_filetime(129782011451468083))
        );
    }

    #[test]
    fn test_get_guid_from_buffer() {
        let raw_guid: &[u8] = &[0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49,
                                0xa5, 0xba, 0x3e, 0x3b, 0x3, 0x28, 0xc3, 0xd];

        let mut logs = Logs::default();
        let guid = get_guid_from_buffer(raw_guid, &mut logs);

        assert_eq!(format!("{}", guid), "54849625-5478-4994-A5BA-3E3B0328C30D");
        assert_eq!(None, logs.get());

        let err_guid = get_guid_from_buffer(&raw_guid[..14], &mut logs);
        assert_eq!(format!("{}", err_guid), "00000000-0000-0000-0000-000000000000", "Return Guid for error case");
        let expected_warning = Log {
            code: LogCode::WarningConversion,
            text: "An I/O error has occurred".to_string()
        };
        assert_eq!(&vec![expected_warning], logs.get().unwrap());
    }

    #[test]
    fn test_from_ascii() {
        let mut logs = Logs::default();
        let good = from_ascii(&[0x74, 0x65, 0x73, 0x74], &mut logs, "Unit test");
        assert_eq!("test", good);
        assert_eq!(None, logs.get());

        let bad = from_ascii(&[0xff, 0xff, 0xff], &mut logs, "Unit test");
        assert_eq!("ÿÿÿ", bad);
        assert_eq!(None, logs.get());
    }

    #[test]
    fn test_read_utf16_le_strings() {
        let buffer = [77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0, 102, 0, 116, 0, 32, 0, 69, 0, 110, 0, 104, 0, 97, 0, 110, 0, 99, 0, 101, 0, 100, 0, 32, 0, 67, 0, 114, 0, 121, 0, 112, 0, 116, 0, 111, 0, 103, 0, 114, 0, 97, 0, 112, 0, 104, 0, 105, 0, 99, 0, 32, 0, 80, 0, 114, 0, 111, 0, 118, 0, 105, 0, 100, 0, 101, 0, 114, 0, 32, 0, 118, 0, 49, 0, 46, 0, 48, 0, 0, 0, 77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0, 102, 0, 116, 0, 32, 0, 66, 0, 97, 0, 115, 0, 101, 0, 32, 0, 67, 0, 114, 0, 121, 0, 112, 0, 116, 0, 111, 0, 103, 0, 114, 0, 97, 0, 112, 0, 104, 0, 105, 0, 99, 0, 32, 0, 80, 0, 114, 0, 111, 0, 118, 0, 105, 0, 100, 0, 101, 0, 114, 0, 32, 0, 118, 0, 49, 0, 46, 0, 48, 0, 0, 0, 0, 0];
        let mut logs = Logs::default();
        let strings = from_utf16_le_strings(&buffer, buffer.len(), &mut logs, "unit test");
        let expected_strings = vec!["Microsoft Enhanced Cryptographic Provider v1.0", "Microsoft Base Cryptographic Provider v1.0"];
        assert_eq!(expected_strings, strings);

        let buffer = [0, 0];
        let mut logs = Logs::default();
        let strings = from_utf16_le_strings(&buffer, buffer.len(), &mut logs, "unit test");
        let expected_strings: Vec<String> = vec![];
        assert_eq!(expected_strings, strings);

        let buffer = [0x63, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x75, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x64, 0x00, 0x5C, 0x00, 0x61, 0x00, 0x70, 0x00, 0x70, 0x00, 0x64, 0x00, 0x61, 0x00, 0x74, 0x00, 0x61, 0x00, 0x5C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x63, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x5C, 0x00, 0x6D, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x66, 0x00, 0x74, 0x00, 0x5C, 0x00, 0x73, 0x00, 0x6B, 0x00, 0x79, 0x00, 0x64, 0x00, 0x72, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x5C, 0x00, 0x31, 0x00, 0x37, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x30, 0x00, 0x31, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x38, 0x00, 0x31, 0x00, 0x31, 0x00, 0x5C, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x64, 0x00, 0x36, 0x00, 0x34, 0x00, 0x00, 0x00, 0x63, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x75, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x64, 0x00, 0x5C, 0x00, 0x61, 0x00, 0x70, 0x00, 0x70, 0x00, 0x64, 0x00, 0x61, 0x00, 0x74, 0x00, 0x61, 0x00, 0x5C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x63, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x5C, 0x00, 0x6D, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x66, 0x00, 0x74, 0x00, 0x5C, 0x00, 0x73, 0x00, 0x6B, 0x00, 0x79, 0x00, 0x64, 0x00, 0x72, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x5C, 0x00, 0x31, 0x00, 0x37, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x30, 0x00, 0x31, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x38, 0x00, 0x31, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut logs = Logs::default();
        let strings = from_utf16_le_strings(&buffer, buffer.len(), &mut logs, "unit test");
        let expected_strings = vec![
            "c:\\users\\donald\\appdata\\local\\microsoft\\skydrive\\17.0.2015.0811\\amd64",
            "c:\\users\\donald\\appdata\\local\\microsoft\\skydrive\\17.0.2015.0811"
        ];
        assert_eq!(expected_strings, strings);

        let buffer = [0x41, 0x00, 0x53, 0x00, 0x43, 0x00, 0x49, 0x00, 0x49, 0x00, 0x5F, 0x00, 0x4D, 0x00, 0x55, 0x00, 0x4C, 0x00, 0x54, 0x00, 0x49, 0x00, 0x5F, 0x00, 0x56, 0x00, 0x41, 0x00, 0x4C, 0x00, 0x55, 0x00, 0x45, 0x00, 0x31, 0x00, 0x00, 0x00, 0x55, 0x00, 0x4E, 0x00, 0x49, 0x00, 0x43, 0x00, 0x4F, 0x00, 0x44, 0x00, 0x45, 0x00, 0x5F, 0x00, 0x4A, 0x00, 0x55, 0x00, 0x4D, 0x00, 0x42, 0x00, 0x4C, 0x00, 0x45, 0x00, 0x5F, 0x00, 0x7B, 0x00, 0x48, 0x00, 0x7E, 0x00, 0x91, 0x25, 0xF4, 0x00, 0xAB, 0x00, 0x7D, 0x00, 0x00, 0x00, 0x55, 0x00, 0x4E, 0x00, 0x49, 0x00, 0x43, 0x00, 0x4F, 0x00, 0x44, 0x00, 0x45, 0x00, 0x5F, 0x00, 0x4A, 0x00, 0x55, 0x00, 0x4D, 0x00, 0x42, 0x00, 0x4C, 0x00, 0x45, 0x00, 0x5F, 0x00, 0x7B, 0x00, 0x48, 0x00, 0x7E, 0x00, 0x91, 0x25, 0xF4, 0x00, 0xAB, 0x00, 0x7D, 0x00, 0x00, 0x00, 0x41, 0x00, 0x53, 0x00, 0x43, 0x00, 0x49, 0x00, 0x49, 0x00, 0x5F, 0x00, 0x4D, 0x00, 0x55, 0x00, 0x4C, 0x00, 0x54, 0x00, 0x49, 0x00, 0x5F, 0x00, 0x56, 0x00, 0x41, 0x00, 0x4C, 0x00, 0x55, 0x00, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut logs = Logs::default();
        let strings = from_utf16_le_strings(&buffer, buffer.len(), &mut logs, "unit test");
        let expected_strings = vec![
            "ASCII_MULTI_VALUE1",
            "UNICODE_JUMBLE_{H~░ô«}",
            "UNICODE_JUMBLE_{H~░ô«}",
            "ASCII_MULTI_VALUE"
        ];
        assert_eq!(expected_strings, strings);
    }

    #[test]
    fn test_string_from_bytes() {
        let test_str_ascii = "test string";
        let mut logs = Logs::default();
        let ascii = string_from_bytes(true, test_str_ascii.as_bytes(), test_str_ascii.len() as u16, &mut logs, "Unit test");
        assert_eq!(test_str_ascii, ascii, "Ascii conversion");
        assert_eq!(None, logs.get(), "No warnings expected");

        let test_utf16 = [0x2C, 0x6E, 0x66, 0x8A, 0x57, 0x5B, 0x26, 0x7B, 0x32, 0x4E];
        let utf16 = string_from_bytes(false, &test_utf16, test_utf16.len() as u16, &mut logs, "Unit test");
        assert_eq!("測試字符串", utf16, "UTF-16 conversion");
        assert_eq!(None, logs.get(), "No warnings expected");

        let test_4byte_utf16 = [0x28, 0x00, 0x01, 0xD8, 0x37, 0xDC, 0x29, 0x00];
        let utf16 = string_from_bytes(false, &test_4byte_utf16, test_4byte_utf16.len() as u16, &mut logs, "Unit test");
        assert_eq!("(𐐷)", utf16, "UTF-16 4-byte char conversion");
        assert_eq!(None, logs.get(), "No warnings expected");

        let test_utf8 = [80, 58, 92, 72, 102, 114, 101, 102, 92, 119, 122, 101, 98, 111, 114, 101, 103, 102, 92, 81, 114, 102, 120, 103, 98, 99, 92, 72, 70, 79, 95, 69, 114, 102, 114, 110, 101, 112, 117, 92, 80, 117, 118, 99, 82, 110, 102, 108, 49, 46, 54, 51, 48, 92, 208, 190, 198, 172, 206, 222, 211, 199, 46, 114, 107, 114];
        let ascii = string_from_bytes(true, &test_utf8, test_utf8.len() as u16, &mut logs, "Unit test");
        assert_eq!("P:\\Hfref\\wzeboregf\\Qrfxgbc\\HFO_Erfrnepu\\PuvcRnfl1.630\\\u{d0}\u{be}\u{c6}\u{ac}\u{ce}\u{de}\u{d3}\u{c7}.rkr", ascii, "Invalid UTF-8 conversion");
        assert_eq!(None, logs.get(), "No warnings expected");

        let test_utf16 = [0x2C, 0x6E, 0xFF, 0xDB, 0x57, 0x5B, 0x26, 0x7B, 0x32, 0x4E];
        let utf16 = string_from_bytes(false, &test_utf16, test_utf16.len() as u16, &mut logs, "Unit test");
        assert_eq!(format!("測{}字符串", std::char::REPLACEMENT_CHARACTER), utf16, "UTF-16 conversion - replacement character");
        let expected_warning = Log {
            code: LogCode::WarningConversion,
            text: "Unit test: unpaired surrogate found: dbff".to_string()
        };
        assert_eq!(&vec![expected_warning], logs.get().unwrap(), "1 warning expected");
    }

    #[test]
    fn test_to_hex_string() {
        assert_eq!("00 01 02 03 04 05 FF", to_hex_string(&[0, 1, 2, 3, 4, 5, 0xff]));
    }
}

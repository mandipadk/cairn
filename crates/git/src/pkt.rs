//! pkt-line: git's length-prefixed framing.
//!
//! Four hex digits of total length (including the prefix itself), then
//! payload. Three lengths are control packets: `0000` flush, `0001`
//! delimiter, `0002` response-end. Used here for smart-HTTP service
//! advertisements and the proc-receive hook conversation.

use std::io::{self, Read, Write};

/// Largest payload a single pkt-line can carry (65520 - 4).
pub const MAX_PAYLOAD: usize = 65516;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Flush,
    Delim,
    ResponseEnd,
    Data(Vec<u8>),
}

pub fn read(reader: &mut impl Read) -> io::Result<Packet> {
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix)?;
    let text = std::str::from_utf8(&prefix)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pkt length is not utf-8"))?;
    let length = usize::from_str_radix(text, 16)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pkt length is not hex"))?;
    match length {
        0 => Ok(Packet::Flush),
        1 => Ok(Packet::Delim),
        2 => Ok(Packet::ResponseEnd),
        3 => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pkt length 3 is invalid",
        )),
        _ => {
            let mut payload = vec![0u8; length - 4];
            reader.read_exact(&mut payload)?;
            Ok(Packet::Data(payload))
        }
    }
}

pub fn write_data(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pkt payload too large",
        ));
    }
    write!(writer, "{:04x}", payload.len() + 4)?;
    writer.write_all(payload)
}

pub fn write_flush(writer: &mut impl Write) -> io::Result<()> {
    writer.write_all(b"0000")
}

/// A data packet as bytes, for building responses.
pub fn data_line(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    write_data(&mut out, payload).expect("in-memory write");
    out
}

/// Read text data lines until a flush, stripping one trailing newline
/// per line (the pkt-line text convention).
pub fn read_text_until_flush(reader: &mut impl Read) -> io::Result<Vec<String>> {
    let mut lines = Vec::new();
    loop {
        match read(reader)? {
            Packet::Flush => return Ok(lines),
            Packet::Delim | Packet::ResponseEnd => continue,
            Packet::Data(payload) => {
                let mut text = String::from_utf8_lossy(&payload).into_owned();
                if text.ends_with('\n') {
                    text.pop();
                }
                lines.push(text);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn data_round_trips() {
        let mut buf = Vec::new();
        write_data(&mut buf, b"hello\n").unwrap();
        write_flush(&mut buf).unwrap();
        assert_eq!(&buf[..4], b"000a");
        let mut cursor = Cursor::new(buf);
        assert_eq!(
            read(&mut cursor).unwrap(),
            Packet::Data(b"hello\n".to_vec())
        );
        assert_eq!(read(&mut cursor).unwrap(), Packet::Flush);
    }

    #[test]
    fn control_packets_parse() {
        let mut cursor = Cursor::new(b"000000010002".to_vec());
        assert_eq!(read(&mut cursor).unwrap(), Packet::Flush);
        assert_eq!(read(&mut cursor).unwrap(), Packet::Delim);
        assert_eq!(read(&mut cursor).unwrap(), Packet::ResponseEnd);
    }

    #[test]
    fn invalid_lengths_are_errors() {
        assert!(read(&mut Cursor::new(b"zzzz".to_vec())).is_err());
        assert!(read(&mut Cursor::new(b"0003".to_vec())).is_err());
        let big = vec![0u8; MAX_PAYLOAD + 1];
        assert!(write_data(&mut Vec::new(), &big).is_err());
    }

    #[test]
    fn text_lines_strip_one_newline() {
        let mut buf = Vec::new();
        write_data(&mut buf, b"version=1\n").unwrap();
        write_data(&mut buf, b"no-newline").unwrap();
        write_flush(&mut buf).unwrap();
        let lines = read_text_until_flush(&mut Cursor::new(buf)).unwrap();
        assert_eq!(lines, ["version=1", "no-newline"]);
    }
}

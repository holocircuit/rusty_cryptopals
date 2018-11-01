// panics if byte > 64, which should not happen
fn encode_char(byte: u8) -> char {
    match byte {
        x if x <= 25 => char::from(x + 0x41),
        x if x <= 51 => char::from(x + 0x47),
        x if x <= 61 => char::from(x - 0x4),
        x if x == 62 => '+',
        x if x == 63 => '/',
        _ => panic!("[byte_to_base64char] should only be called on values < 64"),
    }
}

const PADDING_BYTE: char = '=';

enum DecodedByte {
    Byte(u8),
    PaddingByte,
    UnknownB64Symbol(char),
}

#[derive(Debug)]
pub enum DecodingError {
    BadLength,
    BadPadding,
    BadChar(char),
    DataAfterEnd
}

fn decode_char(c: char) -> DecodedByte {
    let x = c as u32;

    match x {
        43 => DecodedByte::Byte(62),
        47 => DecodedByte::Byte(63),
        61 => DecodedByte::PaddingByte,
        x if x >= 0x41 && x <= 0x5a => DecodedByte::Byte((x - 0x41) as u8),
        x if x >= 0x61 && x <= 0x7a => DecodedByte::Byte((x - 0x61 + 26) as u8),
        x if x >= 0x30 && x <= 0x39 => DecodedByte::Byte((x - 0x30 + 52) as u8),
        _ => DecodedByte::UnknownB64Symbol(c),
    }
}

fn data_slice_to_int(data: &[u8]) -> u32 {
    data.iter().map(|x| *x as u32).fold(0, |y, z| (y << 8) + z)
}

fn decoded_slice_to_int(data: &[DecodedByte]) -> Result<u32, DecodingError> {
    data.iter().try_fold(0, |x, b| match b {
        DecodedByte::UnknownB64Symbol(_) => unreachable!("BUG: should have hit this below"),
        DecodedByte::PaddingByte => Err(DecodingError::BadPadding),
        DecodedByte::Byte(b) => Ok((x << 6) + (*b as u32)),
    })
}

pub fn encode(data: &[u8]) -> String {
    // upper bound on the length
    let encoded_length = data.len() * 4 / 3 + 2;
    let mut encoded_data = String::with_capacity(encoded_length);

    // Do the "full" chunks (of 3 bytes)
    for i in 0..data.len() / 3 {
        let x = data_slice_to_int(&data[3 * i..3 * i + 3]);

        // could write this as a loop but tbh it's a bit clearer unrolled
        encoded_data.push(encode_char(((x >> 18) % 64) as u8));
        encoded_data.push(encode_char(((x >> 12) % 64) as u8));
        encoded_data.push(encode_char(((x >> 6) % 64) as u8));
        encoded_data.push(encode_char((x % 64) as u8));
    }

    // Maybe do the last chunk
    if data.len() % 3 != 0 {
        let size_of_last_chunk = data.len() % 3;
        let x = data_slice_to_int(&data[data.len() - size_of_last_chunk..]);

        // we need to pad to a "round" number of base64 characters, i.e. a multiple of 6 bits
        // last chunk size 1 = 8 bits, so add 4 null bits and two bytes of padding
        // last chunk size 2 = 16 bits, so add 2 null bits and one bytes of padding

        match size_of_last_chunk {
            1 => {
                encoded_data.push(encode_char((((x << 4) >> 6) % 64) as u8));
                encoded_data.push(encode_char(((x << 4) % 64) as u8));
                encoded_data.push(PADDING_BYTE);
                encoded_data.push(PADDING_BYTE);
            }
            2 => {
                encoded_data.push(encode_char((((x << 2) >> 12) % 64) as u8));
                encoded_data.push(encode_char((((x << 2) >> 6) % 64) as u8));
                encoded_data.push(encode_char(((x << 2) % 64) as u8));
                encoded_data.push(PADDING_BYTE);
            }
            _ => unreachable!("BUG: last chunk can only be of size 1 or 2"),
        }
    }

    encoded_data
}

pub fn decode(input: &str) -> Result<Vec<u8>, DecodingError> {
    let decoded_length = input.len() / 3 * 4 + 3;
    let mut decoded_data = Vec::with_capacity(decoded_length);

    if input.len() % 4 != 0 {
        return Err(DecodingError::BadLength);
    }

    if input.len() == 0 {
        return Ok(decoded_data);
    }

    let mut chunk = [
        DecodedByte::PaddingByte,
        DecodedByte::PaddingByte,
        DecodedByte::PaddingByte,
        DecodedByte::PaddingByte,
    ];

    // Slightly different structure to above - Rust won't let us slice
    // into a string, so we fold over and explicitly deal with each chunk.
    let _num = input.chars().try_fold(0, |num_so_far, c| {
        if num_so_far == 4 {
            // append. Check there's no padding bytes - we know we're not in the last
            // block here.

            let x = decoded_slice_to_int(&chunk)?;
            decoded_data.push(((x >> 16) % 256) as u8);
            decoded_data.push(((x >> 8) % 256) as u8);
            decoded_data.push((x % 256) as u8);
        }

        let y = if num_so_far == 4 { 0 } else { num_so_far };

        match decode_char(c) {
            DecodedByte::UnknownB64Symbol(c) => return Err(DecodingError::BadChar(c)),
            b @ _ => {
                chunk[y] = b;
                Ok(y + 1)
            }
        }
    })?;

    let number_of_padding_bytes = chunk
        .iter()
        .rev()
        .take_while(|c| match c {
            DecodedByte::PaddingByte => true,
            _ => false,
        }).count();

    match number_of_padding_bytes {
        3 | 4 => return Err(DecodingError::BadPadding),
        2 => {
            // 12 bits of data, 1 byte of output
            let x = decoded_slice_to_int(&chunk[..2])?;
            decoded_data.push(((x >> 4) % 256) as u8);

            if (x % 16) != 0 {
                return Err(DecodingError::DataAfterEnd);
            }
        }
        1 => {
            // 18 bits of data, 2 bytes of output
            let x = decoded_slice_to_int(&chunk[..3])?;
            decoded_data.push(((x >> 10) % 256) as u8);
            decoded_data.push(((x >> 2) % 256) as u8);

            if (x % 4) != 0 {
                return Err(DecodingError::DataAfterEnd);
            }
        }
        0 => {
            // 4 bytes, and 24 bits of data (as above)
            let x = decoded_slice_to_int(&chunk)?;
            decoded_data.push(((x >> 16) % 256) as u8);
            decoded_data.push(((x >> 8) % 256) as u8);
            decoded_data.push((x % 256) as u8);
        }
        _ => unreachable!("BUG: impossible, chunk has length at most 4"),
    };

    Ok(decoded_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_encode_and_decode(s1: &str, s2: &str) {
        let x = s1.to_string().into_bytes();

        assert_eq!(encode(&x), s2);
        assert_eq!(x, decode(s2).unwrap());
    }

    #[test]
    fn rfc_tests() {
        check_encode_and_decode("", "");
        check_encode_and_decode("f", "Zg==");
        check_encode_and_decode("fo", "Zm8=");
        check_encode_and_decode("foo", "Zm9v");
        check_encode_and_decode("foob", "Zm9vYg==");
        check_encode_and_decode("fooba", "Zm9vYmE=");
        check_encode_and_decode("foobar", "Zm9vYmFy");
    }
}

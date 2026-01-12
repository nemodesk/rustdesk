use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};
// 引入加密库
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use crate::config::Config;

#[derive(Debug, Clone, Copy)]
pub struct BytesCodec {
    state: DecodeState,
    raw: bool,
    max_packet_length: usize,
    obfuscate_key: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy)]
enum DecodeState {
    Head,
    Data(usize),
}

impl Default for BytesCodec {
    fn default() -> Self {
        Self::new_obfuscate(Config::get_obfuscate_key())
    }
}

impl BytesCodec {
    pub fn new_obfuscate(key: [u8; 32]) -> Self {
        Self {
            state: DecodeState::Head,
            raw: false,
            max_packet_length: usize::MAX,
            obfuscate_key: Some(key),
        }
    }
    pub fn set_raw(&mut self) {
        self.raw = true;
    }

    pub fn set_max_packet_length(&mut self, n: usize) {
        self.max_packet_length = n;
    }

    fn decode_head(&mut self, src: &mut BytesMut) -> io::Result<Option<usize>> {
        if src.is_empty() {
            return Ok(None);
        }
        let head_len = ((src[0] & 0x3) + 1) as usize;
        if src.len() < head_len {
            return Ok(None);
        }
        let mut n = src[0] as usize;
        if head_len > 1 {
            n |= (src[1] as usize) << 8;
        }
        if head_len > 2 {
            n |= (src[2] as usize) << 16;
        }
        if head_len > 3 {
            n |= (src[3] as usize) << 24;
        }
        n >>= 2;
        if n > self.max_packet_length {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Too big packet"));
        }
        src.advance(head_len);
        src.reserve(n);
        Ok(Some(n))
    }

    fn decode_data(&self, n: usize, src: &mut BytesMut) -> io::Result<Option<BytesMut>> {
        if src.len() < n {
            return Ok(None);
        }
        Ok(Some(src.split_to(n)))
    }
}

impl Decoder for BytesCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        if self.raw {
            if !src.is_empty() {
                let len = src.len();
                return Ok(Some(src.split_to(len)));
            } else {
                return Ok(None);
            }
        }
        let n = match self.state {
            DecodeState::Head => match self.decode_head(src)? {
                Some(n) => {
                    self.state = DecodeState::Data(n);
                    n
                }
                None => return Ok(None),
            },
            DecodeState::Data(n) => n,
        };

        match self.decode_data(n, src)? {
            Some(mut data) => {
                // 只有调用 new_obfuscate 创建的实例才会解密
                if let Some(key) = self.obfuscate_key {
                    let nonce = [0u8; 12];
                    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
                    cipher.apply_keystream(&mut data);
                }

                self.state = DecodeState::Head;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }
}

// 用于类型约定
impl Encoder<Bytes> for BytesCodec {
    type Error = io::Error;

    fn encode(&mut self, data: Bytes, buf: &mut BytesMut) -> Result<(), io::Error> {
        if self.raw {
            buf.reserve(data.len());
            buf.put(data);
            return Ok(());
        }

        // 拷贝数据到 payload，后续可能修改
        let mut payload = data.to_vec();

        // 如有加密密钥，则加密
        if let Some(key) = self.obfuscate_key {
            let nonce = [0u8; 12]; // 建议用唯一 nonce，demo用 all zero
            let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
            cipher.apply_keystream(&mut payload);
        }

        let len = payload.len();
        if len <= 0x3F {
            buf.put_u8((len << 2) as u8);
        } else if len <= 0x3FFF {
            buf.put_u16_le((len << 2) as u16 | 0x1);
        } else if len <= 0x3FFFFF {
            let h = (len << 2) as u32 | 0x2;
            buf.put_u16_le((h & 0xFFFF) as u16);
            buf.put_u8((h >> 16) as u8);
        } else if len <= 0x3FFFFFFF {
            buf.put_u32_le((len << 2) as u32 | 0x3);
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Overflow"));
        }

        buf.extend_from_slice(&payload);
        Ok(())
    }
}
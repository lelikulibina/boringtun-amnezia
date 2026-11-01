//! Парсер и генератор CPS-шаблонов сигнатурных пакетов I1-I5.
//!
//! Реализован набор тегов AmneziaWG Go: b, t, r, rc, rd, d, ds и dz.
//! В I-пакетах входные данные пусты: поэтому d/ds генерируют ноль байт,
//! а dz записывает длину пустого входа.

use rand_core::RngCore;
use std::fmt;

const MAX_RANDOM_TAG_SIZE: usize = 1_000;
const MAX_SIGNATURE_PACKET_SIZE: usize = 65_507;
const LETTERS: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8; 10] = b"0123456789";

/// Один элемент CPS-шаблона.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignaturePart {
    /// Фиксированные байты из hex-строки.
    Bytes(Vec<u8>),
    /// Unix timestamp в формате u32 big-endian.
    Timestamp,
    /// Криптографически случайные байты.
    RandomBytes(usize),
    /// Случайные латинские буквы a-zA-Z.
    RandomLetters(usize),
    /// Случайные десятичные цифры.
    RandomDigits(usize),
    /// Pass-through входных данных (в I-пакете вход пуст).
    Data,
    /// Base64 RawStdEncoding входных данных (в I-пакете вход пуст).
    Base64Data,
    /// Длина входных данных, записанная в N байтах big-endian.
    DataSize(usize),
}

/// Разобранная CPS-цепочка I1-I5.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignatureTemplate {
    parts: Vec<SignaturePart>,
    output_len: usize,
}

/// Ошибки разбора или генерации CPS-шаблона.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// Открывающая угловая скобка не имеет закрывающей.
    MissingClosingBracket,
    /// Между скобками нет имени тега.
    EmptyTag,
    /// Тег не поддерживается реализацией.
    UnknownTag(String),
    /// Тег получил неверное количество аргументов.
    InvalidArguments(String),
    /// Аргумент тега содержит неверные данные.
    InvalidArgument(String),
    /// Слишком большой размер отдельного или итогового пакета.
    PacketTooLarge,
    /// Размер выходного целого не может вместить длину данных.
    DataLengthDoesNotFit,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingClosingBracket => f.write_str("отсутствует закрывающая скобка '>'"),
            Self::EmptyTag => f.write_str("пустой CPS-тег"),
            Self::UnknownTag(tag) => write!(f, "неизвестный CPS-тег <{tag}>"),
            Self::InvalidArguments(tag) => write!(f, "неверные аргументы CPS-тега <{tag}>"),
            Self::InvalidArgument(value) => write!(f, "неверный аргумент CPS-тега: {value}"),
            Self::PacketTooLarge => f.write_str("сигнатурный пакет превышает допустимый размер"),
            Self::DataLengthDoesNotFit => f.write_str("длина входных данных не помещается в заданное число байт"),
        }
    }
}

impl std::error::Error for SignatureError {}

impl SignatureTemplate {
    /// Разбирает строку CPS-тегов, например <b 0xdeadbeef><r 16><t>.
    ///
    /// Текст вне тегов игнорируется так же, как в amneziawg-go. Некорректные
    /// теги и небезопасно большие размеры отклоняются до генерации пакета.
    pub fn parse(spec: &str) -> Result<Self, SignatureError> {
        let mut parts = Vec::new();
        let mut output_len = 0usize;
        let mut remaining = spec;

        while let Some(start) = remaining.find('<') {
            let after_start = &remaining[start + 1..];
            let end = after_start.find('>').ok_or(SignatureError::MissingClosingBracket)?;
            let tag_body = &after_start[..end];
            let mut fields = tag_body.split_whitespace();
            let name = fields.next().ok_or(SignatureError::EmptyTag)?;
            let argument = fields.next();
            if fields.next().is_some() {
                return Err(SignatureError::InvalidArguments(name.to_owned()));
            }

            let part = match name {
                "b" => {
                    let value = argument.ok_or_else(|| SignatureError::InvalidArguments(name.into()))?;
                    let hex = value.strip_prefix("0x").unwrap_or(value);
                    if hex.is_empty() || hex.len() % 2 != 0 {
                        return Err(SignatureError::InvalidArgument(value.into()));
                    }
                    let mut bytes = Vec::with_capacity(hex.len() / 2);
                    for pair in hex.as_bytes().chunks_exact(2) {
                        let text = std::str::from_utf8(pair)
                            .map_err(|_| SignatureError::InvalidArgument(value.into()))?;
                        bytes.push(u8::from_str_radix(text, 16)
                            .map_err(|_| SignatureError::InvalidArgument(value.into()))?);
                    }
                    SignaturePart::Bytes(bytes)
                }
                "t" => {
                    if argument.is_some() {
                        return Err(SignatureError::InvalidArguments(name.into()));
                    }
                    SignaturePart::Timestamp
                }
                "r" | "rc" | "rd" => {
                    let value = argument.ok_or_else(|| SignatureError::InvalidArguments(name.into()))?;
                    let length = value.parse::<usize>()
                        .map_err(|_| SignatureError::InvalidArgument(value.into()))?;
                    if length > MAX_RANDOM_TAG_SIZE {
                        return Err(SignatureError::PacketTooLarge);
                    }
                    match name {
                        "r" => SignaturePart::RandomBytes(length),
                        "rc" => SignaturePart::RandomLetters(length),
                        _ => SignaturePart::RandomDigits(length),
                    }
                }
                "d" | "ds" => {
                    if argument.is_some() {
                        return Err(SignatureError::InvalidArguments(name.into()));
                    }
                    if name == "d" { SignaturePart::Data } else { SignaturePart::Base64Data }
                }
                "dz" => {
                    let value = argument.ok_or_else(|| SignatureError::InvalidArguments(name.into()))?;
                    let length = value.parse::<usize>()
                        .map_err(|_| SignatureError::InvalidArgument(value.into()))?;
                    if length > 8 {
                        return Err(SignatureError::DataLengthDoesNotFit);
                    }
                    SignaturePart::DataSize(length)
                }
                _ => return Err(SignatureError::UnknownTag(name.into())),
            };

            let part_len = match &part {
                SignaturePart::Bytes(bytes) => bytes.len(),
                SignaturePart::Timestamp => 4,
                SignaturePart::RandomBytes(n)
                | SignaturePart::RandomLetters(n)
                | SignaturePart::RandomDigits(n)
                | SignaturePart::DataSize(n) => *n,
                SignaturePart::Data | SignaturePart::Base64Data => 0,
            };
            output_len = output_len.checked_add(part_len)
                .filter(|len| *len <= MAX_SIGNATURE_PACKET_SIZE)
                .ok_or(SignatureError::PacketTooLarge)?;
            parts.push(part);
            remaining = &after_start[end + 1..];
        }

        Ok(Self { parts, output_len })
    }

    /// Возвращает разобранные элементы шаблона.
    pub fn parts(&self) -> &[SignaturePart] {
        &self.parts
    }

    /// Размер результирующего I-пакета в байтах.
    pub fn output_len(&self) -> usize {
        self.output_len
    }

    /// Генерирует I-пакет. Временная метка передаётся извне для повторяемых тестов.
    pub fn render<R: RngCore>(
        &self,
        rng: &mut R,
        unix_timestamp: u32,
    ) -> Result<Vec<u8>, SignatureError> {
        let mut output = Vec::with_capacity(self.output_len);
        for part in &self.parts {
            match part {
                SignaturePart::Bytes(bytes) => output.extend_from_slice(bytes),
                SignaturePart::Timestamp => output.extend_from_slice(&unix_timestamp.to_be_bytes()),
                SignaturePart::RandomBytes(length) => {
                    let start = output.len();
                    output.resize(start + length, 0);
                    rng.fill_bytes(&mut output[start..]);
                }
                SignaturePart::RandomLetters(length) => {
                    let start = output.len();
                    output.resize(start + length, 0);
                    rng.fill_bytes(&mut output[start..]);
                    for byte in &mut output[start..] {
                        *byte = LETTERS[(*byte as usize) % LETTERS.len()];
                    }
                }
                SignaturePart::RandomDigits(length) => {
                    let start = output.len();
                    output.resize(start + length, 0);
                    rng.fill_bytes(&mut output[start..]);
                    for byte in &mut output[start..] {
                        *byte = DIGITS[(*byte as usize) % DIGITS.len()];
                    }
                }
                // Signature I-packets are built with an empty source slice in Go.
                SignaturePart::Data | SignaturePart::Base64Data => {}
                SignaturePart::DataSize(length) => {
                    if *length == 0 {
                        continue;
                    }
                    let mut encoded = vec![0u8; *length];
                    let mut source_len = 0usize;
                    for index in (0..*length).rev() {
                        encoded[index] = (source_len & 0xff) as u8;
                        source_len >>= 8;
                    }
                    output.extend_from_slice(&encoded);
                }
            }
        }
        debug_assert_eq!(output.len(), self.output_len);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng(u8);
    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 { self.0 as u32 * 0x0101_0101 }
        fn next_u64(&mut self) -> u64 { self.next_u32() as u64 * 0x0001_0001_0001_0001 }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest { *byte = self.0; }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[test]
    fn parses_and_renders_static_bytes_and_big_endian_timestamp() {
        let template = SignatureTemplate::parse("<b 0xdeadbeef><t>").unwrap();
        let mut rng = FixedRng(7);
        assert_eq!(template.output_len(), 8);
        assert_eq!(template.render(&mut rng, 0x0102_0304).unwrap(),
            [0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);
    }

    #[test]
    fn renders_random_tags_with_expected_alphabets_and_lengths() {
        let template = SignatureTemplate::parse("<r 3><rc 4><rd 2>").unwrap();
        let mut rng = FixedRng(7);
        let rendered = template.render(&mut rng, 0).unwrap();
        assert_eq!(rendered.len(), 9);
        assert_eq!(&rendered[..3], &[7, 7, 7]);
        assert!(rendered[3..7].iter().all(|b| LETTERS.contains(b)));
        assert!(rendered[7..].iter().all(|b| DIGITS.contains(b)));
    }

    #[test]
    fn data_tags_are_empty_for_signature_packets_and_data_size_is_zero() {
        let template = SignatureTemplate::parse("<d><ds><dz 4>").unwrap();
        let mut rng = FixedRng(0);
        assert_eq!(template.render(&mut rng, 0).unwrap(), [0, 0, 0, 0]);
    }

    #[test]
    fn rejects_invalid_hex_unknown_tags_and_unclosed_brackets() {
        assert!(matches!(SignatureTemplate::parse("<b 0xabc>"), Err(SignatureError::InvalidArgument(_))));
        assert!(matches!(SignatureTemplate::parse("<unknown>"), Err(SignatureError::UnknownTag(_))));
        assert_eq!(SignatureTemplate::parse("<r 2"), Err(SignatureError::MissingClosingBracket));
    }

    #[test]
    fn rejects_negative_and_oversized_random_lengths() {
        assert!(SignatureTemplate::parse("<r -1>").is_err());
        assert_eq!(SignatureTemplate::parse("<r 1001>"), Err(SignatureError::PacketTooLarge));
    }

    #[test]
    fn ignores_plain_text_between_tags_like_go_parser() {
        let template = SignatureTemplate::parse("prefix<b 0x01>middle<t>suffix").unwrap();
        assert_eq!(template.output_len(), 5);
    }
}

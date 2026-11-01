//! Базовое внешнее кодирование AWG-пакетов.
//!
//! Этот слой добавляет H1-H4 ranges, S1-S4 padding и ChaCha20 header protection
//! поверх канонических пакетов BoringTun. При random H1/H2 пересчитывается MAC1;
//! MAC2 under-load сценарии требуют DisableCookies на обеих сторонах.

use crate::{AmneziaConfig, ValueRange};
use blake2::digest::consts::U16;
use blake2::digest::{FixedOutput, KeyInit};
use blake2::{Blake2s256, Blake2sMac, Digest};
use boringtun::noise::{Packet, Tunn};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand_core::{CryptoRng, RngCore};
use std::fmt;
use zeroize::Zeroize;

const MAX_UDP_PAYLOAD: usize = 65_507;
const DEFAULT_UDP_WINDOW: usize = 500;
const HEADER_PROTECTION_NONCE_SIZE: usize = 12;
const TRANSPORT_HEADER_SIZE: usize = 16;

/// Класс канонического WireGuard сообщения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageKind {
    HandshakeInitiation,
    HandshakeResponse,
    CookieReply,
    Transport,
}

impl MessageKind {
    fn message_size(self) -> usize {
        match self {
            Self::HandshakeInitiation => 148,
            Self::HandshakeResponse => 92,
            Self::CookieReply => 64,
            Self::Transport => 32,
        }
    }

    fn type_id(self) -> u32 {
        match self {
            Self::HandshakeInitiation => 1,
            Self::HandshakeResponse => 2,
            Self::CookieReply => 3,
            Self::Transport => 4,
        }
    }

    fn index(self) -> usize {
        (self.type_id() - 1) as usize
    }

    fn from_packet(packet: &Packet<'_>) -> Self {
        match packet {
            Packet::HandshakeInit(_) => Self::HandshakeInitiation,
            Packet::HandshakeResponse(_) => Self::HandshakeResponse,
            Packet::PacketCookieReply(_) => Self::CookieReply,
            Packet::PacketData(_) => Self::Transport,
        }
    }
}

/// Ошибки создания или применения AWG packet codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketCodecError {
    /// Вход не является каноническим WireGuard-пакетом.
    InvalidCanonicalPacket,
    /// Входящий датаграмм не соответствует ни одному ожидаемому типу.
    InvalidDatagram,
    /// Header protection требует все S1-S4 не меньше 12 байт.
    HeaderProtectionPaddingTooSmall,
    /// Для этой версии codec функция пока не реализована.
    UnsupportedOption(&'static str),
    /// Итоговый датаграмм превышает безопасный UDP payload ceiling.
    PacketTooLarge,
    /// Буфер назначения меньше минимального размера, требуемого BoringTun.
    DestinationBufferTooSmall {
        /// Минимально необходимый размер.
        required: usize,
        /// Фактический размер переданного буфера.
        actual: usize,
    },
    /// Не удалось создать ChaCha20 cipher с переданными key/nonce.
    InvalidCipherParameters,
    /// Для рандомизации H1/H2 необходимы ключи MAC1.
    MissingMac1Keys,
    /// Рандомизация H1/H2 требует DisableCookies на обеих сторонах.
    HeaderRandomizationRequiresDisableCookies,
    /// Не удалось вычислить MAC1 для handshake сообщения.
    Mac1ComputationFailed,
}

impl fmt::Display for PacketCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCanonicalPacket => {
                f.write_str("некорректный канонический WireGuard-пакет")
            }
            Self::InvalidDatagram => f.write_str("некорректный AWG-датаграмм"),
            Self::HeaderProtectionPaddingTooSmall => {
                f.write_str("header protection требует S1-S4 не меньше 12 байт")
            }
            Self::UnsupportedOption(option) => {
                write!(
                    f,
                    "параметр AWG пока не поддерживается этим packet codec: {option}"
                )
            }
            Self::PacketTooLarge => f.write_str("AWG-датаграмм превышает максимальный UDP payload"),
            Self::DestinationBufferTooSmall { required, actual } => {
                write!(
                    f,
                    "буфер слишком мал: требуется {required} байт, получено {actual}"
                )
            }
            Self::InvalidCipherParameters => f.write_str("неверные параметры ChaCha20"),
            Self::MissingMac1Keys => f.write_str("для H1/H2 randomization необходимы ключи MAC1"),
            Self::HeaderRandomizationRequiresDisableCookies => {
                f.write_str("рандомизация H1/H2 требует DisableCookies на обоих peers")
            }
            Self::Mac1ComputationFailed => f.write_str("не удалось пересчитать MAC1"),
        }
    }
}

impl std::error::Error for PacketCodecError {}

/// Кодек внешнего слоя AWG для канонических BoringTun сообщений.
///
/// Реализует H1-H4, S1-S4, header protection и outer RandomTrailers для
/// handshake/cookie. MAC1 пересчитывается при рандомизации H1/H2. Для этого
/// режима обе стороны должны включить DisableCookies: BoringTun API не
/// предоставляет cookie secret для пересчёта MAC2. Transport RandomTrailers,
/// content padding, I1-I5 и junk обрабатываются AwgTunnel wrapper.
#[derive(Clone)]
pub struct AwgPacketCodec {
    padding: [usize; 4],
    header_protection_key: Option<[u8; 32]>,
    header_ranges: [ValueRange; 4],
    inbound_mac1_key: Option<[u8; 32]>,
    outbound_mac1_key: Option<[u8; 32]>,
    random_trailers: bool,
}

impl Drop for AwgPacketCodec {
    fn drop(&mut self) {
        if let Some(key) = self.header_protection_key.as_mut() {
            key.zeroize();
        }
        if let Some(key) = self.inbound_mac1_key.as_mut() {
            key.zeroize();
        }
        if let Some(key) = self.outbound_mac1_key.as_mut() {
            key.zeroize();
        }
    }
}

impl fmt::Debug for AwgPacketCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwgPacketCodec")
            .field("padding", &self.padding)
            .field(
                "header_protection_key",
                &self.header_protection_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("header_ranges", &self.header_ranges)
            .field(
                "inbound_mac1_key",
                &self.inbound_mac1_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "outbound_mac1_key",
                &self.outbound_mac1_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("disable_cookies", &self.disable_cookies)
            .field("random_trailers", &self.random_trailers)
            .finish()
    }
}

impl AwgPacketCodec {
    /// Создаёт codec из конфигурации AWG без MAC1 ключей.
    ///
    /// Подходит для стандартных H1/H2 и для рандомизации H3/H4.
    /// Рандомизация H1/H2 требует конструктора new_with_keys.
    pub fn new(config: &AmneziaConfig) -> Result<Self, PacketCodecError> {
        Self::new_internal(config, None, None)
    }

    /// Создаёт codec с локальным и удалённым public key для MAC1.
    ///
    /// H1/H2 randomization разрешается только при DisableCookies=true:
    /// это исключает необходимость пересчитывать MAC2 с cookie secret,
    /// который закрыт внутри BoringTun.
    pub fn new_with_keys(
        config: &AmneziaConfig,
        local_public_key: &[u8; 32],
        peer_public_key: &[u8; 32],
    ) -> Result<Self, PacketCodecError> {
        let inbound_mac1_key = derive_mac1_key(local_public_key);
        let outbound_mac1_key = derive_mac1_key(peer_public_key);
        Self::new_internal(config, Some(inbound_mac1_key), Some(outbound_mac1_key))
    }

    fn new_internal(
        config: &AmneziaConfig,
        inbound_mac1_key: Option<[u8; 32]>,
        outbound_mac1_key: Option<[u8; 32]>,
    ) -> Result<Self, PacketCodecError> {
        if config.timings.rekey_after_time.is_some()
            || config.timings.rekey_timeout.is_some()
            || config.timings.reject_after_time.is_some()
            || config.timings.keepalive_timeout.is_some()
            || config.timings.max_handshake_attempts.is_some()
        {
            return Err(PacketCodecError::UnsupportedOption("timing overrides"));
        }

        let header_ranges = [
            config.headers.h1.unwrap_or(ValueRange { min: 1, max: 1 }),
            config.headers.h2.unwrap_or(ValueRange { min: 2, max: 2 }),
            config.headers.h3.unwrap_or(ValueRange { min: 3, max: 3 }),
            config.headers.h4.unwrap_or(ValueRange { min: 4, max: 4 }),
        ];
        for (index, range) in header_ranges.iter().enumerate() {
            if range.min > range.max {
                return Err(PacketCodecError::UnsupportedOption("обратный H1-H4 range"));
            }
            let canonical = index as u32 + 1;
            if index < 2 && !range_is_single_value(*range, canonical) && !config.disable_cookies {
                return Err(PacketCodecError::HeaderRandomizationRequiresDisableCookies);
            }
        }
        for left_index in 0..header_ranges.len() {
            for right_index in (left_index + 1)..header_ranges.len() {
                if ranges_overlap(header_ranges[left_index], header_ranges[right_index]) {
                    return Err(PacketCodecError::UnsupportedOption(
                        "пересекающиеся H1-H4 ranges",
                    ));
                }
            }
        }

        let h1_h2_randomized = !range_is_single_value(header_ranges[0], 1)
            || !range_is_single_value(header_ranges[1], 2);
        if h1_h2_randomized && (inbound_mac1_key.is_none() || outbound_mac1_key.is_none()) {
            return Err(PacketCodecError::MissingMac1Keys);
        }

        let padding = [
            usize::from(config.padding.s1.unwrap_or(0)),
            usize::from(config.padding.s2.unwrap_or(0)),
            usize::from(config.padding.s3.unwrap_or(0)),
            usize::from(config.padding.s4.unwrap_or(0)),
        ];
        // Upstream treats an all-zero key as the disabled/default value.
        let header_protection_key = config
            .headers
            .header_protection_key
            .filter(|key| key.iter().any(|byte| *byte != 0));

        if header_protection_key.is_some()
            && padding
                .iter()
                .any(|value| *value < HEADER_PROTECTION_NONCE_SIZE)
        {
            return Err(PacketCodecError::HeaderProtectionPaddingTooSmall);
        }

        Ok(Self {
            padding,
            header_protection_key,
            header_ranges,
            inbound_mac1_key,
            outbound_mac1_key,
            random_trailers: config.random_trailers,
        })
    }

    /// Кодирует канонический WireGuard-пакет в AWG-датаграмм.
    ///
    /// Для handshake/cookie header protection применяется ко всему сообщению;
    /// для transport — только к 16-байтовому транспортному заголовку, как в Go.
    pub fn encode<R: RngCore + CryptoRng>(
        &self,
        canonical_packet: &[u8],
        udp_window: usize,
        rng: &mut R,
    ) -> Result<Vec<u8>, PacketCodecError> {
        let parsed = Tunn::parse_incoming_packet(canonical_packet)
            .map_err(|_| PacketCodecError::InvalidCanonicalPacket)?;
        let kind = MessageKind::from_packet(&parsed);
        let padding_len = self.padding[kind.index()];
        let mut message = canonical_packet.to_vec();
        let header_range = self.header_ranges[kind.index()];
        let header_value = pick_header_value(header_range, rng);
        message[..4].copy_from_slice(&header_value.to_le_bytes());

        if matches!(
            kind,
            MessageKind::HandshakeInitiation | MessageKind::HandshakeResponse
        ) {
            if header_value != kind.type_id() {
                let key = self
                    .outbound_mac1_key
                    .as_ref()
                    .ok_or(PacketCodecError::MissingMac1Keys)?;
                recompute_mac1(&mut message, key)?;
            }
            // Preserve MAC2 exactly as BoringTun produced it. DisableCookies
            // suppresses cookie challenges on receive; it does not erase a
            // previously learned cookie or forbid outgoing MAC2 values.
        }

        let message_len = message.len();
        let trailer_len = if self.random_trailers && kind != MessageKind::Transport {
            let window = if kind == MessageKind::CookieReply {
                DEFAULT_UDP_WINDOW
            } else {
                udp_window
            };
            let space = window.saturating_sub(padding_len + message_len);
            random_below(rng, space)
        } else {
            0
        };
        let total_len = padding_len
            .checked_add(message_len)
            .and_then(|length| length.checked_add(trailer_len))
            .filter(|length| *length <= MAX_UDP_PAYLOAD)
            .ok_or(PacketCodecError::PacketTooLarge)?;

        let mut datagram = vec![0u8; total_len];
        rng.fill_bytes(&mut datagram[..padding_len]);
        let message_end = padding_len + message_len;
        datagram[padding_len..message_end].copy_from_slice(&message);

        if let Some(key) = self.header_protection_key {
            let nonce: [u8; HEADER_PROTECTION_NONCE_SIZE] = datagram
                [..HEADER_PROTECTION_NONCE_SIZE]
                .try_into()
                .expect("padding length is validated by the codec constructor");
            Self::apply_header_protection(
                key,
                &nonce,
                kind,
                &mut datagram[padding_len..message_end],
            )?;
        }
        if trailer_len > 0 {
            rng.fill_bytes(&mut datagram[message_end..]);
        }

        Ok(datagram)
    }

    /// Декодирует AWG-датаграмм в канонический WireGuard-пакет.
    ///
    /// Кандидаты проверяются по S1-S4; тип после снятия защиты должен совпасть
    /// с классом кандидата, после чего выполняется строгий разбор BoringTun.
    pub fn decode(&self, datagram: &[u8]) -> Result<Vec<u8>, PacketCodecError> {
        if datagram.len() > MAX_UDP_PAYLOAD {
            return Err(PacketCodecError::PacketTooLarge);
        }

        for kind in [
            MessageKind::HandshakeInitiation,
            MessageKind::HandshakeResponse,
            MessageKind::CookieReply,
            MessageKind::Transport,
        ] {
            let padding_len = self.padding[kind.index()];
            if datagram.len() < padding_len + 4 {
                continue;
            }

            let mut candidate = datagram[padding_len..].to_vec();
            if self.random_trailers && kind != MessageKind::Transport {
                let expected_size = kind.message_size();
                if candidate.len() < expected_size {
                    continue;
                }
                candidate.truncate(expected_size);
            }
            let header_range = self.header_ranges[kind.index()];
            if let Some(key) = self.header_protection_key {
                let nonce = &datagram[..HEADER_PROTECTION_NONCE_SIZE];
                if Self::unprotect_candidate(key, nonce, kind, header_range, &mut candidate)
                    .is_err()
                {
                    continue;
                }
            } else if !header_range.contains(u32::from_le_bytes(candidate[..4].try_into().unwrap()))
            {
                continue;
            }

            let received_header = u32::from_le_bytes(candidate[..4].try_into().unwrap());
            if received_header != kind.type_id() {
                let handshake = matches!(
                    kind,
                    MessageKind::HandshakeInitiation | MessageKind::HandshakeResponse
                );
                let mac1_key = if handshake {
                    let key = self
                        .inbound_mac1_key
                        .as_ref()
                        .ok_or(PacketCodecError::MissingMac1Keys)?;

                    // A random header candidate can overlap bytes from another
                    // message kind (notably with RandomTrailers enabled). Verify
                    // the sender's MAC1 before canonicalizing the type field;
                    // otherwise arbitrary bytes could be rewritten into a
                    // syntactically valid handshake candidate.
                    if !verify_mac1(&candidate, key) {
                        continue;
                    }
                    Some(key)
                } else {
                    None
                };

                // MAC1 authenticates the randomized wire header. After it has
                // been verified, restore the canonical type and recompute MAC1
                // for BoringTun's unmodified WireGuard parser.
                candidate[..4].copy_from_slice(&kind.type_id().to_le_bytes());
                if let Some(key) = mac1_key {
                    if recompute_mac1(&mut candidate, key).is_err() {
                        continue;
                    }
                }
            }

            let parsed = match Tunn::parse_incoming_packet(&candidate) {
                Ok(packet) => packet,
                Err(_) => continue,
            };
            if MessageKind::from_packet(&parsed) == kind {
                return Ok(candidate);
            }
        }

        Err(PacketCodecError::InvalidDatagram)
    }

    /// S4 padding, используемый при создании transport datagram.
    pub fn transport_padding(&self) -> usize {
        self.padding[MessageKind::Transport.index()]
    }

    /// Включены ли RandomTrailers в конфигурации.
    pub fn random_trailers_enabled(&self) -> bool {
        self.random_trailers
    }

    fn apply_header_protection(
        key: [u8; 32],
        nonce: &[u8],
        kind: MessageKind,
        packet: &mut [u8],
    ) -> Result<(), PacketCodecError> {
        let mut cipher = ChaCha20::new_from_slices(&key, nonce)
            .map_err(|_| PacketCodecError::InvalidCipherParameters)?;
        match kind {
            MessageKind::Transport => {
                cipher.apply_keystream(&mut packet[..TRANSPORT_HEADER_SIZE]);
            }
            _ => cipher.apply_keystream(packet),
        }
        Ok(())
    }

    fn unprotect_candidate(
        key: [u8; 32],
        nonce: &[u8],
        expected_kind: MessageKind,
        allowed_range: ValueRange,
        packet: &mut [u8],
    ) -> Result<(), PacketCodecError> {
        let mut cipher = ChaCha20::new_from_slices(&key, nonce)
            .map_err(|_| PacketCodecError::InvalidCipherParameters)?;
        cipher.apply_keystream(&mut packet[..4]);
        if !allowed_range.contains(u32::from_le_bytes(packet[..4].try_into().unwrap())) {
            return Err(PacketCodecError::InvalidDatagram);
        }

        match expected_kind {
            MessageKind::Transport => {
                if packet.len() < TRANSPORT_HEADER_SIZE {
                    return Err(PacketCodecError::InvalidDatagram);
                }
                cipher.apply_keystream(&mut packet[4..TRANSPORT_HEADER_SIZE]);
            }
            _ => cipher.apply_keystream(&mut packet[4..]),
        }
        Ok(())
    }
}

fn ranges_overlap(left: ValueRange, right: ValueRange) -> bool {
    let left_start = u64::from(left.min);
    let left_end = if left.min == left.max {
        left_start + 1
    } else {
        u64::from(left.max)
    };
    let right_start = u64::from(right.min);
    let right_end = if right.min == right.max {
        right_start + 1
    } else {
        u64::from(right.max)
    };
    left_start < right_end && right_start < left_end
}

fn range_is_single_value(range: ValueRange, expected: u32) -> bool {
    range.min == expected && (range.max == expected || range.max == expected + 1)
}

fn pick_header_value<R: RngCore>(range: ValueRange, rng: &mut R) -> u32 {
    if range.min == range.max {
        range.min
    } else {
        range.min + random_below(rng, (range.max - range.min) as usize) as u32
    }
}

fn derive_mac1_key(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hash = Blake2s256::new();
    hash.update(b"mac1----");
    hash.update(public_key);
    hash.finalize().into()
}

fn verify_mac1(packet: &[u8], key: &[u8; 32]) -> bool {
    let Some(mac1_offset) = packet.len().checked_sub(32) else {
        return false;
    };
    let Ok(mut mac) = Blake2sMac::<U16>::new_from_slice(key) else {
        return false;
    };
    blake2::digest::Update::update(&mut mac, &packet[..mac1_offset]);
    let expected = mac.finalize_fixed();

    // MAC1 is not a secret, but constant-time comparison keeps this helper
    // safe if the surrounding key handling changes in a future refactor.
    let mut difference = 0u8;
    for (expected_byte, received_byte) in
        expected.iter().zip(&packet[mac1_offset..mac1_offset + 16])
    {
        difference |= expected_byte ^ received_byte;
    }
    difference == 0
}

fn recompute_mac1(packet: &mut [u8], key: &[u8; 32]) -> Result<(), PacketCodecError> {
    let mac1_offset = packet
        .len()
        .checked_sub(32)
        .ok_or(PacketCodecError::InvalidCanonicalPacket)?;
    let mut mac: Blake2sMac<U16> =
        Blake2sMac::new_from_slice(key).map_err(|_| PacketCodecError::Mac1ComputationFailed)?;
    blake2::digest::Update::update(&mut mac, &packet[..mac1_offset]);
    let digest = mac.finalize_fixed();
    packet[mac1_offset..mac1_offset + 16].copy_from_slice(&digest);
    Ok(())
}

fn random_below<R: RngCore>(rng: &mut R, upper: usize) -> usize {
    if upper == 0 {
        return 0;
    }
    let upper = upper as u32;
    let threshold = upper.wrapping_neg() % upper;
    loop {
        let value = rng.next_u32();
        if value >= threshold {
            return (value % upper) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng(u8);

    impl CryptoRng for FixedRng {}

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            u32::from(self.0) * 0x0101_0101
        }

        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32()) | (u64::from(self.next_u32()) << 32)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.0;
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn canonical_packet(kind: MessageKind) -> Vec<u8> {
        let length = match kind {
            MessageKind::HandshakeInitiation => 148,
            MessageKind::HandshakeResponse => 92,
            MessageKind::CookieReply => 64,
            MessageKind::Transport => 32,
        };
        let mut packet = vec![0u8; length];
        packet[..4].copy_from_slice(&kind.type_id().to_le_bytes());
        packet
    }

    fn base_config(with_header_protection: bool) -> AmneziaConfig {
        let mut config = AmneziaConfig::default();
        config.padding.s1 = Some(12);
        config.padding.s2 = Some(12);
        config.padding.s3 = Some(12);
        config.padding.s4 = Some(12);
        if with_header_protection {
            config.headers.header_protection_key = Some([0x55; 32]);
        }
        config
    }

    #[test]
    fn round_trips_all_four_wireguard_message_types_with_padding() {
        let mut config = base_config(false);
        config.padding.s1 = Some(4);
        config.padding.s2 = Some(8);
        config.padding.s3 = Some(16);
        config.padding.s4 = Some(20);
        let codec = AwgPacketCodec::new(&config).unwrap();

        for kind in [
            MessageKind::HandshakeInitiation,
            MessageKind::HandshakeResponse,
            MessageKind::CookieReply,
            MessageKind::Transport,
        ] {
            let packet = canonical_packet(kind);
            let mut rng = FixedRng(0xa5);
            let encoded = codec.encode(&packet, 500, &mut rng).unwrap();
            assert_eq!(encoded.len(), packet.len() + codec.padding[kind.index()]);
            if kind == MessageKind::Transport {
                assert_eq!(
                    &encoded[codec.padding[kind.index()] + TRANSPORT_HEADER_SIZE..],
                    &packet[TRANSPORT_HEADER_SIZE..]
                );
            }
            assert_eq!(codec.decode(&encoded).unwrap(), packet);
        }
    }

    #[test]
    fn round_trips_all_message_types_with_chacha20_header_protection() {
        let codec = AwgPacketCodec::new(&base_config(true)).unwrap();
        for kind in [
            MessageKind::HandshakeInitiation,
            MessageKind::HandshakeResponse,
            MessageKind::CookieReply,
            MessageKind::Transport,
        ] {
            let packet = canonical_packet(kind);
            let mut rng = FixedRng(0x7b);
            let encoded = codec.encode(&packet, 500, &mut rng).unwrap();
            assert_ne!(&encoded[12..16], &packet[..4]);
            assert_eq!(codec.decode(&encoded).unwrap(), packet);
        }
    }

    #[test]
    fn codec_debug_redacts_header_protection_and_mac1_keys() {
        let config = base_config(true);
        let codec = AwgPacketCodec::new_with_keys(&config, &[0xa5; 32], &[0x5a; 32]).unwrap();
        let rendered = format!("{codec:?}");

        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("55555555"));
        assert!(!rendered.contains("a5a5a5a5"));
        assert!(!rendered.contains("5a5a5a5a"));
    }

    #[test]
    fn all_zero_header_protection_key_disables_the_cipher() {
        let mut config = AmneziaConfig::default();
        config.headers.header_protection_key = Some([0; 32]);
        let codec = AwgPacketCodec::new(&config).unwrap();
        let packet = canonical_packet(MessageKind::HandshakeInitiation);
        let encoded = codec.encode(&packet, 500, &mut FixedRng(9)).unwrap();
        assert_eq!(codec.decode(&encoded).unwrap(), packet);
    }

    #[test]
    fn rejects_header_protection_when_any_padding_is_missing_or_too_small() {
        let mut config = base_config(true);
        config.padding.s3 = None;
        assert_eq!(
            AwgPacketCodec::new(&config).err(),
            Some(PacketCodecError::HeaderProtectionPaddingTooSmall)
        );
    }

    #[test]
    fn rejects_randomized_handshake_headers_until_mac_recalculation_is_available() {
        let mut config = base_config(false);
        config.headers.h1 = Some(ValueRange { min: 100, max: 200 });
        assert_eq!(
            AwgPacketCodec::new(&config).err(),
            Some(PacketCodecError::HeaderRandomizationRequiresDisableCookies)
        );
    }

    #[test]
    fn disable_cookies_preserves_existing_mac2_value() {
        let mut config = base_config(false);
        config.disable_cookies = true;
        config.headers.h1 = Some(ValueRange { min: 100, max: 101 });
        let codec = AwgPacketCodec::new_with_keys(&config, &[0x11; 32], &[0x11; 32]).unwrap();

        let mut packet = canonical_packet(MessageKind::HandshakeInitiation);
        let mac2_offset = packet.len() - 16;
        packet[mac2_offset..].fill(0x77);
        let encoded = codec.encode(&packet, 500, &mut FixedRng(0x31)).unwrap();

        assert_eq!(&encoded[12 + 148 - 16..12 + 148], &[0x77; 16]);
        assert_eq!(codec.decode(&encoded).unwrap()[148 - 16..], [0x77; 16]);
    }

    #[test]
    fn randomized_h1_h2_require_disable_cookies_and_mac1_keys() {
        let mut config = base_config(false);
        config.disable_cookies = true;
        config.headers.h1 = Some(ValueRange { min: 100, max: 200 });
        config.headers.h2 = Some(ValueRange { min: 300, max: 400 });
        assert_eq!(
            AwgPacketCodec::new(&config).err(),
            Some(PacketCodecError::MissingMac1Keys)
        );
    }

    #[test]
    fn randomized_h3_h4_work_without_handshake_mac_keys() {
        let mut config = base_config(false);
        config.headers.h3 = Some(ValueRange { min: 50, max: 60 });
        config.headers.h4 = Some(ValueRange { min: 70, max: 80 });
        let codec = AwgPacketCodec::new(&config).unwrap();

        for kind in [MessageKind::CookieReply, MessageKind::Transport] {
            let packet = canonical_packet(kind);
            let encoded = codec.encode(&packet, 500, &mut FixedRng(0x2b)).unwrap();
            assert_eq!(codec.decode(&encoded).unwrap(), packet);
        }
    }

    #[test]
    fn random_trailers_are_added_to_handshake_and_stripped_on_receive() {
        let mut config = base_config(false);
        config.random_trailers = true;
        let codec = AwgPacketCodec::new(&config).unwrap();
        let packet = canonical_packet(MessageKind::HandshakeInitiation);
        let encoded = codec.encode(&packet, 500, &mut FixedRng(0x42)).unwrap();
        assert!(encoded.len() > codec.padding[0] + packet.len());
        assert_eq!(codec.decode(&encoded).unwrap(), packet);
    }

    #[test]
    fn cookie_reply_random_trailer_uses_the_default_udp_window() {
        let mut config = base_config(false);
        config.random_trailers = true;
        let codec = AwgPacketCodec::new(&config).unwrap();
        let packet = canonical_packet(MessageKind::CookieReply);
        let encoded = codec.encode(&packet, 4_000, &mut FixedRng(0x31)).unwrap();
        assert!(encoded.len() <= DEFAULT_UDP_WINDOW);
        assert_eq!(codec.decode(&encoded).unwrap(), packet);
    }

    #[test]
    fn random_trailers_are_not_appended_outside_transport_ciphertext() {
        let mut config = base_config(false);
        config.random_trailers = true;
        let codec = AwgPacketCodec::new(&config).unwrap();
        let packet = canonical_packet(MessageKind::Transport);
        let encoded = codec.encode(&packet, 500, &mut FixedRng(0x42)).unwrap();
        assert_eq!(encoded.len(), codec.padding[3] + packet.len());
        assert_eq!(codec.decode(&encoded).unwrap(), packet);
    }

    #[test]
    fn false_randomized_handshake_candidate_does_not_steal_transport_datagram() {
        let mut config = base_config(false);
        config.disable_cookies = true;
        config.random_trailers = true;
        config.padding.s4 = Some(16);
        config.headers.h1 = Some(ValueRange { min: 100, max: 101 });
        config.headers.h4 = Some(ValueRange { min: 200, max: 201 });

        let codec = AwgPacketCodec::new_with_keys(&config, &[0x11; 32], &[0x22; 32]).unwrap();

        // The bytes at S1 look like a randomized initiation header, but the
        // actual datagram starts its transport message at S4. Its apparent
        // initiation MAC1 is random ciphertext and must not be recomputed into
        // a valid MAC1 before the transport candidate is considered.
        let mut transport = canonical_packet(MessageKind::Transport);
        transport.resize(160, 0x5a);
        transport[..4].copy_from_slice(&200u32.to_le_bytes());

        let mut datagram = vec![0x33; 12];
        datagram.extend_from_slice(&100u32.to_le_bytes());
        datagram.extend_from_slice(&transport);

        assert_eq!(codec.decode(&datagram).unwrap(), {
            let mut expected = transport;
            expected[..4].copy_from_slice(&4u32.to_le_bytes());
            expected
        });
    }

    #[test]
    fn verify_mac1_detects_modified_handshake_bytes() {
        let key = [0x7d; 32];
        let mut packet = canonical_packet(MessageKind::HandshakeInitiation);
        recompute_mac1(&mut packet, &key).unwrap();
        assert!(verify_mac1(&packet, &key));

        packet[24] ^= 0x80;
        assert!(!verify_mac1(&packet, &key));
    }

    #[test]
    fn decode_never_panics_for_short_or_random_datagrams() {
        let codec = AwgPacketCodec::new(&base_config(true)).unwrap();
        let mut state = 0x1234_5678u32;
        for length in 0..512 {
            let mut datagram = vec![0u8; length];
            for byte in &mut datagram {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            let _ = codec.decode(&datagram);
        }
    }

    #[test]
    fn rejects_malformed_and_oversized_datagrams() {
        let codec = AwgPacketCodec::new(&base_config(false)).unwrap();
        assert_eq!(
            codec.decode(&[0, 1, 2]),
            Err(PacketCodecError::InvalidDatagram)
        );
        assert_eq!(
            codec.decode(&vec![0; MAX_UDP_PAYLOAD + 1]),
            Err(PacketCodecError::PacketTooLarge)
        );
    }

    #[test]
    fn rejects_noncanonical_packets_on_encode() {
        let codec = AwgPacketCodec::new(&base_config(false)).unwrap();
        assert_eq!(
            codec.encode(&[1, 2, 3, 4], 500, &mut FixedRng(1)),
            Err(PacketCodecError::InvalidCanonicalPacket)
        );
    }

    #[test]
    fn rejects_wrong_header_protection_key() {
        let sender = AwgPacketCodec::new(&base_config(true)).unwrap();
        let mut wrong = base_config(true);
        wrong.headers.header_protection_key = Some([0x99; 32]);
        let receiver = AwgPacketCodec::new(&wrong).unwrap();

        let packet = canonical_packet(MessageKind::HandshakeInitiation);
        let encoded = sender.encode(&packet, 500, &mut FixedRng(3)).unwrap();
        assert_eq!(
            receiver.decode(&encoded),
            Err(PacketCodecError::InvalidDatagram)
        );
    }
}

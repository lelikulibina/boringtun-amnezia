//! Базовое внешнее кодирование AWG-пакетов.
//!
//! Этот слой добавляет S1-S4 padding и ChaCha20 header protection поверх
//! канонических пакетов BoringTun. Чтобы MAC1/MAC2 оставались корректными,
//! текущая версия принимает только H1-H4, равные стандартным WG type IDs.
//! Случайные H-диапазоны требуют переноса MAC-генерации внутрь форка BoringTun.

use crate::{AmneziaConfig, ValueRange};
use boringtun::noise::{Packet, Tunn};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand_core::RngCore;
use std::fmt;

const MAX_UDP_PAYLOAD: usize = 65_507;
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
    /// Не удалось создать ChaCha20 cipher с переданными key/nonce.
    InvalidCipherParameters,
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
            Self::InvalidCipherParameters => f.write_str("неверные параметры ChaCha20"),
        }
    }
}

impl std::error::Error for PacketCodecError {}

/// Кодек внешнего слоя AWG для канонических BoringTun сообщений.
///
/// Реализует S1-S4 и header protection. Не реализует H-рандомизацию,
/// junk/signature packets, content padding, random trailers или изменение
/// поведения cookie/timers. Такие параметры отклоняются конструктором,
/// чтобы приложение не могло случайно включить неработающую опцию.
#[derive(Debug, Clone)]
pub struct AwgPacketCodec {
    padding: [usize; 4],
    header_protection_key: Option<[u8; 32]>,
}

impl AwgPacketCodec {
    /// Создаёт codec из конфигурации AWG.
    ///
    /// В текущем слое разрешены только стандартные H1-H4 значения 1,2,3,4:
    /// это сохраняет корректность MAC1/MAC2, которые формирует BoringTun.
    pub fn new(config: &AmneziaConfig) -> Result<Self, PacketCodecError> {
        let expected_headers = [
            (config.headers.h1, 1),
            (config.headers.h2, 2),
            (config.headers.h3, 3),
            (config.headers.h4, 4),
        ];
        for (range, expected) in expected_headers {
            if let Some(range) = range {
                if range
                    != (ValueRange {
                        min: expected,
                        max: expected,
                    })
                {
                    return Err(PacketCodecError::UnsupportedOption(
                        "произвольные H1-H4 требуют пересчёта MAC внутри BoringTun",
                    ));
                }
            }
        }

        if config.padding.content_padding.is_some() {
            return Err(PacketCodecError::UnsupportedOption("content_padding"));
        }
        if config.junk.count > 0 {
            return Err(PacketCodecError::UnsupportedOption("Jc/Jmin/Jmax"));
        }
        if config.signature_packets.iter().any(Option::is_some) {
            return Err(PacketCodecError::UnsupportedOption("I1-I5 transport"));
        }
        if config.timings.rekey_after_time.is_some()
            || config.timings.rekey_timeout.is_some()
            || config.timings.reject_after_time.is_some()
            || config.timings.keepalive_timeout.is_some()
            || config.timings.max_handshake_attempts.is_some()
        {
            return Err(PacketCodecError::UnsupportedOption("timing overrides"));
        }
        if config.random_trailers {
            return Err(PacketCodecError::UnsupportedOption("RandomTrailers"));
        }
        if config.disable_cookies {
            return Err(PacketCodecError::UnsupportedOption("DisableCookies"));
        }

        let padding = [
            usize::from(config.padding.s1.unwrap_or(0)),
            usize::from(config.padding.s2.unwrap_or(0)),
            usize::from(config.padding.s3.unwrap_or(0)),
            usize::from(config.padding.s4.unwrap_or(0)),
        ];
        let header_protection_key = config.headers.header_protection_key;

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
        })
    }

    /// Кодирует канонический WireGuard-пакет в AWG-датаграмм.
    ///
    /// Для handshake/cookie header protection применяется ко всему сообщению;
    /// для transport — только к 16-байтовому транспортному заголовку, как в Go.
    pub fn encode<R: RngCore>(
        &self,
        canonical_packet: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, PacketCodecError> {
        let parsed = Tunn::parse_incoming_packet(canonical_packet)
            .map_err(|_| PacketCodecError::InvalidCanonicalPacket)?;
        let kind = MessageKind::from_packet(&parsed);
        let padding_len = self.padding[kind.index()];
        let total_len = padding_len
            .checked_add(canonical_packet.len())
            .filter(|length| *length <= MAX_UDP_PAYLOAD)
            .ok_or(PacketCodecError::PacketTooLarge)?;

        let mut datagram = vec![0u8; total_len];
        rng.fill_bytes(&mut datagram[..padding_len]);
        datagram[padding_len..].copy_from_slice(canonical_packet);

        if let Some(key) = self.header_protection_key {
            let nonce = &datagram[..HEADER_PROTECTION_NONCE_SIZE];
            Self::apply_header_protection(key, nonce, kind, &mut datagram[padding_len..])?;
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
            if let Some(key) = self.header_protection_key {
                let nonce = &datagram[..HEADER_PROTECTION_NONCE_SIZE];
                if Self::unprotect_candidate(key, nonce, kind, &mut candidate).is_err() {
                    continue;
                }
            } else if u32::from_le_bytes(candidate[..4].try_into().unwrap()) != kind.type_id() {
                continue;
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
        packet: &mut [u8],
    ) -> Result<(), PacketCodecError> {
        let mut cipher = ChaCha20::new_from_slices(&key, nonce)
            .map_err(|_| PacketCodecError::InvalidCipherParameters)?;
        cipher.apply_keystream(&mut packet[..4]);
        if u32::from_le_bytes(packet[..4].try_into().unwrap()) != expected_kind.type_id() {
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

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng(u8);

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

    fn config(with_header_protection: bool) -> AmneziaConfig {
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
        let mut config = config(false);
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
            let encoded = codec.encode(&packet, &mut rng).unwrap();
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
        let codec = AwgPacketCodec::new(&config(true)).unwrap();
        for kind in [
            MessageKind::HandshakeInitiation,
            MessageKind::HandshakeResponse,
            MessageKind::CookieReply,
            MessageKind::Transport,
        ] {
            let packet = canonical_packet(kind);
            let mut rng = FixedRng(0x7b);
            let encoded = codec.encode(&packet, &mut rng).unwrap();
            assert_ne!(&encoded[12..16], &packet[..4]);
            assert_eq!(codec.decode(&encoded).unwrap(), packet);
        }
    }

    #[test]
    fn rejects_header_protection_when_any_padding_is_missing_or_too_small() {
        let mut config = config(true);
        config.padding.s3 = None;
        assert_eq!(
            AwgPacketCodec::new(&config).err(),
            Some(PacketCodecError::HeaderProtectionPaddingTooSmall)
        );
    }

    #[test]
    fn rejects_randomized_handshake_headers_until_mac_recalculation_is_available() {
        let mut config = config(false);
        config.headers.h1 = Some(ValueRange { min: 100, max: 200 });
        assert_eq!(
            AwgPacketCodec::new(&config).err(),
            Some(PacketCodecError::UnsupportedOption(
                "произвольные H1-H4 требуют пересчёта MAC внутри BoringTun"
            ))
        );
    }

    #[test]
    fn rejects_unimplemented_awg_features_instead_of_silently_ignoring_them() {
        let mut config = config(false);
        config.junk.count = 2;
        assert_eq!(
            AwgPacketCodec::new(&config).err(),
            Some(PacketCodecError::UnsupportedOption("Jc/Jmin/Jmax"))
        );

        let mut config = config(false);
        config.random_trailers = true;
        assert_eq!(
            AwgPacketCodec::new(&config).err(),
            Some(PacketCodecError::UnsupportedOption("RandomTrailers"))
        );
    }

    #[test]
    fn rejects_malformed_and_oversized_datagrams() {
        let codec = AwgPacketCodec::new(&config(false)).unwrap();
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
        let codec = AwgPacketCodec::new(&config(false)).unwrap();
        assert_eq!(
            codec.encode(&[1, 2, 3, 4], &mut FixedRng(1)),
            Err(PacketCodecError::InvalidCanonicalPacket)
        );
    }

    #[test]
    fn rejects_wrong_header_protection_key() {
        let sender = AwgPacketCodec::new(&config(true)).unwrap();
        let mut wrong = config(true);
        wrong.headers.header_protection_key = Some([0x99; 32]);
        let receiver = AwgPacketCodec::new(&wrong).unwrap();

        let packet = canonical_packet(MessageKind::HandshakeInitiation);
        let encoded = sender.encode(&packet, &mut FixedRng(3)).unwrap();
        assert_eq!(
            receiver.decode(&encoded),
            Err(PacketCodecError::InvalidDatagram)
        );
    }
}

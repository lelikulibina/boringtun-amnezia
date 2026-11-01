//! Высокоуровневая обёртка BoringTun с базовым AWG framing.

use super::packet_codec::{AwgPacketCodec, PacketCodecError};
use crate::wireguard::{x25519, Tunn, TunnResult};
use crate::{
    AmneziaConfig, ConfigError, EngineConfig, JunkConfig, ProtocolMode, SignatureTemplate,
    ValueRange,
};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::rate_limiter::RateLimiter;
use rand_core::{CryptoRng, RngCore};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_UDP_WINDOW: usize = 500;
const MIN_TRANSPORT_MESSAGE_SIZE: usize = 32;
const MAX_UDP_PAYLOAD: usize = 65_507;

/// Результат обработки AWG-туннеля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwgTunnelOutput {
    /// Нет действий для сетевого или TUN уровня.
    Done,
    /// Датаграмм, который необходимо отправить в UDP socket.
    WriteToNetwork(Vec<u8>),
    /// Несколько UDP-датаграмм в обязательном порядке: I1-I5, junk, handshake.
    WriteToNetworkBatch(Vec<Vec<u8>>),
    /// Расшифрованный IPv4 пакет, который следует записать в TUN.
    WriteToTunnelV4(Vec<u8>, Ipv4Addr),
    /// Расшифрованный IPv6 пакет, который следует записать в TUN.
    WriteToTunnelV6(Vec<u8>, Ipv6Addr),
}

/// Ошибки AWG tunnel wrapper.
#[derive(Debug)]
pub enum AwgTunnelError {
    /// Ошибка проверки конфигурации протокола.
    Configuration(ConfigError),
    /// Ошибка AWG framing/codec.
    Codec(PacketCodecError),
    /// Ошибка разбора/генерации CPS шаблона.
    Signature(crate::signature::SignatureError),
    /// Ошибка криптографического или протокольного движка BoringTun.
    WireGuard(WireGuardError),
    /// Для AWG tunnel передан режим, отличный от AWG 3.0/3.1.
    InvalidMode,
}

impl fmt::Display for AwgTunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => write!(f, "ошибка конфигурации AWG: {error}"),
            Self::Codec(error) => write!(f, "ошибка AWG codec: {error}"),
            Self::Signature(error) => write!(f, "ошибка CPS шаблона: {error}"),
            Self::WireGuard(error) => write!(f, "ошибка BoringTun: {error:?}"),
            Self::InvalidMode => f.write_str("AwgTunnel требует режим AmneziaWG 3.0 или 3.1"),
        }
    }
}

impl std::error::Error for AwgTunnelError {}

impl From<ConfigError> for AwgTunnelError {
    fn from(value: ConfigError) -> Self {
        Self::Configuration(value)
    }
}

impl From<PacketCodecError> for AwgTunnelError {
    fn from(value: PacketCodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<crate::signature::SignatureError> for AwgTunnelError {
    fn from(value: crate::signature::SignatureError) -> Self {
        Self::Signature(value)
    }
}

/// BoringTun Tunn с AWG packet framing и pre-handshake пакетами.
pub struct AwgTunnel {
    tunn: Tunn,
    codec: AwgPacketCodec,
    junk: JunkConfig,
    signature_packets: [Option<SignatureTemplate>; 5],
    content_padding: Option<ValueRange>,
    udp_window: usize,
}

impl AwgTunnel {
    /// Создаёт туннель для одного peer в выбранном поколении AmneziaWG.
    pub fn new(
        mode: ProtocolMode,
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        config: &AmneziaConfig,
    ) -> Result<Self, AwgTunnelError> {
        if !matches!(mode, ProtocolMode::AmneziaWg30 | ProtocolMode::AmneziaWg31) {
            return Err(AwgTunnelError::InvalidMode);
        }

        EngineConfig {
            mode,
            amnezia: Some(config.clone()),
        }
        .validate()?;

        let codec = AwgPacketCodec::new(config)?;
        let local_public = x25519::PublicKey::from(&static_private);
        // An effectively unbounded limit preserves MAC1 validation while
        // disabling cookie challenges, matching AWG DisableCookies behavior.
        let rate_limiter = if config.disable_cookies {
            Some(Arc::new(RateLimiter::new(&local_public, u64::MAX)))
        } else {
            None
        };
        let tunn = Tunn::new(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            index,
            rate_limiter,
        );
        Ok(Self {
            tunn,
            codec,
            junk: config.junk,
            signature_packets: config.signature_packets.clone(),
            content_padding: config.padding.content_padding,
            udp_window: DEFAULT_UDP_WINDOW,
        })
    }

    /// Формирует handshake initiation и возвращает datagram batch:
    /// сначала I1-I5, затем junk-пакеты, в конце сам handshake.
    pub fn initiate_handshake<R: RngCore + CryptoRng>(
        &mut self,
        dst: &mut [u8],
        force_resend: bool,
        rng: &mut R,
    ) -> Result<AwgTunnelOutput, AwgTunnelError> {
        let result = self.tunn.format_handshake_initiation(dst, force_resend);
        match result {
            TunnResult::WriteToNetwork(packet) => {
                let mut batch = self.preamble_packets(rng)?;
                batch.push(self.codec.encode(packet, self.udp_window, rng)?);
                Ok(AwgTunnelOutput::WriteToNetworkBatch(batch))
            }
            other => self.map_result(other, rng),
        }
    }

    /// Шифрует внутренний IP-пакет и добавляет AWG framing.
    ///
    /// ContentPaddingAddition и RandomTrailers для transport добавляются
    /// нулевыми байтами к plaintext до вызова BoringTun. Приёмник WireGuard
    /// обрежет их по длине внутреннего IP-пакета после AEAD проверки.
    pub fn encapsulate<R: RngCore + CryptoRng>(
        &mut self,
        inner_packet: &[u8],
        dst: &mut [u8],
        rng: &mut R,
    ) -> Result<AwgTunnelOutput, AwgTunnelError> {
        let base_size = self
            .codec
            .transport_padding()
            .checked_add(MIN_TRANSPORT_MESSAGE_SIZE)
            .and_then(|size| size.checked_add(inner_packet.len()))
            .filter(|size| *size <= MAX_UDP_PAYLOAD)
            .ok_or(PacketCodecError::PacketTooLarge)?;

        // Upstream expands the peer UDP window to the largest base transport
        // datagram observed for this peer. Smaller packets can then be padded
        // without exceeding that learned window.
        self.udp_window = self.udp_window.max(base_size);
        let available = self.udp_window.saturating_sub(base_size);
        let extra_padding = if inner_packet.is_empty() {
            0
        } else {
            self.transport_padding_addition(available, rng)
        };

        let mut plaintext = inner_packet.to_vec();
        plaintext.resize(plaintext.len() + extra_padding, 0);

        let result = self.tunn.encapsulate(&plaintext, dst);
        self.map_result(result, rng)
    }

    /// Снимает AWG framing и передаёт канонический пакет в BoringTun.
    ///
    /// Пустой datagram передаётся напрямую: BoringTun использует его для
    /// продолжения отправки ранее поставленных в очередь пакетов.
    pub fn decapsulate<R: RngCore + CryptoRng>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &mut [u8],
        rng: &mut R,
    ) -> Result<AwgTunnelOutput, AwgTunnelError> {
        let result = if datagram.is_empty() {
            self.tunn.decapsulate(src_addr, &[], dst)
        } else {
            let canonical = self.codec.decode(datagram)?;
            self.tunn.decapsulate(src_addr, &canonical, dst)
        };
        self.map_result(result, rng)
    }

    /// Сбрасывает обученное UDP окно после смены endpoint.
    pub fn reset_udp_window(&mut self) {
        self.udp_window = DEFAULT_UDP_WINDOW;
    }

    fn transport_padding_addition<R: RngCore + CryptoRng>(
        &self,
        available: usize,
        rng: &mut R,
    ) -> usize {
        if let Some(range) = self.content_padding {
            if range.min != 0 || range.max != 0 {
                let selected = random_range(rng, range.min, range.max);
                return (selected as usize).min(available);
            }
        }

        if self.codec.random_trailers_enabled() {
            return random_below(rng, available);
        }
        0
    }

    fn preamble_packets<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Vec<Vec<u8>>, AwgTunnelError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let mut packets = Vec::new();
        for template in self.signature_packets.iter().flatten() {
            if template.output_len() > 0 {
                packets.push(template.render(rng, timestamp)?);
            }
        }

        if self.junk.count > 0 {
            let width = (self.junk.max_size - self.junk.min_size) as usize;
            for _ in 0..self.junk.count {
                let size = self.junk.min_size as usize + random_below(rng, width);
                let mut packet = vec![0u8; size];
                rng.fill_bytes(&mut packet);
                packets.push(packet);
            }
        }

        Ok(packets)
    }

    fn map_result<R: RngCore + CryptoRng>(
        &mut self,
        result: TunnResult<'_>,
        rng: &mut R,
    ) -> Result<AwgTunnelOutput, AwgTunnelError> {
        match result {
            TunnResult::Done => Ok(AwgTunnelOutput::Done),
            TunnResult::Err(error) => Err(AwgTunnelError::WireGuard(error)),
            TunnResult::WriteToNetwork(packet) => Ok(AwgTunnelOutput::WriteToNetwork(
                self.codec.encode(packet, self.udp_window, rng)?,
            )),
            TunnResult::WriteToTunnelV4(packet, source) => {
                Ok(AwgTunnelOutput::WriteToTunnelV4(packet.to_vec(), source))
            }
            TunnResult::WriteToTunnelV6(packet, source) => {
                Ok(AwgTunnelOutput::WriteToTunnelV6(packet.to_vec(), source))
            }
        }
    }
}

fn random_below<R: RngCore>(rng: &mut R, upper: usize) -> usize {
    if upper == 0 {
        return 0;
    }
    let upper = upper as u64;
    random_below_u64(rng, upper) as usize
}

fn random_range<R: RngCore>(rng: &mut R, min: u32, max: u32) -> u32 {
    if max <= min {
        return min;
    }
    let width = u64::from(max) - u64::from(min);
    min + random_below_u64(rng, width) as u32
}

fn random_below_u64<R: RngCore>(rng: &mut R, upper: u64) -> u64 {
    if upper <= 1 {
        return 0;
    }
    let threshold = upper.wrapping_neg() % upper;
    loop {
        let value = rng.next_u64();
        if value >= threshold {
            return value % upper;
        }
    }
}

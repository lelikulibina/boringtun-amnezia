//! Высокоуровневая обёртка BoringTun с базовым AWG framing.

use super::packet_codec::{AwgPacketCodec, PacketCodecError};
use crate::wireguard::{x25519, Tunn, TunnResult};
use crate::AmneziaConfig;
use boringtun::noise::errors::WireGuardError;
use rand_core::RngCore;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Результат обработки AWG-туннеля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwgTunnelOutput {
    /// Нет действий для сетевого или TUN уровня.
    Done,
    /// Датаграмм, который необходимо отправить в UDP socket.
    WriteToNetwork(Vec<u8>),
    /// Расшифрованный IPv4 пакет, который следует записать в TUN.
    WriteToTunnelV4(Vec<u8>, Ipv4Addr),
    /// Расшифрованный IPv6 пакет, который следует записать в TUN.
    WriteToTunnelV6(Vec<u8>, Ipv6Addr),
}

/// Ошибки AWG tunnel wrapper.
#[derive(Debug)]
pub enum AwgTunnelError {
    /// Ошибка AWG framing/codec.
    Codec(PacketCodecError),
    /// Ошибка криптографического или протокольного движка BoringTun.
    WireGuard(WireGuardError),
}

impl fmt::Display for AwgTunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(f, "ошибка AWG codec: {error}"),
            Self::WireGuard(error) => write!(f, "ошибка BoringTun: {error:?}"),
        }
    }
}

impl std::error::Error for AwgTunnelError {}

impl From<PacketCodecError> for AwgTunnelError {
    fn from(value: PacketCodecError) -> Self {
        Self::Codec(value)
    }
}

/// BoringTun Tunn с внешним AWG packet framing.
///
/// Текущий wrapper поддерживает S1-S4 и header protection при стандартных
/// H1-H4. Все остальные опции конфигурации проверяются codec-конструктором
/// и приводят к ошибке, если ещё не поддерживаются.
pub struct AwgTunnel {
    tunn: Tunn,
    codec: AwgPacketCodec,
}

impl AwgTunnel {
    /// Создаёт туннель для одного WireGuard peer с базовым AWG framing.
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        config: &AmneziaConfig,
    ) -> Result<Self, AwgTunnelError> {
        let codec = AwgPacketCodec::new(config)?;
        let tunn = Tunn::new(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            index,
            None,
        );
        Ok(Self { tunn, codec })
    }

    /// Формирует и кодирует handshake initiation.
    pub fn initiate_handshake<R: RngCore>(
        &mut self,
        dst: &mut [u8],
        force_resend: bool,
        rng: &mut R,
    ) -> Result<AwgTunnelOutput, AwgTunnelError> {
        let result = self.tunn.format_handshake_initiation(dst, force_resend);
        self.map_result(result, rng)
    }

    /// Шифрует внутренний IP-пакет и добавляет AWG framing.
    pub fn encapsulate<R: RngCore>(
        &mut self,
        inner_packet: &[u8],
        dst: &mut [u8],
        rng: &mut R,
    ) -> Result<AwgTunnelOutput, AwgTunnelError> {
        let result = self.tunn.encapsulate(inner_packet, dst);
        self.map_result(result, rng)
    }

    /// Снимает AWG framing и передаёт канонический пакет в BoringTun.
    ///
    /// Пустой datagram передаётся напрямую: BoringTun использует его для
    /// продолжения отправки ранее поставленных в очередь пакетов.
    pub fn decapsulate<R: RngCore>(
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

    fn map_result<R: RngCore>(
        &self,
        result: TunnResult<'_>,
        rng: &mut R,
    ) -> Result<AwgTunnelOutput, AwgTunnelError> {
        match result {
            TunnResult::Done => Ok(AwgTunnelOutput::Done),
            TunnResult::Err(error) => Err(AwgTunnelError::WireGuard(error)),
            TunnResult::WriteToNetwork(packet) => Ok(AwgTunnelOutput::WriteToNetwork(
                self.codec.encode(packet, rng)?,
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

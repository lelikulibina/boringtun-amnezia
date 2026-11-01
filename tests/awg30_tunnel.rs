#![cfg(feature = "amneziawg-3-0")]

use boringtun_amnezia::awg::tunnel::{AwgTunnel, AwgTunnelOutput};
use boringtun_amnezia::wireguard::x25519;
use boringtun_amnezia::{AmneziaConfig, PacketPadding, ProtocolMode, ValueRange};
use rand_core::{CryptoRng, RngCore};

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

fn awg30_config() -> AmneziaConfig {
    let mut config = AmneziaConfig::default();
    config.headers.h1 = Some(ValueRange { min: 100, max: 200 });
    config.headers.h2 = Some(ValueRange { min: 300, max: 400 });
    config.headers.h3 = Some(ValueRange { min: 500, max: 600 });
    config.headers.h4 = Some(ValueRange { min: 700, max: 800 });
    config.headers.header_protection_key = Some([0x66; 32]);
    config.padding = PacketPadding {
        s1: Some(12),
        s2: Some(12),
        s3: Some(12),
        s4: Some(12),
        content_padding: None,
    };
    config
}

fn tunnel_pair(config: &AmneziaConfig) -> (AwgTunnel, AwgTunnel) {
    let a_secret = x25519::StaticSecret::from([0x11; 32]);
    let b_secret = x25519::StaticSecret::from([0x22; 32]);
    let a_public = x25519::PublicKey::from(&a_secret);
    let b_public = x25519::PublicKey::from(&b_secret);

    (
        AwgTunnel::new(
            ProtocolMode::AmneziaWg30,
            a_secret,
            b_public,
            None,
            None,
            1,
            config,
        )
        .unwrap(),
        AwgTunnel::new(
            ProtocolMode::AmneziaWg30,
            b_secret,
            a_public,
            None,
            None,
            2,
            config,
        )
        .unwrap(),
    )
}

fn network_packet(output: AwgTunnelOutput) -> Vec<u8> {
    match output {
        AwgTunnelOutput::WriteToNetwork(packet) => packet,
        other => panic!("ожидался исходящий UDP datagram, получено: {other:?}"),
    }
}

fn network_batch(output: AwgTunnelOutput) -> Vec<Vec<u8>> {
    match output {
        AwgTunnelOutput::WriteToNetworkBatch(packets) => packets,
        AwgTunnelOutput::WriteToNetwork(packet) => vec![packet],
        other => panic!("ожидался исходящий UDP batch, получено: {other:?}"),
    }
}

fn ipv4_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
    packet
}

#[test]
fn awg30_header_protection_and_transport_are_interoperable_between_tunnels() {
    let config = awg30_config();
    let (mut client, mut server) = tunnel_pair(&config);
    let mut rng = FixedRng(0x2d);
    let mut buffer = [0u8; 2048];

    let initiation = network_batch(
        client
            .initiate_handshake(&mut buffer, false, &mut rng)
            .unwrap(),
    )
    .pop()
    .unwrap();
    let response = network_packet(
        server
            .decapsulate(None, &initiation, &mut buffer, &mut rng)
            .unwrap(),
    );
    let keepalive = network_packet(
        client
            .decapsulate(None, &response, &mut buffer, &mut rng)
            .unwrap(),
    );
    assert_eq!(
        server
            .decapsulate(None, &keepalive, &mut buffer, &mut rng)
            .unwrap(),
        AwgTunnelOutput::Done
    );

    let inner = ipv4_packet();
    let encrypted = network_packet(client.encapsulate(&inner, &mut buffer, &mut rng).unwrap());
    match server
        .decapsulate(None, &encrypted, &mut buffer, &mut rng)
        .unwrap()
    {
        AwgTunnelOutput::WriteToTunnelV4(packet, _) => assert_eq!(packet, inner),
        other => panic!("ожидался расшифрованный IPv4 пакет, получено: {other:?}"),
    }
}

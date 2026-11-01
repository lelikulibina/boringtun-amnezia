use boringtun_amnezia::awg::tunnel::{AwgTunnel, AwgTunnelOutput};
use boringtun_amnezia::wireguard::x25519;
use boringtun_amnezia::{
    AmneziaConfig, JunkConfig, PacketPadding, ProtocolMode, SignatureTemplate, ValueRange,
};
use rand_core::{CryptoRng, RngCore};
use std::net::Ipv4Addr;

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

fn awg_config() -> AmneziaConfig {
    let mut config = AmneziaConfig::default();
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
            ProtocolMode::AmneziaWg31,
            a_secret,
            b_public,
            None,
            None,
            1,
            config,
        )
        .unwrap(),
        AwgTunnel::new(
            ProtocolMode::AmneziaWg31,
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

fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet
}

fn establish_pair(
    initiator: &mut AwgTunnel,
    responder: &mut AwgTunnel,
    rng: &mut FixedRng,
    buffer: &mut [u8],
) {
    let initiation_batch = network_batch(initiator.initiate_handshake(buffer, false, rng).unwrap());
    let initiation = initiation_batch.last().expect("handshake datagram exists");
    let response = network_packet(
        responder
            .decapsulate(None, initiation, buffer, rng)
            .unwrap(),
    );
    let keepalive = network_packet(initiator.decapsulate(None, &response, buffer, rng).unwrap());
    assert_eq!(
        responder
            .decapsulate(None, &keepalive, buffer, rng)
            .unwrap(),
        AwgTunnelOutput::Done
    );
}

#[test]
fn undersized_destination_buffers_return_errors_instead_of_panicking() {
    let config = awg_config();
    let (mut tunnel, _peer) = tunnel_pair(&config);
    let mut rng = FixedRng(0x19);
    let mut small = [0u8; 64];

    assert!(matches!(
        tunnel.initiate_handshake(&mut small, false, &mut rng),
        Err(boringtun_amnezia::awg::tunnel::AwgTunnelError::Codec(
            boringtun_amnezia::awg::packet_codec::PacketCodecError::DestinationBufferTooSmall {
                required: 148,
                actual: 64
            }
        ))
    ));

    assert!(matches!(
        tunnel.decapsulate(None, &[], &mut small, &mut rng),
        Err(boringtun_amnezia::awg::tunnel::AwgTunnelError::Codec(
            boringtun_amnezia::awg::packet_codec::PacketCodecError::DestinationBufferTooSmall {
                actual: 64,
                ..
            }
        ))
    ));
}

#[test]
fn awg_framed_handshake_and_transport_work_in_both_directions() {
    let config = awg_config();
    let (mut initiator, mut responder) = tunnel_pair(&config);
    let mut rng = FixedRng(0x5a);
    let mut buffer = [0u8; 2048];
    establish_pair(&mut initiator, &mut responder, &mut rng, &mut buffer);

    let a_to_b = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
    let encrypted = network_packet(
        initiator
            .encapsulate(&a_to_b, &mut buffer, &mut rng)
            .unwrap(),
    );
    assert_eq!(
        responder
            .decapsulate(None, &encrypted, &mut buffer, &mut rng)
            .unwrap(),
        AwgTunnelOutput::WriteToTunnelV4(a_to_b, Ipv4Addr::new(10, 0, 0, 1))
    );

    let b_to_a = ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1]);
    let encrypted = network_packet(
        responder
            .encapsulate(&b_to_a, &mut buffer, &mut rng)
            .unwrap(),
    );
    assert_eq!(
        initiator
            .decapsulate(None, &encrypted, &mut buffer, &mut rng)
            .unwrap(),
        AwgTunnelOutput::WriteToTunnelV4(b_to_a, Ipv4Addr::new(10, 0, 0, 2))
    );
}

#[test]
fn default_awg_transport_padding_aligns_plaintext_to_sixteen_bytes() {
    let config = awg_config();
    let (mut initiator, mut responder) = tunnel_pair(&config);
    let mut rng = FixedRng(0x2a);
    let mut buffer = [0u8; 2048];
    establish_pair(&mut initiator, &mut responder, &mut rng, &mut buffer);

    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
    let encrypted = network_packet(
        initiator
            .encapsulate(&packet, &mut buffer, &mut rng)
            .unwrap(),
    );
    // 12 bytes S4 + 16-byte transport header + 32-byte padded plaintext
    // plus 16-byte Poly1305 tag.
    assert_eq!(encrypted.len(), 76);
    assert_eq!(
        responder
            .decapsulate(None, &encrypted, &mut buffer, &mut rng)
            .unwrap(),
        AwgTunnelOutput::WriteToTunnelV4(packet, Ipv4Addr::new(10, 0, 0, 1))
    );
}

#[test]
fn randomized_h1_h4_with_disable_cookies_preserve_mac1_and_transport() {
    let mut config = awg_config();
    config.disable_cookies = true;
    config.headers.h1 = Some(ValueRange { min: 100, max: 120 });
    config.headers.h2 = Some(ValueRange { min: 200, max: 220 });
    config.headers.h3 = Some(ValueRange { min: 300, max: 320 });
    config.headers.h4 = Some(ValueRange { min: 400, max: 420 });

    let (mut initiator, mut responder) = tunnel_pair(&config);
    let mut rng = FixedRng(0x6d);
    let mut buffer = [0u8; 2048];
    establish_pair(&mut initiator, &mut responder, &mut rng, &mut buffer);

    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
    let encrypted = network_packet(
        initiator
            .encapsulate(&packet, &mut buffer, &mut rng)
            .unwrap(),
    );
    assert_eq!(
        responder
            .decapsulate(None, &encrypted, &mut buffer, &mut rng)
            .unwrap(),
        AwgTunnelOutput::WriteToTunnelV4(packet, Ipv4Addr::new(10, 0, 0, 1))
    );
}

#[test]
fn awg_31_content_padding_addition_round_trip() {
    let mut config = awg_config();
    config.disable_cookies = true;
    config.padding.content_padding = Some(ValueRange { min: 5, max: 9 });
    let (mut initiator, mut responder) = tunnel_pair(&config);
    let mut rng = FixedRng(0x3c);
    let mut buffer = [0u8; 2048];
    establish_pair(&mut initiator, &mut responder, &mut rng, &mut buffer);

    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
    let encrypted = network_packet(
        initiator
            .encapsulate(&packet, &mut buffer, &mut rng)
            .unwrap(),
    );
    assert_eq!(
        responder
            .decapsulate(None, &encrypted, &mut buffer, &mut rng)
            .unwrap(),
        AwgTunnelOutput::WriteToTunnelV4(packet, Ipv4Addr::new(10, 0, 0, 1))
    );
}

#[test]
fn awg_31_random_trailers_pad_transport_plaintext_before_encryption() {
    let mut config = awg_config();
    config.random_trailers = true;
    config.disable_cookies = true;
    let (mut initiator, mut responder) = tunnel_pair(&config);
    let mut rng = FixedRng(0x17);
    let mut buffer = [0u8; 2048];
    establish_pair(&mut initiator, &mut responder, &mut rng, &mut buffer);

    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
    let encrypted = network_packet(
        initiator
            .encapsulate(&packet, &mut buffer, &mut rng)
            .unwrap(),
    );
    assert!(encrypted.len() > 64);
    assert!(encrypted.len() <= 500);
    assert_eq!(
        responder
            .decapsulate(None, &encrypted, &mut buffer, &mut rng)
            .unwrap(),
        AwgTunnelOutput::WriteToTunnelV4(packet, Ipv4Addr::new(10, 0, 0, 1))
    );
}

#[test]
fn initiation_sends_signature_packets_then_junk_then_handshake() {
    let mut config = awg_config();
    config.signature_packets[0] = Some(SignatureTemplate::parse("<b 0xdeadbeef>").unwrap());
    config.junk = JunkConfig {
        count: 2,
        min_size: 8,
        max_size: 9,
    };
    let (mut initiator, _responder) = tunnel_pair(&config);
    let mut rng = FixedRng(0x4d);
    let mut buffer = [0u8; 2048];

    let batch = network_batch(
        initiator
            .initiate_handshake(&mut buffer, false, &mut rng)
            .unwrap(),
    );
    assert_eq!(batch.len(), 4);
    assert_eq!(batch[0], [0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(batch[1].len(), 8);
    assert_eq!(batch[2].len(), 8);
    assert!(batch[3].len() >= 148 + 12);
}

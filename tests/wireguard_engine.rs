#![cfg(feature = "wireguard")]

use boringtun_amnezia::wireguard::{x25519, Tunn, TunnResult};

fn tunnel_pair() -> (Tunn, Tunn) {
    let a_secret = x25519::StaticSecret::from([0x11; 32]);
    let b_secret = x25519::StaticSecret::from([0x22; 32]);
    let a_public = x25519::PublicKey::from(&a_secret);
    let b_public = x25519::PublicKey::from(&b_secret);

    (
        Tunn::new(a_secret, b_public, None, None, 1, None),
        Tunn::new(b_secret, a_public, None, None, 2, None),
    )
}

fn network_packet(result: TunnResult<'_>) -> Vec<u8> {
    match result {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("ожидался исходящий UDP-пакет, получено: {other:?}"),
    }
}

fn minimal_ipv4_packet() -> Vec<u8> {
    // Минимальный IPv4 header: version/IHL=4/5, total length=20,
    // TTL=64, protocol=UDP. Checksum не проверяется этим тестовым путём.
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
fn boringtun_completes_wireguard_handshake() {
    let (mut initiator, mut responder) = tunnel_pair();

    let initiation = {
        let mut buffer = [0u8; 2048];
        network_packet(initiator.format_handshake_initiation(&mut buffer, false))
    };

    let response = {
        let mut buffer = [0u8; 2048];
        network_packet(responder.decapsulate(None, &initiation, &mut buffer))
    };

    let keepalive = {
        let mut buffer = [0u8; 2048];
        network_packet(initiator.decapsulate(None, &response, &mut buffer))
    };

    let mut buffer = [0u8; 2048];
    assert!(matches!(
        responder.decapsulate(None, &keepalive, &mut buffer),
        TunnResult::Done
    ));
}

#[test]
fn boringtun_encrypts_and_decrypts_ipv4_transport_packet() {
    let (mut initiator, mut responder) = tunnel_pair();

    let initiation = {
        let mut buffer = [0u8; 2048];
        network_packet(initiator.format_handshake_initiation(&mut buffer, false))
    };
    let response = {
        let mut buffer = [0u8; 2048];
        network_packet(responder.decapsulate(None, &initiation, &mut buffer))
    };
    let keepalive = {
        let mut buffer = [0u8; 2048];
        network_packet(initiator.decapsulate(None, &response, &mut buffer))
    };
    let mut buffer = [0u8; 2048];
    assert!(matches!(
        responder.decapsulate(None, &keepalive, &mut buffer),
        TunnResult::Done
    ));

    let plaintext = minimal_ipv4_packet();
    let encrypted = {
        let mut buffer = [0u8; 2048];
        network_packet(initiator.encapsulate(&plaintext, &mut buffer))
    };

    let mut decrypted = [0u8; 2048];
    match responder.decapsulate(None, &encrypted, &mut decrypted) {
        TunnResult::WriteToTunnelV4(packet, source) => {
            assert_eq!(source, std::net::Ipv4Addr::new(10, 0, 0, 1));
            assert_eq!(&packet[..], plaintext.as_slice());
        }
        other => panic!("ожидался расшифрованный IPv4 пакет, получено: {other:?}"),
    }
}

#[test]
fn malformed_wireguard_datagrams_are_rejected() {
    for packet in [&[][..], &[1, 0, 0][..], &[9, 0, 0, 0][..]] {
        assert!(Tunn::parse_incoming_packet(packet).is_err());
    }
}

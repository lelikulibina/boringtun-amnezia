#![cfg(feature = "amneziawg-3-1")]

use boringtun_amnezia::awg::tunnel::{AwgTunnel, AwgTunnelOutput};
use boringtun_amnezia::wireguard::{x25519, Tunn, TunnResult};
use boringtun_amnezia::{
    AmneziaConfig, HeaderObfuscation, PacketPadding, ProtocolMode, ValueRange,
};
use rand_core::{CryptoRng, RngCore};
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

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

struct GoPeer {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    address: SocketAddr,
}

impl Drop for GoPeer {
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"QUIT\n");
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl GoPeer {
    fn spawn(
        mode: &str,
        private_key: &[u8; 32],
        peer_public_key: &[u8; 32],
        endpoint: SocketAddr,
    ) -> Self {
        Self::spawn_with_env(
            "AWG_GO_HELPER",
            mode,
            private_key,
            peer_public_key,
            endpoint,
        )
    }

    fn spawn_with_env(
        helper_env: &str,
        mode: &str,
        private_key: &[u8; 32],
        peer_public_key: &[u8; 32],
        endpoint: SocketAddr,
    ) -> Self {
        let helper = std::env::var(helper_env)
            .unwrap_or_else(|_| panic!("{helper_env} must point to the pinned Go peer helper"));
        let mut child = Command::new(helper)
            .args([
                "--mode",
                mode,
                "--private-key",
                &encode_hex(private_key),
                "--peer-public-key",
                &encode_hex(peer_public_key),
                "--endpoint",
                &endpoint.to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start AmneziaWG Go helper");

        let stdin = child.stdin.take().expect("Go helper stdin");
        let stdout = child.stdout.take().expect("Go helper stdout");
        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if sender.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let first_line = lines
            .recv_timeout(Duration::from_secs(15))
            .expect("Go helper did not report its UDP port");
        let port: u16 = first_line
            .strip_prefix("PORT=")
            .expect("Go helper PORT line")
            .parse()
            .expect("valid Go helper UDP port");
        let underload_line = lines
            .recv_timeout(Duration::from_secs(5))
            .expect("Go helper did not activate under-load test mode");
        let expected_ready_line = if mode == "wg-client" || mode == "wireguard-go" {
            "READY=1"
        } else {
            "UNDERLOAD=1"
        };
        assert_eq!(underload_line, expected_ready_line);

        Self {
            child,
            stdin,
            lines,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        }
    }

    fn send_tun_packet(&mut self, packet: &[u8]) {
        writeln!(self.stdin, "SEND:{}", encode_hex(packet)).expect("send packet to Go TUN");
        self.stdin.flush().expect("flush Go helper stdin");
    }

    fn flood_rust_mac1(&mut self) {
        self.stdin
            .write_all(b"FLOOD\n")
            .expect("request Rust MAC1 flood");
        self.stdin.flush().expect("flush Rust MAC1 flood command");
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(5))
            .expect("timed out waiting for MAC1 flood completion");
        assert_eq!(line, "FLOOD_SENT=10");
    }

    fn rotate_cookie_secret(&mut self) {
        self.stdin
            .write_all(b"ROTATE_COOKIE\n")
            .expect("request Go cookie secret rotation");
        self.stdin.flush().expect("flush cookie rotation command");
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(5))
            .expect("timed out waiting for Go cookie secret rotation");
        assert_eq!(line, "COOKIE_ROTATED=1");
    }

    fn receive_tun_packet(&self) -> Vec<u8> {
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(10))
            .expect("timed out waiting for packet written to Go TUN");
        let packet = line
            .strip_prefix("TUN:")
            .unwrap_or_else(|| panic!("unexpected output from Go helper: {line}"));
        decode_hex(packet)
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex input has even length");
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let digit = |value: u8| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                b'A'..=b'F' => value - b'A' + 10,
                _ => panic!("invalid hex digit"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn ipv4_packet(source_last_octet: u8, destination_last_octet: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 0, 0, source_last_octet]);
    packet[16..20].copy_from_slice(&[10, 0, 0, destination_last_octet]);
    packet[20..28].copy_from_slice(b"awg-test");
    packet
}

fn send_awg_output(socket: &UdpSocket, peer: SocketAddr, output: AwgTunnelOutput) {
    match output {
        AwgTunnelOutput::WriteToNetwork(packet) => {
            socket.send_to(&packet, peer).expect("send AWG UDP packet");
        }
        AwgTunnelOutput::WriteToNetworkBatch(packets) => {
            for packet in packets {
                socket
                    .send_to(&packet, peer)
                    .expect("send AWG UDP batch packet");
            }
        }
        AwgTunnelOutput::Done => {}
        other => panic!("unexpected AWG tunnel output: {other:?}"),
    }
}

fn send_wireguard_output(socket: &UdpSocket, peer: SocketAddr, output: TunnResult<'_>) {
    match output {
        TunnResult::WriteToNetwork(packet) => {
            socket
                .send_to(packet, peer)
                .expect("send WireGuard UDP packet");
        }
        TunnResult::Done => {}
        other => panic!("unexpected WireGuard tunnel output: {other:?}"),
    }
}

fn receive_udp(socket: &UdpSocket, buffer: &mut [u8]) -> Vec<u8> {
    let (length, _) = socket.recv_from(buffer).expect("receive UDP datagram");
    buffer[..length].to_vec()
}

fn receive_awg_ipv4(
    socket: &UdpSocket,
    peer: SocketAddr,
    tunnel: &mut AwgTunnel,
    rng: &mut FixedRng,
) -> Vec<u8> {
    let mut udp_buffer = [0u8; 2048];
    let mut tunnel_buffer = [0u8; 2048];
    loop {
        let datagram = receive_udp(socket, &mut udp_buffer);
        match tunnel
            .decapsulate(Some(peer.ip()), &datagram, &mut tunnel_buffer, rng)
            .expect("decode Go AWG packet")
        {
            AwgTunnelOutput::WriteToTunnelV4(packet, _) => return packet,
            AwgTunnelOutput::WriteToNetwork(packet) => {
                socket.send_to(&packet, peer).expect("send AWG response");
            }
            AwgTunnelOutput::WriteToNetworkBatch(packets) => {
                for packet in packets {
                    socket
                        .send_to(&packet, peer)
                        .expect("send AWG response batch");
                }
            }
            AwgTunnelOutput::Done => {}
            other => panic!("unexpected output while receiving AWG IPv4: {other:?}"),
        }
    }
}

fn receive_wireguard_ipv4(socket: &UdpSocket, peer: SocketAddr, tunnel: &mut Tunn) -> Vec<u8> {
    let mut udp_buffer = [0u8; 2048];
    let mut tunnel_buffer = [0u8; 2048];
    loop {
        let datagram = receive_udp(socket, &mut udp_buffer);
        match tunnel.decapsulate(Some(peer.ip()), &datagram, &mut tunnel_buffer) {
            TunnResult::WriteToTunnelV4(packet, _) => return packet.to_vec(),
            TunnResult::WriteToNetwork(packet) => {
                socket
                    .send_to(packet, peer)
                    .expect("send WireGuard response");
            }
            TunnResult::Done => {}
            other => panic!("unexpected output while receiving WireGuard IPv4: {other:?}"),
        }
    }
}

fn awg_config(is_31: bool) -> AmneziaConfig {
    AmneziaConfig {
        headers: HeaderObfuscation {
            h1: Some(ValueRange { min: 100, max: 200 }),
            h2: Some(ValueRange { min: 300, max: 400 }),
            h3: Some(ValueRange { min: 500, max: 600 }),
            h4: Some(ValueRange { min: 700, max: 800 }),
            header_protection_key: Some([0x66; 32]),
        },
        padding: PacketPadding {
            s1: Some(12),
            s2: Some(12),
            s3: Some(12),
            s4: Some(12),
            content_padding: is_31.then_some(ValueRange { min: 1, max: 4 }),
        },
        random_trailers: is_31,
        ..AmneziaConfig::default()
    }
}

fn run_upstream_wireguard_interop() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind Rust UDP socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let local = socket.local_addr().unwrap();
    let rust_secret_bytes = [0x51; 32];
    let go_secret_bytes = [0x61; 32];
    let rust_secret = x25519::StaticSecret::from(rust_secret_bytes);
    let go_secret = x25519::StaticSecret::from(go_secret_bytes);
    let rust_public = x25519::PublicKey::from(&rust_secret);
    let go_public = x25519::PublicKey::from(&go_secret);
    let mut peer = GoPeer::spawn_with_env(
        "WIREGUARD_GO_HELPER",
        "wireguard-go",
        &go_secret_bytes,
        rust_public.as_bytes(),
        local,
    );
    let mut tunnel = Tunn::new(rust_secret, go_public, None, None, 1, None);
    let mut buffer = [0u8; 2048];
    let mut udp_buffer = [0u8; 2048];

    let initiation = match tunnel.format_handshake_initiation(&mut buffer, true) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("expected upstream WireGuard initiation, got {other:?}"),
    };
    socket.send_to(&initiation, peer.address).unwrap();

    let response = receive_udp(&socket, &mut udp_buffer);
    assert_eq!(
        u32::from_le_bytes(response[..4].try_into().unwrap()),
        2,
        "upstream wireguard-go should respond without a forced cookie challenge"
    );
    let output = tunnel.decapsulate(Some(peer.address.ip()), &response, &mut buffer);
    send_wireguard_output(&socket, peer.address, output);

    let rust_packet = ipv4_packet(1, 2);
    let encrypted = match tunnel.encapsulate(&rust_packet, &mut buffer) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("expected encrypted Rust IPv4 packet, got {other:?}"),
    };
    socket.send_to(&encrypted, peer.address).unwrap();
    assert_eq!(peer.receive_tun_packet(), rust_packet);

    let go_packet = ipv4_packet(2, 1);
    peer.send_tun_packet(&go_packet);
    let mut received_go_packet = false;
    for _ in 0..5 {
        let datagram = receive_udp(&socket, &mut udp_buffer);
        match tunnel.decapsulate(Some(peer.address.ip()), &datagram, &mut buffer) {
            TunnResult::WriteToTunnelV4(packet, _) => {
                assert_eq!(packet, go_packet);
                received_go_packet = true;
                break;
            }
            TunnResult::WriteToNetwork(packet) => {
                socket
                    .send_to(packet, peer.address)
                    .expect("send upstream WireGuard response");
            }
            TunnResult::Done => {}
            other => panic!("unexpected upstream WireGuard output: {other:?}"),
        }
    }
    assert!(
        received_go_packet,
        "Rust did not receive IPv4 transport from upstream wireguard-go"
    );
}

fn send_rust_server_network_packet(
    socket: &UdpSocket,
    peer_address: SocketAddr,
    packet: Vec<u8>,
    disable_cookies: bool,
    cookie_challenge_received: &mut bool,
    handshake_response_sent: &mut bool,
) {
    assert!(packet.len() >= 4, "Rust server emitted a truncated packet");
    let message_type = u32::from_le_bytes(packet[..4].try_into().unwrap());
    match message_type {
        2 => {
            assert_eq!(
                *cookie_challenge_received, !disable_cookies,
                "Rust server handshake response did not match DisableCookies behavior"
            );
            *handshake_response_sent = true;
        }
        3 => {
            assert!(
                !disable_cookies,
                "Rust server emitted Cookie Reply despite DisableCookies=true"
            );
            *cookie_challenge_received = true;
        }
        _ => {}
    }
    socket
        .send_to(&packet, peer_address)
        .expect("send Rust server response to Go peer");
}

fn run_rust_server_cookie_interop(disable_cookies: bool) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind Rust AWG server UDP socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let local = socket.local_addr().unwrap();
    let rust_secret_bytes = [0x33; 32];
    let go_secret_bytes = [0x44; 32];
    let rust_secret = x25519::StaticSecret::from(rust_secret_bytes);
    let go_secret = x25519::StaticSecret::from(go_secret_bytes);
    let rust_public = x25519::PublicKey::from(&rust_secret);
    let go_public = x25519::PublicKey::from(&go_secret);
    let mut peer = GoPeer::spawn("wg-client", &go_secret_bytes, rust_public.as_bytes(), local);

    let config = AmneziaConfig {
        disable_cookies,
        ..AmneziaConfig::default()
    };
    let mut tunnel = AwgTunnel::new(
        ProtocolMode::AmneziaWg31,
        rust_secret,
        go_public,
        None,
        None,
        1,
        &config,
    )
    .expect("create Rust AWG server tunnel");

    // Ten valid-MAC1 but invalid-Noise messages consume the default BoringTun
    // handshake budget. The eleventh real initiation must receive Cookie Reply
    // unless DisableCookies selected the unbounded rate limiter.
    peer.flood_rust_mac1();
    let mut udp_buffer = [0u8; 2048];
    let mut buffer = [0u8; 2048];
    let mut rng = FixedRng(0x72);
    for _ in 0..10 {
        let probe = receive_udp(&socket, &mut udp_buffer);
        match tunnel.decapsulate(Some(peer.address.ip()), &probe, &mut buffer, &mut rng) {
            Ok(AwgTunnelOutput::Done)
            | Err(boringtun_amnezia::awg::tunnel::AwgTunnelError::WireGuard(_)) => {}
            Ok(AwgTunnelOutput::WriteToNetwork(_))
            | Ok(AwgTunnelOutput::WriteToNetworkBatch(_)) => {
                // A probe may itself be the threshold-crossing packet. Its
                // Cookie Reply is addressed to the temporary flood socket.
            }
            Ok(other) => panic!("unexpected output for invalid MAC1 probe: {other:?}"),
            Err(other) => panic!("invalid AWG framing for valid-MAC1 probe: {other:?}"),
        }
    }

    let go_packet = ipv4_packet(2, 1);
    peer.send_tun_packet(&go_packet);
    let mut cookie_challenge_received = false;
    let mut handshake_response_sent = false;
    let mut go_packet_received = false;

    for _ in 0..8 {
        let datagram = receive_udp(&socket, &mut udp_buffer);
        let output = tunnel
            .decapsulate(Some(peer.address.ip()), &datagram, &mut buffer, &mut rng)
            .unwrap_or_else(|error| panic!("Rust AWG server rejected Go initiation: {error:?}"));
        match output {
            AwgTunnelOutput::WriteToNetwork(packet) => send_rust_server_network_packet(
                &socket,
                peer.address,
                packet,
                disable_cookies,
                &mut cookie_challenge_received,
                &mut handshake_response_sent,
            ),
            AwgTunnelOutput::WriteToNetworkBatch(packets) => {
                for packet in packets {
                    send_rust_server_network_packet(
                        &socket,
                        peer.address,
                        packet,
                        disable_cookies,
                        &mut cookie_challenge_received,
                        &mut handshake_response_sent,
                    );
                }
            }
            AwgTunnelOutput::WriteToTunnelV4(packet, _) => {
                assert_eq!(packet, go_packet);
                go_packet_received = true;
                break;
            }
            AwgTunnelOutput::WriteToTunnelV6(_, _) => {
                panic!("unexpected IPv6 packet in Rust server interoperability test")
            }
            AwgTunnelOutput::Done => {}
        }
    }

    assert_eq!(
        cookie_challenge_received, !disable_cookies,
        "Rust server Cookie Reply behavior did not match DisableCookies"
    );
    assert!(
        handshake_response_sent,
        "Rust server did not complete Go handshake"
    );
    assert!(
        go_packet_received,
        "Rust server did not receive Go IPv4 transport"
    );

    let rust_packet = ipv4_packet(1, 2);
    let encrypted = tunnel
        .encapsulate(&rust_packet, &mut buffer, &mut rng)
        .expect("encrypt Rust server IPv4 packet");
    send_awg_output(&socket, peer.address, encrypted);
    assert_eq!(peer.receive_tun_packet(), rust_packet);
}

fn run_wireguard_interop() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind Rust UDP socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let local = socket.local_addr().unwrap();
    let rust_secret_bytes = [0x11; 32];
    let go_secret_bytes = [0x22; 32];
    let rust_secret = x25519::StaticSecret::from(rust_secret_bytes);
    let go_secret = x25519::StaticSecret::from(go_secret_bytes);
    let rust_public = x25519::PublicKey::from(&rust_secret);
    let go_public = x25519::PublicKey::from(&go_secret);
    let mut peer = GoPeer::spawn("wireguard", &go_secret_bytes, rust_public.as_bytes(), local);
    let mut tunnel = Tunn::new(rust_secret, go_public, None, None, 1, None);

    let mut buffer = [0u8; 2048];
    let mut initiation = match tunnel.format_handshake_initiation(&mut buffer, true) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("expected WireGuard initiation, got {other:?}"),
    };
    let mut udp_buffer = [0u8; 2048];
    let mut established = false;
    let mut cookie_challenge_received = false;

    for _ in 0..3 {
        socket.send_to(&initiation, peer.address).unwrap();
        let response = receive_udp(&socket, &mut udp_buffer);
        let message_type = u32::from_le_bytes(response[..4].try_into().unwrap());
        let result = tunnel.decapsulate(Some(peer.address.ip()), &response, &mut buffer);

        match message_type {
            3 => {
                cookie_challenge_received = true;
                assert!(matches!(result, TunnResult::Done));
                initiation = match tunnel.format_handshake_initiation(&mut buffer, true) {
                    TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                    other => panic!("expected WireGuard cookie retry, got {other:?}"),
                };
            }
            2 => {
                assert!(
                    cookie_challenge_received,
                    "Go peer skipped the expected MAC2 cookie challenge"
                );
                send_wireguard_output(&socket, peer.address, result);
                established = true;
                break;
            }
            other => panic!("unexpected WireGuard handshake response type: {other}"),
        }
    }
    assert!(
        cookie_challenge_received,
        "Go peer did not issue a MAC2 cookie challenge"
    );
    assert!(
        established,
        "WireGuard handshake did not complete after MAC2 retry"
    );

    let rust_packet = ipv4_packet(1, 2);
    let encrypted = match tunnel.encapsulate(&rust_packet, &mut buffer) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("expected encrypted WireGuard transport, got {other:?}"),
    };
    socket.send_to(&encrypted, peer.address).unwrap();
    assert_eq!(peer.receive_tun_packet(), rust_packet);

    let go_packet = ipv4_packet(2, 1);
    peer.send_tun_packet(&go_packet);
    assert_eq!(
        receive_wireguard_ipv4(&socket, peer.address, &mut tunnel),
        go_packet
    );
}

fn run_awg_interop(
    mode: ProtocolMode,
    go_mode: &str,
    is_31: bool,
    disable_cookies: bool,
    rotate_cookie: bool,
) {
    eprintln!("Starting Go interoperability scenario: {go_mode}");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind Rust UDP socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let local = socket.local_addr().unwrap();
    let rust_secret_bytes = [0x11; 32];
    let go_secret_bytes = [0x22; 32];
    let rust_secret = x25519::StaticSecret::from(rust_secret_bytes);
    let go_secret = x25519::StaticSecret::from(go_secret_bytes);
    let rust_public = x25519::PublicKey::from(&rust_secret);
    let go_public = x25519::PublicKey::from(&go_secret);
    let mut peer = GoPeer::spawn(go_mode, &go_secret_bytes, rust_public.as_bytes(), local);
    let mut config = awg_config(is_31);
    config.disable_cookies = disable_cookies;
    let mut tunnel = AwgTunnel::new(mode, rust_secret, go_public, None, None, 1, &config)
        .expect("create Rust AWG tunnel");

    let mut rng = FixedRng(0x51);
    let mut buffer = [0u8; 2048];
    let mut initiation = tunnel
        .initiate_handshake(&mut buffer, true, &mut rng)
        .expect("format Rust AWG initiation");
    let mut udp_buffer = [0u8; 2048];
    let mut established = false;
    let mut cookie_challenge_received = false;
    let mut cookie_challenge_count = 0usize;
    let mut cookie_rotation_triggered = false;

    for _ in 0..3 {
        send_awg_output(&socket, peer.address, initiation);
        let response = receive_udp(&socket, &mut udp_buffer);
        let output = tunnel
            .decapsulate(Some(peer.address.ip()), &response, &mut buffer, &mut rng)
            .unwrap_or_else(|error| {
                let prefix = encode_hex(&response[..response.len().min(16)]);
                panic!(
                    "decode Go {go_mode} response failed ({} bytes, prefix {prefix}): {error:?}",
                    response.len()
                )
            });

        match output {
            AwgTunnelOutput::Done => {
                assert!(
                    !disable_cookies,
                    "Go peer sent Cookie Reply despite DisableCookies=true"
                );
                cookie_challenge_received = true;
                cookie_challenge_count += 1;
                if rotate_cookie && !cookie_rotation_triggered {
                    peer.rotate_cookie_secret();
                    cookie_rotation_triggered = true;
                }
                initiation = tunnel
                    .initiate_handshake(&mut buffer, true, &mut rng)
                    .expect("format AWG MAC2 cookie retry");
            }
            other => {
                assert_eq!(
                    cookie_challenge_received, !disable_cookies,
                    "Go AWG peer cookie challenge behavior did not match DisableCookies"
                );
                send_awg_output(&socket, peer.address, other);
                established = true;
                break;
            }
        }
    }
    assert_eq!(
        cookie_challenge_received, !disable_cookies,
        "Go AWG peer cookie challenge behavior did not match DisableCookies"
    );
    assert_eq!(
        cookie_challenge_count,
        if disable_cookies {
            0
        } else if rotate_cookie {
            2
        } else {
            1
        },
        "Go AWG peer cookie challenge count did not match rotation scenario"
    );
    assert_eq!(cookie_rotation_triggered, rotate_cookie);
    assert!(
        established,
        "AWG handshake did not complete after MAC2 retry"
    );

    let rust_packet = ipv4_packet(1, 2);
    let encrypted = tunnel
        .encapsulate(&rust_packet, &mut buffer, &mut rng)
        .expect("encrypt Rust AWG transport packet");
    send_awg_output(&socket, peer.address, encrypted);
    assert_eq!(peer.receive_tun_packet(), rust_packet);

    let go_packet = ipv4_packet(2, 1);
    peer.send_tun_packet(&go_packet);
    assert_eq!(
        receive_awg_ipv4(&socket, peer.address, &mut tunnel, &mut rng),
        go_packet
    );
}

#[test]
#[ignore = "requires the pinned amneziawg-go helper built by the go-interop CI job"]
fn interoperates_with_pinned_wireguard_and_amneziawg_go_in_both_directions() {
    run_wireguard_interop();
    run_upstream_wireguard_interop();
    run_awg_interop(ProtocolMode::AmneziaWg30, "awg30", false, false, false);
    run_awg_interop(ProtocolMode::AmneziaWg31, "awg31", true, false, false);
    run_awg_interop(
        ProtocolMode::AmneziaWg31,
        "awg31-nocookies",
        true,
        true,
        false,
    );
    run_awg_interop(
        ProtocolMode::AmneziaWg31,
        "awg31-rotate-cookie",
        true,
        false,
        true,
    );
    run_rust_server_cookie_interop(false);
    run_rust_server_cookie_interop(true);
}

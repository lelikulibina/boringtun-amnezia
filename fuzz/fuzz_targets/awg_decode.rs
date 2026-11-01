#![no_main]

use boringtun_amnezia::awg::packet_codec::AwgPacketCodec;
use boringtun_amnezia::{AmneziaConfig, PacketPadding, ValueRange};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|datagram: &[u8]| {
    let mut config = AmneziaConfig::default();
    config.headers.h1 = Some(ValueRange { min: 100, max: 200 });
    config.headers.h2 = Some(ValueRange { min: 300, max: 400 });
    config.headers.h3 = Some(ValueRange { min: 500, max: 600 });
    config.headers.h4 = Some(ValueRange { min: 700, max: 800 });
    config.headers.header_protection_key = Some([0x42; 32]);
    config.padding = PacketPadding {
        s1: Some(12),
        s2: Some(12),
        s3: Some(12),
        s4: Some(12),
        content_padding: None,
    };
    config.random_trailers = true;

    // Keys are deterministic fuzz fixtures, not production secrets.
    let mut codec = AwgPacketCodec::new_with_keys(&config, &[0x11; 32], &[0x22; 32])
        .expect("static fuzz configuration must be valid");
    let _ = codec.decode(datagram);
});

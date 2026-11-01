# BoringTun Amnezia

Rust-проект для поддержки стандартного WireGuard и AmneziaWG 3.0/3.1.

## Текущий статус

- **WireGuard:** подключён Cloudflare BoringTun 0.7.1 через точную версию Cargo dependency. Публичный API доступен через `wireguard::Tunn`; есть integration tests handshake и зашифрованного обмена IPv4-пакетами.
- **AWG framing:** реализованы S1-S4 padding и ChaCha20 header protection. Для transport защищаются только 16 байт заголовка; ciphertext не изменяется.
- **AWG tunnel wrapper:** добавлена обёртка BoringTun с двусторонним handshake/transport, I1-I5/Junk preambles и MTU-aware content padding.
- **AWG 3.1:** реализованы RandomTrailers, ContentPaddingAddition и DisableCookies. Для handshake/cookie trailer добавляется во внешний датаграмм; для transport нулевые байты добавляются в plaintext до AEAD и обрезаются по длине внутреннего IP-пакета.
- **Стандартное AWG padding:** при выключенных ContentPaddingAddition/RandomTrailers transport plaintext дополняется до кратности 16 с учётом MTU. MTU по умолчанию 1420; его можно изменить через `AwgTunnel::set_mtu`.
- **Защитная валидация:** ограничены размер CPS-тегов и количество/размер junk-пакетов; некорректные диапазоны отклоняются до отправки.
- **Ограничения:** произвольные H1-H4 и кастомные таймеры пока не реализованы. Внутренние keepalive-пакеты BoringTun пока не получают transport padding addition.
- **Буферы:** `AwgTunnel::required_receive_buffer_size` сообщает минимальный размер receive buffer; для входящего datagram буфер должен быть не меньше и его длины. При смене endpoint вызовите `reset_udp_window`.
- **Сетевой/TUN стек:** не входит в библиотечную обёртку.

Полная совместимость с amneziawg-go 3.0/3.1 ещё не заявляется: требуются differential и двусторонние interoperability-тесты.

## Сборка и тесты

    cargo fmt --all -- --check
    cargo test --workspace --all-features
    cargo clippy --workspace --all-targets --all-features -- -D warnings

## Upstream

- Cloudflare BoringTun: https://github.com/cloudflare/boringtun
- AmneziaWG Go: https://github.com/amnezia-vpn/amneziawg-go
- WireGuard Go: https://github.com/WireGuard/wireguard-go

Аудит и план: docs/UPSTREAM.md и docs/IMPLEMENTATION_PLAN.md.

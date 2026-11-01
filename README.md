# BoringTun Amnezia

Rust-проект для поддержки стандартного WireGuard и AmneziaWG 3.0/3.1.

## Текущий статус

- **WireGuard:** подключён Cloudflare BoringTun 0.7.1 через точную версию Cargo dependency. Публичный API доступен через `wireguard::Tunn`; есть integration tests handshake и зашифрованного обмена IPv4-пакетами.
- **AWG framing:** реализованы S1-S4 padding и ChaCha20 header protection. Для transport защищаются только 16 байт заголовка; ciphertext не изменяется.
- **AWG tunnel wrapper:** добавлена обёртка BoringTun с двусторонним handshake/transport.
- **AWG 3.1:** реализованы RandomTrailers, ContentPaddingAddition и DisableCookies; для transport дополнительные нулевые байты добавляются до шифрования, для handshake/cookie trailer обрабатывается внешним codec.
- **I1-I5 и junk:** CPS-шаблоны отправляются перед junk-пакетами и handshake в правильном порядке.
- **Защитная валидация:** ограничены размер CPS-тегов и количество/размер junk-пакетов; некорректные диапазоны отклоняются до отправки.
- **Ограничения:** произвольные H1-H4, кастомные таймеры и полный cookie/MAC interoperability с любыми конфигурациями пока не реализованы. Внутренние keepalive-пакеты BoringTun пока не получают transport padding addition.
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

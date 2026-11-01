# BoringTun Amnezia

Rust-проект для поддержки стандартного WireGuard и AmneziaWG 3.0/3.1.

## Текущий статус

- **WireGuard:** подключён Cloudflare BoringTun 0.7.1 через точную версию Cargo dependency. Публичный API движка доступен через `wireguard::Tunn`; добавлены интеграционные тесты handshake и зашифрованного обмена IPv4-пакетами.
- **AWG framing:** реализован packet codec для S1-S4 padding и ChaCha20 header protection. Для transport защищаются только 16 байт заголовка; ciphertext не изменяется.
- **AWG tunnel wrapper:** добавлена обёртка над BoringTun, которая кодирует исходящие и декодирует входящие пакеты. Есть интеграционный тест двустороннего handshake и IPv4 transport через AWG framing.
- **I1-I5:** добавлен CPS-парсер/рендерер шаблонов.
- **Ограничения:** случайные H1-H4, junk/signature отправка, content padding, RandomTrailers, DisableCookies и кастомные таймеры пока не подключены. Кодек явно отклоняет эти параметры, а не игнорирует их.
- **Сетевой/TUN стек:** не входит в текущую библиотечную обёртку.

Не используйте AWG-режимы в production до завершения дифференциальных тестов с amneziawg-go и полной проверки совместимости.

## Сборка и тесты

    cargo fmt --all -- --check
    cargo test --workspace --all-features
    cargo clippy --workspace --all-targets --all-features -- -D warnings

## Upstream

- Cloudflare BoringTun: https://github.com/cloudflare/boringtun
- AmneziaWG Go: https://github.com/amnezia-vpn/amneziawg-go
- WireGuard Go: https://github.com/WireGuard/wireguard-go

Аудит и план: docs/UPSTREAM.md и docs/IMPLEMENTATION_PLAN.md.

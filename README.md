# BoringTun Amnezia

Rust-проект для поддержки стандартного WireGuard и AmneziaWG 3.0/3.1.

## Текущий статус

- **WireGuard:** подключён опубликованный Cloudflare BoringTun 0.7.1 через точную версию зависимости Cargo. Публичный API движка доступен через `wireguard::Tunn`; добавлены интеграционные тесты handshake и зашифрованного обмена IPv4-пакетами.
- **AmneziaWG 3.0/3.1:** собственная обработка пакетов ещё не реализована. Есть конфигурационные типы и проверки части параметров, включая требования Header Protection и ограничения флагов AWG 3.1.
- **Сетевой/TUN стек:** не входит в текущую библиотечную обёртку.

Не используйте AWG-режимы в production до завершения двусторонних interoperability-тестов.

## Сборка и тесты

    cargo fmt --all -- --check
    cargo test --workspace --all-features
    cargo clippy --workspace --all-targets --all-features -- -D warnings

## Upstream

- Cloudflare BoringTun: https://github.com/cloudflare/boringtun
- AmneziaWG Go: https://github.com/amnezia-vpn/amneziawg-go
- WireGuard Go: https://github.com/WireGuard/wireguard-go

Аудит и план: docs/UPSTREAM.md и docs/IMPLEMENTATION_PLAN.md.

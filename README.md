# BoringTun Amnezia

Rust-проект для поддержки стандартного WireGuard и AmneziaWG 3.0/3.1.

## Текущий статус

- **WireGuard:** протокольный движок предоставляется Cloudflare BoringTun 0.7.1 через закреплённую зависимость Cargo. Добавлен публичный re-export API и интеграционный тест полного handshake/обмена пакетом.
- **AmneziaWG 3.0/3.1:** пока не реализованы. Конфигурационные типы являются только начальным API; они не преобразуют сетевые пакеты.
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

# BoringTun Amnezia

Rust-проект для поддержки стандартного WireGuard и AmneziaWG 3.0/3.1.

## Текущий статус

- **WireGuard:** подключён опубликованный Cloudflare BoringTun 0.7.1 через точную версию зависимости Cargo. Публичный API движка доступен через `wireguard::Tunn`; добавлены интеграционные тесты handshake и зашифрованного обмена IPv4-пакетами.
- **AmneziaWG:** добавлены модели параметров и валидация H1-H4/S1-S4, Header Protection, junk bounds, диапазонов таймеров и 3.1-флагов. Добавлен тестируемый CPS-парсер/рендерер I1-I5.
- **Преобразование пакетов AWG:** ещё не реализовано. Наличие конфигурации и CPS-генератора не означает совместимость AWG.
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

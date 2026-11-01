# BoringTun Amnezia

Rust-библиотека для реализации WireGuard и AmneziaWG 3.0/3.1 на основе архитектуры Cloudflare BoringTun.

> **Статус разработки:** начальный каркас. Сейчас библиотека предоставляет только типы конфигурации и их валидацию. Она не реализует криптографический handshake, транспорт WireGuard или обфускацию AmneziaWG и пока не предназначена для создания VPN-туннелей.

## Цели

- сохранить побайтовую совместимость классического WireGuard;
- реализовать отдельные, явно версионированные режимы AmneziaWG 3.0 и 3.1;
- использовать Cloudflare BoringTun как Rust-основу, а amneziawg-go и wireguard-go — как поведенческие эталоны;
- проверять совместимость дифференциальными и двусторонними интеграционными тестами.

## Эталонные проекты

- https://github.com/cloudflare/boringtun
- https://github.com/amnezia-vpn/amneziawg-go
- https://github.com/WireGuard/wireguard-go

## Сборка и тесты

    cargo fmt --all -- --check
    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings

Подробный план и критерии готовности: docs/IMPLEMENTATION_PLAN.md.

## Безопасность

До завершения криптографических и interoperability-тестов не используйте проект для защиты реального трафика. Не отключайте проверки аутентичности и не используйте самодельную криптографию.

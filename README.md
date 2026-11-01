# BoringTun Amnezia

Rust-проект для поддержки стандартного WireGuard и AmneziaWG 3.0/3.1.

## Текущий статус

- **WireGuard:** подключён Cloudflare BoringTun 0.7.1 через точную версию Cargo dependency. Публичный API доступен через `wireguard::Tunn`; есть integration tests handshake и зашифрованного обмена IPv4-пакетами.
- **AWG framing:** реализованы H1-H4 ranges, S1-S4 padding и ChaCha20 header protection. Для handshake при изменении H1/H2 пересчитывается MAC1; для transport защищаются только 16 байт заголовка.
- **AWG tunnel wrapper:** добавлена обёртка BoringTun с двусторонним handshake/transport, I1-I5/Junk preambles и MTU-aware content padding.
- **AWG 3.1:** реализованы RandomTrailers, ContentPaddingAddition и DisableCookies. Для handshake/cookie trailer добавляется во внешний датаграмм; для transport нулевые байты добавляются в plaintext до AEAD и обрезаются по длине внутреннего IP-пакета.
- **H1/H2 и MAC2:** исходные MAC1/MAC2 проверяются до канонизации заголовка; при валидном cookie MAC1/MAC2 пересчитываются для BoringTun. Cookie Reply обрабатываются через XChaCha20-Poly1305 и ключи, выведенные из публичных ключей peers. Это устраняет необходимость включать DisableCookies только ради H1/H2 randomization; внешняя проверка under-load с Go ещё требуется.
- **Стандартное AWG padding:** при выключенных ContentPaddingAddition/RandomTrailers transport plaintext дополняется до кратности 16 с учётом MTU. MTU по умолчанию 1420; его можно изменить через `AwgTunnel::set_mtu`.
- **Защитная валидация:** ограничены размер CPS-тегов и количество/размер junk-пакетов; некорректные диапазоны отклоняются до отправки. HeaderProtectionKey скрывается в Debug и очищается через `zeroize` при уничтожении конфигурации/кодека.
- **Go interoperability:** GitHub Actions собирает эталонный peer из amneziawg-go commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`; для WG, AWG 3.0 и AWG 3.1 прошли двусторонние handshake/IPv4 transport и Cookie Reply → MAC2 retry при принудительно активном under-load состоянии. Естественный overload threshold и cookie rotation ещё не проверены.
- **Ограничения:** кастомные таймеры и padding для внутренних keepalive-пакетов BoringTun пока не реализованы.
- **Таймеры:** `AwgTunnel::update_timers` предоставляет хосту polling BoringTun для rekey, повторных handshake и persistent keepalive; пока используются стандартные интервалы BoringTun, а AWG overrides отклоняются.
- **Сетевой/TUN стек:** не входит в библиотечную обёртку.

Полная совместимость с amneziawg-go 3.0/3.1 ещё не заявляется: Go MAC2 challenge/response проверен с принудительным under-load флагом, но естественное достижение порога очереди, cookie rotation, differential vectors и отдельная проверка с upstream wireguard-go остаются задачами.

## Сборка и тесты

    cargo fmt --all -- --check
    cargo test --workspace --all-features
    cargo clippy --workspace --all-targets --all-features -- -D warnings

## Fuzzing

Для локального запуска требуется nightly Rust и cargo-fuzz:

    cargo install cargo-fuzz
    cargo fuzz run awg_decode
    cargo fuzz run cps_parse

GitHub Actions запускает короткие fuzz-campaigns вручную и по еженедельному расписанию. Найденные сбои должны превращаться в обычные регрессионные unit-тесты.

## Upstream

- Cloudflare BoringTun: https://github.com/cloudflare/boringtun
- AmneziaWG Go: https://github.com/amnezia-vpn/amneziawg-go
- WireGuard Go: https://github.com/WireGuard/wireguard-go

Аудит и план: docs/UPSTREAM.md и docs/IMPLEMENTATION_PLAN.md.

## Feature flags

- `wireguard` — базовый WireGuard engine.
- `amneziawg-3-0` — AWG 3.0 (автоматически включает общую AWG-часть и WireGuard).
- `amneziawg-3-1` — AWG 3.1 (автоматически включает общую AWG-часть и WireGuard).
- По умолчанию включены WireGuard, AWG 3.0 и AWG 3.1. Выбор отключённого режима проверяется через `EngineConfig::validate`.

Примеры минимальных сборок:

    cargo test --no-default-features --features wireguard
    cargo test --no-default-features --features amneziawg-3-0
    cargo test --no-default-features --features amneziawg-3-1

# Аудит upstream

## Cloudflare BoringTun

Для протокольного ядра используется опубликованный crate `boringtun = 0.7.1` с точным ограничением версии в Cargo.toml.

- Репозиторий: https://github.com/cloudflare/boringtun
- Версия crate: 0.7.1
- Подготовка релиза 0.7.1: commit `253f7afb2b3df9e952065d10bf2af19913cb176b`
- Лицензия: BSD-3-Clause; копия upstream LICENSE сохранена в THIRD_PARTY_LICENSES/BoringTun-LICENSE.md.
- Публичное ядро: `boringtun::noise::Tunn`.
- BoringTun предоставляет протокол WireGuard, но не сетевой/TUN стек.

README upstream предупреждает о реструктуризации и рекомендует использовать опубликованные crates.io пакеты, а не полагаться на master. Поэтому выбрана закреплённая версия crate, а не git-зависимость. Исходники BoringTun не копируются в этот репозиторий; лицензионные условия и notices upstream должны сохраняться при распространении.

## AmneziaWG Go

- Репозиторий: https://github.com/amnezia-vpn/amneziawg-go
- Текущий Go module path: `github.com/amnezia-vpn/amneziawg-go/v3`.
- Аудируемая ревизия 3.1: `b5928efb6ca19f0153958460c3d141f04abc5c2e` (вместе с исправлением RandomTrailers `da11c9fadc49333d654c4d7ac18fc8d63f4e8000)).
- Проверенные исходники: device/uapi.go, device/send.go, device/receive.go, device/obf.go, device/obf_bytes.go, device/obf_rand.go, device/obf_randchars.go, device/obf_randdigits.go, device/obf_timestamp.go, device/obf_data.go, device/obf_datastring.go, device/obf_datasize.go.
- Файл `device/uapi.go` подтверждает H1-H4, S1-S4, I1-I5, HeaderProtectionKey, ContentPaddingAddition, рандомизируемые таймеры, RandomTrailers и DisableCookies.
- При включённом HeaderProtectionKey каждое значение S1-S4 должно быть не меньше 12 байт. Отсутствующее значение трактуется как ноль и не проходит проверку.
- RandomTrailers и DisableCookies присутствуют в v3 и рассматриваются как возможности AWG 3.1.
- `device/send.go` подтверждает порядок исходящего handshake: I1-I5, junk-пакеты, padding, сериализованное сообщение, MAC, header protection, trailer.
- `device/receive.go` сначала определяет тип и padding, снимает header protection, затем передаёт каноническое сообщение в обычную WireGuard обработку.
- CPS парсер Go поддерживает b, t, r, rc, rd, d, ds, dz. Для I-пакетов источник пуст; d/ds дают пустой вывод, dz кодирует нулевую длину.
- Junk size выбирается по полуоткрытому диапазону [Jmin, Jmax); при равных границах длина равна Jmin.
- RandomTrailers: для handshake/cookie добавляются случайные внешние байты, которые удаляются до передачи в WireGuard parser; для transport случайные нули добавляются в plaintext до AEAD, затем отбрасываются по длине внутреннего IP пакета.
- Если ContentPaddingAddition и RandomTrailers выключены, Go использует calculatePaddingSize и дополняет transport plaintext до кратности 16 с учётом MTU.
- UDP window peer начинается с 500 байт и увеличивается до максимального базового transport packet size. Для cookie reply используется фиксированное DefaultUdpWindow=500.
- DisableCookies отключает выдачу cookie challenge, но не отключает проверку MAC1.
- MAC1 key: BLAKE2s-256("mac1----" || receiver static public key); MAC1 — keyed BLAKE2s-128 по сообщению до поля MAC1. При изменении H1/H2 Rust пересчитывает MAC1 для случайного type ID, а при приёме канонизирует type ID и пересчитывает MAC1 для локального BoringTun.
- MAC2 использует cookie из Cookie Reply и keyed BLAKE2s-128 по сообщению с MAC1. Публичный API BoringTun не раскрывает cookie secret, поэтому Rust-кодек выводит cookie-encryption key из публичного ключа peer, расшифровывает Cookie Reply через XChaCha20-Poly1305 и сохраняет выданный cookie. При H1/H2 randomization исходный MAC2 сначала проверяется; только валидный MAC2 пересчитывается после канонизации. Невалидный MAC2 остаётся невалидным, чтобы BoringTun мог выдать новый Cookie Reply при rate limiting. DisableCookies по-прежнему отключает выдачу challenge, но не очищает MAC2.
- В upstream issue #189 (https://github.com/amnezia-vpn/amneziawg-go/issues/189) зафиксированы опасные некорректные конфигурации: Jmin > Jmax и отрицательные CPS размеры. В Rust-реализации эти значения отклоняются заранее; дополнительно ограничены Jc и размер CPS random tags.

Ограничения совместимости CPS: текущий модуль реализует безопасный разбор восьми Go-тегов, но строгая валидация аргументов намеренно отвергает часть неканонических строк, которые Go-парсер мог принять. Это будет уточнено differential-тестами.

## WireGuard Go

- Репозиторий: https://github.com/WireGuard/wireguard-go
- Контрольная ревизия при аудите: `b3bc704ef0ee21a36298601a9e1e5ff90377ac52`.
- Используется как независимый поведенческий эталон для классического WireGuard.
- Добавлен отдельный helper `tests/interop/wireguard_peer.go`, который собирается непосредственно внутри закреплённой upstream ревизии. Двусторонние тесты WireGuard прошли в CI 2026-11-02.

## Текущее состояние

- BoringTun 0.7.1 подключён как протокольная зависимость.
- Публичный WireGuard API реэкспортирован.
- Есть интеграционные тесты полного handshake и шифрования/расшифрования IPv4 пакета между двумя экземплярами Tunn.
- Добавлен CPS парсер/рендерер I1-I5 с unit-тестами.
- Конфигурация проверяет диапазоны, непересечение H1-H4, junk bounds, обязательные S1-S4 для Header Protection и флаги 3.1.
- Реализован AWG packet transformation pipeline: H1-H4, S1-S4, header protection, MAC1/MAC2 normalization, Cookie Reply, RandomTrailers, ContentPaddingAddition, CPS preambles и junk. В CI прошли двусторонние Rust ↔ amneziawg-go тесты AWG 3.0/3.1, в том числе MAC2 challenge, DisableCookies и cookie-secret rotation; также прошёл отдельный двусторонний Rust ↔ wireguard-go тест классического WireGuard. Это подтверждает именно покрытые сценарии, но не является заявлением о полной production-совместимости.


## Дополнительное hardening после анализа классификатора

При приёме пакета с рандомизированным H1/H2 Rust-кодек сначала проверяет исходный MAC1 над сообщением с фактическим type ID и только после успешной проверки канонизирует заголовок и пересчитывает MAC1 для BoringTun. Это предотвращает принятие случайного handshake-кандидата, собранного из байтов другого типа пакета. Регрессионный тест моделирует ложный H1-кандидат перед корректным transport-пакетом. Проверка подтверждена двусторонними тестами с закреплённым amneziawg-go.

В upstream issue #186 описан класс проблем с ложной классификацией транспортных пакетов при RandomTrailers и диапазонах H1-H3: https://github.com/amnezia-vpn/amneziawg-go/issues/186. Rust-код не должен считать само попадание случайных байтов в диапазон достаточным основанием для классификации handshake.


## Обслуживание таймеров BoringTun

`AwgTunnel::update_timers` делегирует `Tunn::update_timers` и кодирует его сетевые результаты через AWG codec. При timer-triggered повторном handshake wrapper добавляет I1-I5 и junk-пакеты перед handshake, как при явном `initiate_handshake`. В текущей версии используются штатные таймеры BoringTun; параметры RekeyAfterTime, RekeyTimeout, RejectAfterTime, KeepaliveTimeout и MaxHandshakeAttempts остаются явно неподдержанными, чтобы не имитировать настройку, которую ядро BoringTun не умеет принимать.


## Управление секретами

Конфигурация и packet codec используют ручной `Debug`, который маскирует HeaderProtectionKey и MAC1 keys. HeaderProtectionKey и внутренние копии ключей очищаются через `zeroize` при уничтожении соответствующих структур.


## Зафиксированные reference snapshots

Проверено 2026-11-02; все SHA сверены с HEAD соответствующих upstream default branches:

| Проект | Reference HEAD | Использование в этом репозитории |
|---|---|---|
| Cloudflare BoringTun | `6dcc889a95ad82400932f785d874421d70308195` | Архитектурный upstream. Cargo dependency пока закреплён на опубликованной версии `boringtun = 0.7.1`, а не на этом HEAD. |
| AmneziaWG Go | `b5928efb6ca19f0153958460c3d141f04abc5c2e` | Эталон поведения AWG и будущих differential/interoperability tests. |
| WireGuard Go | `b3bc704ef0ee21a36298601a9e1e5ff90377ac52` | Эталон классического WireGuard и будущих differential/interoperability tests. |

Перед обновлением любого reference SHA необходимо повторно прогнать совместимость и обновить golden vectors. Не использовать плавающую ветку master в тестовых сценариях.

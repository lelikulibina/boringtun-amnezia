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
- В upstream issue #189 (https://github.com/amnezia-vpn/amneziawg-go/issues/189) зафиксированы опасные некорректные конфигурации: Jmin > Jmax и отрицательные CPS размеры. В Rust-реализации эти значения отклоняются заранее; дополнительно ограничены Jc и размер CPS random tags.

Ограничения совместимости CPS: текущий модуль реализует безопасный разбор восьми Go-тегов, но строгая валидация аргументов намеренно отвергает часть неканонических строк, которые Go-парсер мог принять. Это будет уточнено differential-тестами.

## WireGuard Go

- Репозиторий: https://github.com/WireGuard/wireguard-go
- Контрольная ревизия при аудите: `b3bc704ef0ee21a36298601a9e1e5ff90377ac52`.
- Используется как независимый поведенческий эталон для классического WireGuard.
- Нужны двусторонние тесты Rust/BoringTun ↔ wireguard-go.

## Текущее состояние

- BoringTun 0.7.1 подключён как протокольная зависимость.
- Публичный WireGuard API реэкспортирован.
- Есть интеграционные тесты полного handshake и шифрования/расшифрования IPv4 пакета между двумя экземплярами Tunn.
- Добавлен CPS парсер/рендерер I1-I5 с unit-тестами.
- Конфигурация проверяет диапазоны, непересечение H1-H4, junk bounds, обязательные S1-S4 для Header Protection и флаги 3.1.
- AWG packet transformation пока не реализован; совместимость AWG 3.0/3.1 не заявляется.

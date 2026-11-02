# Матрица протокольных режимов

| Возможность | WireGuard | AmneziaWG 3.0 | AmneziaWG 3.1 |
|---|---:|---:|---:|
| Базовый WireGuard handshake и transport через BoringTun | Подключено | Основа | Основа |
| AWG tunnel wrapper | Не нужен | Подключён | Подключён |
| H1-H4 | Стандартные type IDs | Диапазоны и рандомизация | Диапазоны и рандомизация |
| MAC1 при H1/H2 randomization | Не требуется | Пересчёт и проверка до канонизации | То же |
| MAC2 и Cookie Reply при H1/H2 randomization | Не требуется | Реализован внутренний cookie flow; есть end-to-end тест under-load | То же |
| S1-S4 | Нет | Реализовано | Реализовано |
| Header protection | Нет | ChaCha20 | ChaCha20 |
| ContentPaddingAddition | Нет | Нет (только базовое MTU-aware padding до кратности 16) | Реализовано |
| Jc/Jmin/Jmax | Нет | Junk-пакеты перед handshake | Junk-пакеты перед handshake |
| I1-I5 CPS | Нет | Parser/renderer и отправка | Parser/renderer и отправка |
| RandomTrailers | Нет | Отклоняется как опция 3.1 | Handshake/cookie outer trailer и transport plaintext padding |
| DisableCookies | Нет | Отклоняется как опция 3.1 | Отключает cookie challenge при сохранении MAC1; внешний Go тест подтверждает обход Cookie Reply при under-load |
| Кастомные таймеры AWG | Стандартные WG | Не реализованы | Не реализованы; ненулевые overrides отклоняются |
| Padding внутренних keepalive BoringTun | Стандартное поведение | Не реализовано | Не реализовано |
| Внешняя совместимость | Rust/BoringTun ↔ upstream wireguard-go: handshake, Cookie Reply/MAC2 retry и IPv4 transport в обе стороны | Rust ↔ amneziawg-go: handshake, Cookie Reply/MAC2 и IPv4 transport в обе стороны | То же, плюс RandomTrailers, ContentPaddingAddition, DisableCookies и cookie rotation |

## Текущие доказательства

- WireGuard: локальные интеграционные тесты и внешний двусторонний тест с закреплённым upstream wireguard-go подтверждают handshake, Cookie Reply/MAC2 retry и IPv4 transport.
- AWG 3.0: интеграционный тест двух Rust-туннелей и внешний двусторонний тест с закреплённым amneziawg-go проверяют handshake, header protection, Cookie Reply/MAC2 и transport.
- AWG 3.1: интеграционные тесты и внешний двусторонний тест с закреплённым amneziawg-go проверяют transport, ContentPaddingAddition, RandomTrailers, DisableCookies, cookie rotation, CPS и junk preambles.
- MAC2: внутренний end-to-end тест с принудительным rate limiter проверяет Cookie Reply, сохранение cookie, рандомизированный повторный handshake и успешный ответ.
- Decoder hardening: есть детерминированный тест коротких/случайных датаграмм и проверки ошибочных/слишком больших пакетов.
- Golden framing vector: детерминированные H3/S3 Cookie Reply и H4/S4 transport fixtures фиксирует точные байты внешнего заголовка, padding и каноническое восстановление; MAC1/MAC2 и key derivation закреплены независимыми BLAKE2s vectors.
- Go interoperability CI: закреплённые upstream `wireguard-go` и `amneziawg-go` успешно прошли двусторонние WG/AWG 3.0/3.1 handshake и IPv4 transport; проверены Cookie Reply/MAC2 retry, AWG 3.1 DisableCookies и принудительная ротация cookie secret.
- CI run `41401197459` (PR #27): Linux, macOS и Windows прошли; Go job также подтвердил live handshake queue stress на запущенном Device и естественное истечение CookieRefreshTime с повторным Cookie Reply/MAC2 retry.

## Ограничения и критерии совместимости

Двусторонние тесты Rust↔upstream wireguard-go и Rust↔amneziawg-go проходят для WG/AWG 3.0/3.1. Дополнительно проверены live handshake queue stress и естественное истечение cookie secret по таймеру. Текущий golden fixture покрывает H4/S4 transport; полные differential/golden vectors для всех вариантов framing и CPS ещё нужны. Ненулевые пользовательские таймеры и padding автоматически генерируемых BoringTun keepalive пока явно не поддерживаются.

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
| ContentPaddingAddition | Нет | Реализовано | Реализовано |
| Jc/Jmin/Jmax | Нет | Junk-пакеты перед handshake | Junk-пакеты перед handshake |
| I1-I5 CPS | Нет | Parser/renderer и отправка | Parser/renderer и отправка |
| RandomTrailers | Нет | Отклоняется как опция 3.1 | Handshake/cookie outer trailer и transport plaintext padding |
| DisableCookies | Нет | Отклоняется как опция 3.1 | Отключает cookie challenge, сохраняя MAC1 validation |
| Кастомные таймеры AWG | Стандартные WG | Не реализованы | Не реализованы; ненулевые overrides отклоняются |
| Padding внутренних keepalive BoringTun | Стандартное поведение | Не реализовано | Не реализовано |
| Внешняя совместимость с amneziawg-go | Не требуется | Не подтверждена | Не подтверждена |

## Текущие доказательства

- WireGuard: локальные интеграционные тесты двух экземпляров BoringTun подтверждают handshake и обмен IPv4-пакетами.
- AWG 3.0: интеграционный тест двух Rust-туннелей проверяет handshake, header protection и transport.
- AWG 3.1: интеграционные тесты проверяют двусторонний transport, ContentPaddingAddition, RandomTrailers, CPS и junk preambles.
- MAC2: внутренний end-to-end тест с принудительным rate limiter проверяет Cookie Reply, сохранение cookie, рандомизированный повторный handshake и успешный ответ.
- Decoder hardening: есть детерминированный тест коротких/случайных датаграмм и проверки ошибочных/слишком больших пакетов.
- CI: Linux, macOS и Windows проходят форматирование, тесты и feature matrix на зафиксированном PR HEAD.

## Ограничения и критерии совместимости

Внутренние Rust↔Rust тесты не заменяют независимую совместимость с Go. До заявления полной совместимости необходимо добавить golden vectors и двусторонние differential/interoperability tests с закреплёнными ревизиями amneziawg-go и wireguard-go, включая cookie rotation и under-load сценарии. Ненулевые пользовательские таймеры и padding автоматически генерируемых BoringTun keepalive пока явно не поддерживаются.

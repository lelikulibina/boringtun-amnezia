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
| DisableCookies | Нет | Отклоняется как опция 3.1 | Отключает cookie challenge при сохранении MAC1; внешний Go тест подтверждает обход Cookie Reply при under-load |
| Кастомные таймеры AWG | Стандартные WG | Не реализованы | Не реализованы; ненулевые overrides отклоняются |
| Padding внутренних keepalive BoringTun | Стандартное поведение | Не реализовано | Не реализовано |
| Внешняя совместимость с amneziawg-go | Handshake + Cookie Reply/MAC2 under-load + двусторонний IPv4 transport проверены в обе стороны | То же, с H1-H4/header protection | То же, плюс RandomTrailers/ContentPaddingAddition и DisableCookies |

## Текущие доказательства

- WireGuard: локальные интеграционные тесты двух экземпляров BoringTun подтверждают handshake и обмен IPv4-пакетами.
- AWG 3.0: интеграционный тест двух Rust-туннелей проверяет handshake, header protection и transport.
- AWG 3.1: интеграционные тесты проверяют двусторонний transport, ContentPaddingAddition, RandomTrailers, CPS и junk preambles.
- MAC2: внутренний end-to-end тест с принудительным rate limiter проверяет Cookie Reply, сохранение cookie, рандомизированный повторный handshake и успешный ответ.
- Decoder hardening: есть детерминированный тест коротких/случайных датаграмм и проверки ошибочных/слишком больших пакетов.
- Go interoperability CI: pinned amneziawg-go commit `b5928efb6ca19f0153958460c3d141f04abc5c2e` успешно прошёл WG/AWG 3.0/3.1 handshake, Cookie Reply/MAC2 retry при принудительно активном Go under-load, Rust-server Cookie Reply/MAC2 после исчерпания BoringTun handshake rate budget, AWG 3.1 DisableCookies=true на обеих сторонах и двусторонний IPv4 transport.
- CI: Linux и macOS прошли форматирование и тесты; Windows проверяется отдельно на текущем HEAD.

## Ограничения и критерии совместимости

Двусторонние тесты Rust↔amneziawg-go проходят для WG/AWG 3.0/3.1, включая Cookie Reply/MAC2 при принудительно активном under-load флаге. Отдельный изолированный тест вызывает реальный IsUnderLoad() с очередью на пороге. Это не проверяет реальное заполнение live handshake queue сетевым потоком и ротацию cookie secret. До заявления полной совместимости нужны golden vectors, differential tests, live overload stress test и отдельная проверка с upstream wireguard-go. Ненулевые пользовательские таймеры и padding автоматически генерируемых BoringTun keepalive пока явно не поддерживаются.

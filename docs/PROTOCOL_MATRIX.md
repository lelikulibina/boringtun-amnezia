# Матрица протокольных режимов

| Возможность | WireGuard | AmneziaWG 3.0 | AmneziaWG 3.1 |
|---|---:|---:|---:|
| Базовый WireGuard handshake и transport через BoringTun | Подключено | Основа | Основа |
| AWG tunnel wrapper | Не нужен | Подключён | Подключён |
| H1-H4 | Стандартные type IDs | Только стандартные type IDs; случайные диапазоны отклоняются | То же |
| S1-S4 | Нет | Реализовано | Реализовано |
| Header protection | Нет | ChaCha20 реализован | ChaCha20 реализован |
| ContentPaddingAddition | Нет | Конфигурация валидируется, transport padding работает | Реализовано |
| Jc/Jmin/Jmax | Нет | Пакеты отправляются перед handshake | Реализовано |
| I1-I5 CPS | Нет | Parser/renderer и отправка реализованы | Реализовано |
| RandomTrailers | Нет | Отклоняется как опция 3.1 | Handshake/cookie outer trailer и transport plaintext padding |
| DisableCookies | Нет | Отклоняется как опция 3.1 | Rate limiter с effectively-unbounded threshold |
| Кастомные таймеры | Стандартные WG | Не реализовано | Не реализовано |
| Полный H-range randomization + MAC1/MAC2 | Нет | Не реализовано | Не реализовано |
| Полный interoperability с amneziawg-go | Не требуется | Не подтверждено | Не подтверждено |

**Ограничения:** H1-H4 пока должны соответствовать стандартным WireGuard type IDs. RandomTrailers transport реализован для обычных вызовов encapsulate; внутренний keepalive, генерируемый самим BoringTun после handshake, пока не получает дополнительный plaintext padding. Требуются differential tests против зафиксированной Go-ревизии.

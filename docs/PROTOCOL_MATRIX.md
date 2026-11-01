# Матрица протокольных режимов

| Возможность | WireGuard | AmneziaWG 3.0 | AmneziaWG 3.1 |
|---|---:|---:|---:|
| Базовый WireGuard handshake и transport через BoringTun | Подключено | Основа | Основа |
| AWG tunnel wrapper | Не нужен | Подключён | Подключён |
| H1-H4 | Стандартные type IDs | Ranges и randomization | То же |
| MAC1 при H1/H2 randomization | Не требуется | Пересчитывается BLAKE2s | Пересчитывается BLAKE2s |
| MAC2/cookie under load при random H1/H2 | Не требуется | CookieReply decrypt + MAC2 recompute | То же |
| Локальный rate limiter при random H1/H2 | Стандартный | Cookie challenge отключается локально | Cookie challenge отключается локально |
| S1-S4 | Нет | Реализовано | Реализовано |
| Header protection | Нет | ChaCha20 реализован | ChaCha20 реализован |
| ContentPaddingAddition | Нет | Реализовано | Реализовано |
| Jc/Jmin/Jmax | Нет | Пакеты отправляются перед handshake | Реализовано |
| I1-I5 CPS | Нет | Parser/renderer и отправка реализованы | Реализовано |
| RandomTrailers | Нет | Отклоняется как опция 3.1 | Handshake/cookie outer trailer и transport plaintext padding |
| DisableCookies | Нет | Отклоняется как опция 3.1 | Реализовано через отключение cookie challenge |
| Кастомные таймеры | Стандартные WG | Не реализовано | Не реализовано |
| Полный interoperability с amneziawg-go | Не требуется | Не подтверждено | Не подтверждено |

**Ограничения:** для H1/H2 randomization локальный rate limiter отключает cookie challenge, но проверяет MAC1; удалённые cookie replies обрабатываются и используются для MAC2. RandomTrailers transport реализован для обычных вызовов encapsulate; внутренний keepalive, генерируемый самим BoringTun после handshake, пока не получает дополнительный plaintext padding. Требуются differential tests против зафиксированной Go-ревизии.

# План реализации BoringTun Amnezia

## 0. Исходное состояние

Целевой репозиторий изначально был пуст. Создан Rust crate, рабочая ветка и CI. Все дальнейшие изменения ведутся через PR.

## 1. Закреплённые эталоны

- Cloudflare BoringTun crate 0.7.1, точная Cargo dependency.
- AmneziaWG Go v3: ревизии для аудита указаны в docs/UPSTREAM.md.
- WireGuard Go: контрольная ревизия указана в docs/UPSTREAM.md.

## 2. Этапы и фактический прогресс

### Этап A — upstream и базовый движок
- [x] Подключить опубликованный BoringTun crate 0.7.1.
- [x] Сохранить лицензию BoringTun.
- [x] Реэкспортировать Tunn API.
- [x] Добавить integration tests полного WireGuard handshake/transport и AWG 3.0/3.1 tunnel flows.
- [x] Добавить Go peer helper и CI interoperability тест для WG/AWG 3.0/3.1 против закреплённого amneziawg-go; базовые handshake и двусторонний IPv4 transport прошли.
- [x] Проверить Cookie Reply → MAC2 retry против Go peer для WG/AWG 3.0/3.1 при принудительно активном under-load состоянии.
- [x] Проверить AWG 3.1 DisableCookies=true против Go peer: при активном under-load Cookie Reply не отправляется, handshake и transport завершаются.
- [x] Проверить пороговый предикат Go IsUnderLoad() на изолированной handshake queue, заполненной до QueueHandshakeSize/8.
- [x] Проверить Rust server-side Cookie Reply/MAC2 против Go client после 10 валидных MAC1 probes с некорректным Noise payload; подтвердить DisableCookies=true без Cookie Reply.
- [x] Проверить принудительную ротацию Go cookie secret: старый MAC2 отвергается, новый Cookie Reply и повторный MAC2 завершают handshake.
- [ ] Проверить live Go handshake queue stress и естественное истечение CookieRefreshTime.

### Этап B — конфигурация AWG
- [x] Модели H1-H4, S1-S4, content padding, junk, timing и 3.1 flags.
- [x] Полуоткрытые диапазоны и проверка пересечений H1-H4 с default type IDs.
- [x] Валидация требования S1-S4 >= 12 при ненулевом HeaderProtectionKey.
- [x] Ограничение Jc, проверка Jmin/Jmax и UDP payload ceiling.
- [x] CPS parser/renderer восьми Go-тегов; отрицательные и чрезмерные размеры отклоняются.
- [ ] Differential tests конфигурации и CPS против amneziawg-go.

### Этап C — AWG packet pipeline
- [x] S1-S4 padding для всех четырёх типов WG сообщений.
- [x] Отдельный AWG 3.0 integration test: handshake, header protection и двусторонний transport.
- [x] ChaCha20 header protection: handshake/cookie целиком, transport header (16 байт) отдельно.
- [x] H1-H4 ranges и header randomization.
- [x] Проверка исходного MAC1 перед канонизацией рандомизированных H1/H2 и пересчёт MAC1 для BoringTun после проверки.
- [x] I1-I5 pre-handshake datagrams и junk-пакеты в правильном порядке.
- [x] ContentPaddingAddition и RandomTrailers для handshake/cookie/обычного transport encapsulate.
- [x] Стандартное дополнение transport plaintext до кратности 16 с учётом MTU.
- [x] DisableCookies через отключение rate-limit cookie challenges при сохранении MAC1 validation.
- [x] Внутренний MAC2 cookie flow: расшифровка Cookie Reply, сохранение cookies, проверка исходного MAC2 и безопасный пересчёт после канонизации.
- [x] Независимые BLAKE2s golden vectors для MAC1/cookie key derivation и MAC1/MAC2 message tags.
- [x] Базовая двусторонняя interoperability проверка handshake/IPv4 transport AWG 3.0 и 3.1 против закреплённого amneziawg-go.
- [ ] Golden vectors и differential-проверка полного AWG packet framing непосредственно с закреплённой Go-реализацией.
- [x] End-to-end RateLimiter under-load test: Cookie Reply → client cookie → randomized retry → успешный handshake.
- [x] Двусторонняя Go interoperability проверка MAC2 under-load и принудительной cookie rotation.
- [ ] Differential/golden vectors для всех вариантов и отдельная проверка с upstream wireguard-go.
- [x] Экспортировать `update_timers` и проводить результаты timer polling через AWG framing, включая I1-I5/junk при повторном handshake.
- [ ] Поддержка random trailers для внутренних keepalive-пакетов BoringTun.
- [ ] Кастомные таймеры.
- [x] Регрессионный тест ложного handshake-кандидата, который не должен перехватывать transport datagram.
- [x] Двусторонняя совместимость AWG 3.0 Rust ↔ Go на закреплённом upstream commit; golden vectors полного packet framing остаются отдельной задачей.

### Этап D — AmneziaWG 3.1
- [x] Базовые механизмы 3.1 RandomTrailers и DisableCookies.
- [x] Базовые двусторонние handshake/transport тесты AWG 3.0/3.1 на закреплённой версии amneziawg-go.
- [x] Двусторонняя совместимость AWG 3.1 Rust ↔ Go на закреплённом upstream commit; differential tests и golden vectors остаются отдельной задачей.
- [ ] Live Go queue under-load, естественное cookie expiry и расширенные edge-case сценарии.

### Этап E — интеграция и hardening
- [x] Детерминированный no-panic regression test декодера на коротких и случайных датаграммах; отдельные проверки malformed и oversized packets.
- [x] Добавлены coverage-guided fuzz targets для AWG decoder и CPS parser на cargo-fuzz/libFuzzer; добавлен ручной и еженедельный workflow.
- [ ] Выполнить длительные fuzz-campaigns, сохранить найденные regression corpus и разобрать все crash/hang.
- [ ] Property-based tests, benchmarks и расширенная regression suite.
- [x] CI feature matrix для no-default, WireGuard, AWG 3.0 и AWG 3.1.
- [x] CI на Linux/macOS/Windows.
- [ ] Документация API, конфигурации и угроз.

## 3. Архитектурные ограничения

- Разделить криптографический движок WireGuard, сериализацию сообщений, транспортный слой и AWG packet transformation.
- Выбирать режим явно; не угадывать его по входящим пакетам.
- AWG 3.0 и 3.1 должны иметь отдельные профили возможностей.
- Стандартный WG-путь не должен зависеть от AWG-параметров.
- Не использовать Go FFI как основную реализацию.
- Не реализовывать собственные криптографические примитивы.
- Не журналировать ключи и plaintext.
- Проверять размеры и арифметику до выделения памяти.

## 4. Тестовая стратегия

Для каждой функции обязательны unit tests валидных/невалидных границ, malformed input tests, сериализация/десериализация, golden vectors, differential tests и двусторонние interoperability tests. Любое изменение AWG-пути должно иметь regression test стандартного WireGuard.

## 5. Критерии готовности

Проект нельзя объявлять совместимым с WireGuard или AWG, пока соответствующий режим не проходит полную матрицу interoperability и regression tests. Текущая реализация проходит внешнюю двустороннюю Go interoperability suite для классического WireGuard, AWG 3.0 и AWG 3.1 на закреплённых ревизиях. Проверены handshake, IPv4 transport, Cookie Reply/MAC2 retry, DisableCookies и принудительная cookie-secret rotation, включая Rust server-side cookie flow. Live Go queue stress, естественное cookie expiry, differential vectors, custom timers и padding автоматически генерируемых keepalive ещё впереди.

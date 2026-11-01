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
- [x] Добавить integration tests полного handshake и защищённого transport обмена между двумя туннелями.
- [ ] Добавить interoperability tests с внешним wireguard-go процессом.

### Этап B — конфигурация AWG
- [x] Модели H1-H4, S1-S4, content padding, junk, timing и 3.1 flags.
- [x] Полуоткрытые диапазоны и проверка пересечений H1-H4 с default type IDs.
- [x] Валидация требования S1-S4 >= 12 при ненулевом HeaderProtectionKey.
- [x] Ограничение Jc, проверка Jmin/Jmax и UDP payload ceiling.
- [x] CPS parser/renderer восьми Go-тегов; отрицательные и чрезмерные размеры отклоняются.
- [ ] Differential tests конфигурации и CPS против amneziawg-go.

### Этап C — AWG packet pipeline
- [x] S1-S4 padding для всех четырёх типов WG сообщений.
- [x] ChaCha20 header protection: handshake/cookie целиком, transport header (16 байт) отдельно.
- [x] H1-H4 ranges и header randomization.
- [x] Пересчёт MAC1 при random H1/H2 с BLAKE2s.
- [x] I1-I5 pre-handshake datagrams и junk-пакеты в правильном порядке.
- [x] ContentPaddingAddition и RandomTrailers для handshake/cookie/обычного transport encapsulate.
- [x] Стандартное дополнение transport plaintext до кратности 16 с учётом MTU.
- [x] DisableCookies через отключение rate-limit cookie challenges при сохранении MAC1 validation.
- [ ] MAC2 cookie challenge interoperability при random H1/H2; пока требуется DisableCookies на обоих peers.
- [ ] Поддержка random trailers для внутренних keepalive-пакетов BoringTun.
- [ ] Кастомные таймеры.
- [ ] Golden vectors и двусторонняя совместимость AWG 3.0 Rust ↔ Go.

### Этап D — AmneziaWG 3.1
- [x] Базовые механизмы 3.1 RandomTrailers и DisableCookies.
- [ ] Differential tests на точной версии amneziawg-go 3.1.
- [ ] Совместимость с cookie/under-load и edge-case сценариями.

### Этап E — интеграция и hardening
- [ ] Fuzzing парсеров и malformed packets.
- [ ] Property-based tests, benchmarks и regression suite.
- [ ] CI на Linux/macOS/Windows и feature matrix.
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

Проект нельзя объявлять совместимым с WireGuard или AWG, пока соответствующий режим не проходит полную матрицу interoperability и regression tests. Текущая реализация покрывает базовые AWG packet transforms, но MAC2 under-load, custom timers и внешняя проверка совместимости ещё впереди.

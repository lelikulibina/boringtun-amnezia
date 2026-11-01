# План реализации BoringTun Amnezia

## 0. Исходное состояние

Целевой репозиторий изначально был пуст. Создан Rust crate и рабочая ветка. Все дальнейшие изменения ведутся через PR.

## 1. Закреплённые эталоны

- Cloudflare BoringTun crate 0.7.1, точная Cargo dependency.
- AmneziaWG Go v3: ревизия для аудита указана в docs/UPSTREAM.md.
- WireGuard Go: контрольная ревизия указана в docs/UPSTREAM.md.

## 2. Этапы и фактический прогресс

### Этап A — upstream и базовый движок
- [x] Подключить опубликованный BoringTun crate 0.7.1.
- [x] Сохранить лицензию BoringTun.
- [x] Реэкспортировать Tunn API.
- [x] Добавить integration tests полного handshake и защищённого transport обмена между двумя туннелями.
- [ ] Проверить интеграционные тесты в CI; текущий первый CI запуск обнаружил только форматирование lib.rs, исправления внесены, требуется повторный запуск.
- [ ] Добавить interoperability tests с внешним wireguard-go процессом.

### Этап B — стабилизация конфигурации AWG
- [x] Модели H1-H4, S1-S4, content padding.
- [x] Валидация непересекающихся H1-H4.
- [x] Валидация требования S1-S4 >= 12 при HeaderProtectionKey.
- [x] Модели junk-пакетов и рандомизируемых таймеров.
- [x] Разделение RandomTrailers и DisableCookies как возможностей AWG 3.1.
- [x] CPS parser/renderer I1-I5 с тестами всех восьми тегов Go.
- [ ] Differential tests конфигурации и CPS против amneziawg-go.

### Этап C — AmneziaWG 3.0 packet transform
- [ ] Сериализация/десериализация пакетов с S1-S4 и H1-H4.
- [ ] ChaCha20 header protection с nonce из padding.
- [ ] Пересчёт/проверка MAC1/MAC2 на канонических сообщениях.
- [ ] Отправка I1-I5 и junk-пакетов перед handshake.
- [ ] ContentPaddingAddition и рандомизируемые таймеры.
- [ ] Golden vectors и двусторонняя совместимость AWG 3.0 Rust ↔ Go.

### Этап D — AmneziaWG 3.1
- [ ] RandomTrailers с точным поведением для каждого типа сообщения.
- [ ] DisableCookies с корректным поведением under-load.
- [ ] Differential tests и двусторонняя совместимость AWG 3.1 Rust ↔ Go.

### Этап E — интеграция и hardening
- [ ] Fuzzing парсеров и malformed packets.
- [ ] Property-based tests, benchmarks и regression suite.
- [ ] CI на Linux/macOS/Windows и сборка feature matrix.
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

Проект нельзя объявлять совместимым с WireGuard или AWG, пока соответствующий режим не проходит полную матрицу interoperability и regression tests. Текущая реализация AWG ограничена конфигурационными типами, проверками и CPS-парсером.

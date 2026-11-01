# Внешние interoperability-тесты

CI собирает тестовый peer из закреплённой ревизии `amneziawg-go` и запускает его рядом с Rust-туннелем через loopback UDP и channel-backed TUN.

## Что проверяется

- стандартный WireGuard: handshake, Cookie Reply/MAC2 retry при активном under-load, двусторонний IPv4 transport;
- AmneziaWG 3.0: H1-H4 randomization, S1-S4, header protection, Cookie Reply/MAC2 retry и двусторонний IPv4 transport;
- AmneziaWG 3.1: то же плюс RandomTrailers и ContentPaddingAddition.

## Детерминированный under-load

Файл `underload_test_hook.go` CI временно копирует в пакет `device` закреплённого Go checkout. Он устанавливает внутренний `underLoadUntil` на 30 секунд. Это **test-only hook**: производственный Go-код не меняется в репозитории и не подменяются CookieChecker, MAC1, MAC2 или криптографические операции.

Такой подход проверяет реальный путь Go Cookie Reply → расшифровка cookie на Rust стороне → повторный handshake с MAC2 → проверка MAC2 Go peer. Он намеренно не проверяет алгоритм определения перегрузки по длине handshake queue; для этого нужна отдельная стресс-проверка с контролируемой нагрузкой.

## Локальный запуск

1. Собрать Go peer из той же ревизии, что закреплена в `.github/workflows/ci.yml`.
2. Установить `AWG_GO_HELPER` в путь к собранному исполняемому файлу.
3. Выполнить:

    cargo test --test go_interop -- --ignored --nocapture

Тесты используют только loopback UDP и не требуют root, системного TUN или изменения сетевых интерфейсов.

## Не покрыто

- естественное достижение under-load через реальную очередь handshake;
- ротация cookie и истечение cookie secret;
- отдельный сценарий AWG 3.1 DisableCookies=true;
- golden vectors для всех вариантов пакетов и независимая проверка с upstream wireguard-go.

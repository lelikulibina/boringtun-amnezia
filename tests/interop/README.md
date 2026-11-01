# Внешние interoperability-тесты

CI собирает тестовый peer из закреплённой ревизии `amneziawg-go` и запускает его рядом с Rust-туннелем через loopback UDP и channel-backed TUN.

## Что проверяется

- стандартный WireGuard: handshake, Cookie Reply/MAC2 retry при активном under-load, двусторонний IPv4 transport;
- AmneziaWG 3.0: H1-H4 randomization, S1-S4, header protection, Cookie Reply/MAC2 retry и двусторонний IPv4 transport;
- AmneziaWG 3.1: то же плюс RandomTrailers и ContentPaddingAddition; отдельные сценарии проверяют DisableCookies=true и ротацию cookie secret между первым Cookie Reply и MAC2 retry (старый MAC2 отвергается, новый Cookie Reply принимается).

## Проверка Rust как сервера

Отдельный reverse-role сценарий запускает Go peer как WireGuard-клиент, а Rust AWG tunnel — как сервер. Go helper отправляет десять корректных по MAC1, но заведомо некорректных по Noise initiation probes с loopback IP. Это исчерпывает стандартный BoringTun handshake rate budget; затем Go peer начинает настоящий handshake.

Проверяется, что Rust сервер:
- при DisableCookies=false отвечает Cookie Reply, проверяет MAC2 на повторном initiation и завершает handshake;
- при DisableCookies=true не отправляет Cookie Reply и принимает handshake без MAC2;
- после handshake передаёт IPv4 transport в обе стороны.

Этот тест использует настоящий BoringTun RateLimiter и настоящий Go CookieGenerator; MAC1 flood helper создаёт только синтаксически корректные initiation probes с корректным MAC1.

## Детерминированный under-load

Файл `underload_test_hook.go` CI временно копирует в пакет `device` закреплённого Go checkout. Он устанавливает внутренний `underLoadUntil` на 30 секунд. Это **test-only hook**: производственный Go-код не меняется в репозитории и не подменяются CookieChecker, MAC1, MAC2 или криптографические операции.

Такой подход проверяет реальный путь Go Cookie Reply → расшифровка cookie на Rust стороне → повторный handshake с MAC2 → проверка MAC2 Go peer. Этот сценарий уже проходит в CI для WG, AWG 3.0 и AWG 3.1. Дополнительно `VerifyNaturalUnderLoadThresholdForInterop` создаёт изолированный Device, заполняет handshake queue до порога и вызывает настоящий `IsUnderLoad()`. Это проверяет сам пороговый предикат, но не реальное заполнение очереди сетевыми пакетами и конкуренцию worker goroutines; для этого остаётся отдельный stress test.

## Локальный запуск

1. Собрать Go peer из той же ревизии, что закреплена в `.github/workflows/ci.yml`.
2. Установить `AWG_GO_HELPER` в путь к собранному исполняемому файлу.
3. Выполнить:

    cargo test --test go_interop -- --ignored --nocapture

Тесты используют только loopback UDP и не требуют root, системного TUN или изменения сетевых интерфейсов.

## Не покрыто

- естественное заполнение live Go handshake queue реальными сетевыми пакетами и конкуренция worker goroutines;
- ожидание естественного истечения CookieRefreshTime без test hook (принудительная ротация cookie secret уже проверяется);
- golden vectors для всех вариантов пакетов и независимая проверка с upstream wireguard-go.

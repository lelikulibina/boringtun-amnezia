# Аудит upstream

## Целевой репозиторий

В начале работы lelikulibina/boringtun-amnezia был пустым репозиторием (GitHub API вернул состояние empty repository). В нём не было исходников, лицензии, истории коммитов или Cargo workspace.

## Источники

- Cloudflare BoringTun: https://github.com/cloudflare/boringtun
- AmneziaWG Go: https://github.com/amnezia-vpn/amneziawg-go
- WireGuard Go: https://github.com/WireGuard/wireguard-go

## Текущее состояние аудита

- README Cloudflare BoringTun подтверждает, что библиотека реализует базовый WireGuard-протокол, но не включает сетевой и tunnel stack.
- README AmneziaWG Go описывает дополнительные параметры AWG 3+, в том числе H1-H4, S1-S4, junk packets, I1-I5, content padding и header protection.
- README wireguard-go используется как дополнительный ориентир поведения классического userspace WireGuard.
- Точные upstream commit SHA пока не зафиксированы. До переноса исходного кода нужно получить и сохранить SHA, лицензионные файлы и соответствующие notices.
- AWG 3.1 нельзя считать полностью описанным README: нужно установить точную реализацию и различия версии по исходному коду и тестам.

## Важное ограничение

На этом этапе код BoringTun не импортирован. Текущий crate — самостоятельный каркас конфигурации. Следующий обязательный инженерный шаг — импортировать закреплённый upstream BoringTun с сохранением лицензий и тестов, затем доказать отсутствие регрессий WireGuard. Никакая протокольная совместимость пока не заявляется.

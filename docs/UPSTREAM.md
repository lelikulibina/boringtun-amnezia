# Аудит upstream

## Cloudflare BoringTun

Для протокольного ядра используется опубликованный crate `boringtun = 0.7.1` с точным ограничением версии в Cargo.toml. Это предпочтительнее зависимости от нестабильной ветки master: сам README upstream прямо предупреждает о реструктуризации и рекомендует использовать crates.io.

- Репозиторий: https://github.com/cloudflare/boringtun
- Версия crate: 0.7.1
- Лицензия: BSD-3-Clause
- Ветка master на момент аудита содержит версию 0.7.1 в boringtun/Cargo.toml.
- Публичное ядро находится в boringtun::noise; Tunn обеспечивает обработку WG handshake/transport.
- BoringTun не предоставляет сетевой и tunnel stack в библиотечном API.

Исходники не копируются в этот репозиторий на данном этапе: используется upstream crate с сохранением исходной лицензии и авторства. Лицензионные условия upstream распространяются на зависимость; при распространении бинарных сборок необходимо выполнять требования BSD-3-Clause.

## AmneziaWG и WireGuard

- AWG: https://github.com/amnezia-vpn/amneziawg-go
- WG: https://github.com/WireGuard/wireguard-go

README AWG описывает семейства H1-H4, S1-S4, junk packets, I1-I5, content padding и header protection. Точная семантика должна быть подтверждена чтением исходников закреплённого commit и тестовыми векторами. GitHub code search не вернул индексированных совпадений для ряда AWG-символов; это не считается доказательством отсутствия реализации.

## Ограничения

AWG packet transformation ещё не реализован. Не заявляется совместимость AWG 3.0/3.1. Перед релизом требуется зафиксировать commit SHA обеих Go-реализаций, добавить NOTICE/LICENSE и собрать differential/interoperability suite.

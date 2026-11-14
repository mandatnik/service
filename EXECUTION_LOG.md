# Журнал выполнения

Текущий этап: **P07 завершён; итоговая публикация в Gitea**.

## P01 — контракты и каркас

Статус: завершён (`7de5608`). Go-модуль `telehack2026`, общий protocol,
JCS RFC 8785 с запретом дубликатов, ECDSA P-256/SHA-256/ASN.1 DER,
PEM SPKI, DTO/лимиты/ошибки, X.509-парсер (включая ГОСТ), контрольные
векторы, docs/api/frontend-каркас. `go test ./...`, `go vet ./...`,
Windows cross-build; 20 фикстур + корень совпадают с манифестом.

## P02 — Windows-служба и сборщик

Статус: завершён. SCM-служба LocalSystem, профили, offline hive,
`CERT_STORE_PROV_REG`, файловое MY, логическое MY через токен сессии,
`.cer/.crt/.pem` с рекурсией и ошибками файлов, дедупликация SHA-256,
DPAPI/ACL/логи. На `.136/.137` прочитаны user1/user2 (по 3), agent (5),
folder (8 уникальных из 9), SYSTEM/SID S-1-5-18/session 0; повреждённый
файл даёт partial; mounts очищены. Доказательства: `evidence/p02/*`,
`docs/acceptance/P02-P03.md`.

## P03 — версии и лицензии CSP

Статус: завершён. Product release и core отдельно: 5.0.13003/5.0.10013
и 4.0.9963/4.0.9019. COM `CPCSPLicense`: GetType 0→client, 1→server,
raw/source сохранены; срок raw + `time_basis=system_local_assumed`;
`is_trial=unknown`, `term_kind=time_limited`; встроенная лицензия —
детектор OID `1.2.643.2.2.49.2`, реального образца нет (явный пробел).
Отсутствие CSP — успешный `not_installed`, ошибки COM — partial/unknown.

## P04 — SQL Server, миграции, сохранение

Статус: завершён. Отдельная БД `Telehack2026`, bootstrap/login через
`sa` + TLS CA, таблицы migrations/machines/registrations/hostnames/
machine_users/certificates/observations/source_states/csp_states/
configs/jobs/reports/events/request_ids/admins/sessions. Миграция
применена на чистой БД, повторный запуск не меняет данные; marker-строка
сохранилась. Проверены повторный отчёт, concurrent request_id, одинаковый
DER на разных машинах (одна строка certificates), .cer без пользователя,
partial/delayed, created_at.

## P05 — агентский REST/HTTPS API

Статус: завершён. Два HTTPS-listener на разных портах, один процесс.
Регистрация/повтор/конфликты ключа/UUID/hostname, rename с сохранением
machine_id, sync по hash с заданиями, идемпотентный report, ack.
Replay-реестр в SQL, request_id в транзакции; replay переживает restart;
DNS — сигнал, не блокировка; лимиты размера/метода/кривой/подписи/пути.
Contract suite: 61 проверка, все PASS (`evidence/p07/contract-*.json`).

## P06 — цикл агента

Статус: завершён. DPAPI identity bundle, первый сбор сразу, опрос 10 минут,
интервал 1 день (2 в тесте), очередь ровно 2 отчёта с атомарной записью,
state/jobs durable, повторы с новым request_id/тем же report_id, ack
заданий, логи current/previous 10 MB, service restart, подписанный rename.
Проверены: полный/partial/empty/очередь 1→2→2 с eviction и доставкой после
сети, config change, manual job при неизменном hash, backend/agent restart,
реальный rename 1→1A→1 с тремя регистрациями и одним machine_id.

## P07 — сквозной стенд и Gitea

Статус: завершён. На `.136/.137` работают настоящие LocalSystem-службы,
на `.138` — portable backend + SQL 2019. В БД две машины, 5 пользователей
каждой, личные/файловые наблюдения, CSP client/server, один DER на двух
машинах без дубля. Пустой успешный отчёт — `.137` seq4, 0 active.
Фикстуры удалены, mounts/hostnames/временные файлы очищены; реальный
сертификат `mimbol` не изменялся. Приёмочный протокол:
`docs/acceptance/P07.md`; доказательства: `evidence/p07/`.

Публикация: один монорепозиторий в Gitea (`pdoexception/telehack2026`),
private, плюс release-артефакты; свежий clone проверен.

## P08 — админка Vue + Vite

Статус: завершён. Локальный bcrypt-администратор, сессии в SQL с
HttpOnly/Secure/SameSite cookie, CSRF double-submit, rate limit; API
машин/пользователей/сертификатов/лицензий/событий/заданий/конфигурации/
hostname. Ручное сканирование, изменение расписания/папок, rebind/revoke,
разрешение hostname-конфликтов. Vue 3.5.45/Vite 6.4.6, один
HTML/CSS/JS, `go:embed`, без CDN. Проверено Chromium 158 на реальных
данных `.136/.137`, включая истечение сеанса и недоступную БД. Протокол:
`docs/acceptance/P08.md`; скриншоты: `evidence/p08/`.

## P09 — MSI, GPO, upgrade/uninstall

Статус: завершён. WiX 3.14.1 MSI 0.2.0/0.3.0; LocalSystem-служба,
ProgramData ACL, пример конфига, recovery, upgrade с тем же UpgradeCode.
Проверены чистая установка на обеих станциях, upgrade 0.2→0.3 с
сохранением UUID/DPAPI/state/очереди (отчёт доставлен после backend down),
repair, удаление через CLI/MSI, повреждённый MSI (1620) и переустановка с
hostname-конфликтом. Реальная GPO: отдельная OU, startup script, config
создан GPO, обе станции установились; GPO/OU/share очищены после теста.
Протокол: `docs/acceptance/P09.md`; доказательства: `evidence/p09/`.

## P10 — отказы и границы

Статус: завершён. Проверены повреждённые очередь/конфиг, занятый и
повреждённый профиль, недоступные папки/битый `.cer`, недоступный COM,
остановленный SQL (UI 503), backend outage/queue recovery, потеря ответа
после принятого отчёта (идемпотентный retry), рестарты, rename с
неотправленной очередью, заполнение выделенного 16 MB VHD, TLS hostname/CA
failure и восстановление, отсутствие inbound-портов/секретов/mounts.
Протокол: `docs/acceptance/P10.md`; логи: `evidence/p10/`.

## Вне объёма

P11 нагрузка 200+, P12 финальная поставка.

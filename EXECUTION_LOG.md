# Журнал выполнения

Текущий этап: **P03 завершён, переход к P04**.

## P01 — контракты и каркас

Статус: завершён (`7de5608`).

Сделано:
- Go-модуль `telehack2026`, точки входа `cmd/agent`, `cmd/backend`,
  `cmd/acceptance`, общий `internal/protocol`.
- Конверт `{data,sign,host}`, JCS RFC 8785 + запрет дубликатов ключей,
  ECDSA P-256/SHA-256/ASN.1 DER/Base64, PEM `PUBLIC KEY`/SPKI.
- Подписанные `uuid`, `hostname`, `request_id`, `method`, `path`.
- DTO регистрации, переименования, синхронизации, отчёта, задания;
  коды ошибок; лимиты; конфигурация и её хеш.
- Разбор X.509 (включая ГОСТ) без проверки доверия; OID встроенной
  лицензии `1.2.643.2.2.49.2`.
- Контрольные векторы JCS, фиксированный вектор подписи, негативные
  проверки кривой/подмены.
- Документы `docs/protocol.md`, `docs/decisions.md`,
  `docs/configuration.md`, `docs/build.md`, `docs/stand-setup.md`,
  `api/openapi.yaml`; каркас frontend Vue+Vite (P08).

Проверки: `go test ./...`, `go vet ./...`, Windows cross-build;
20 фикстур + корень совпадают с манифестом.

## P02 — Windows-служба и сборщик

Статус: завершён.

Сделано:
- Настоящая SCM-служба `TelehackAgent` (LocalSystem), install/uninstall/
  start/stop/status/diag/reset-identity, recovery actions.
- Перечисление профилей `ProfileList`; HKU для загруженных; временное
  подключение `NTUSER.DAT` с `RegLoadKey`/`RegUnLoadKey` и уникальным
  именем для незагруженных; повторная проверка Loaded при занятом hive.
- Read-only `CERT_STORE_PROV_REG`; отсутствующий store не создаётся.
- Файловое MY-хранилище `%APPDATA%\Microsoft\SystemCertificates\My`
  (40-байтный заголовок + DER), плюс логическое MY через токен
  загруженной сессии (`WTSQueryUserToken` + impersonation).
- Папки `.cer`/`.crt`/`.pem`: рекурсия, лимиты, ошибки отдельных файлов,
  дедупликация SHA-256, источник partial при повреждённом файле.
- Извлечение полей X.509, SHA-256, ГОСТ; без закрытых ключей.
- DPAPI, ACL состояния, ротируемые TXT-логи, диагностические JSON.

Проверки на `.136`/`.137`: SYSTEM/S-1-5-18/session 0; user1/user2
(незагруженные) — по 3 фикстуры; `agent` — 5; `mimbol` — логическое MY;
папка — 8 уникальных из 9 файлов; повреждённый `.cer` → partial;
`HKU\Telehack*` после сбора нет. Доказательства: `evidence/p02/136.json`,
`evidence/p02/137.json`, `docs/acceptance/P02-P03.md`.

## P03 — версии и лицензии CSP

Статус: завершён.

Сделано:
- Product release из `csptest` (5.0.13003 / 4.0.9963) и core
  (5.0.10013 / 4.0.9019) — отдельные поля.
- COM `CPCSPLicense.CPCSPLicense`: GetType и GetExpireDate, STA,
  освобождение вариантов/интерфейсов, без CAdES.
- GetType 0→client, 1→server с raw/источником; иные значения unknown.
- `is_trial=unknown`, `term_kind=time_limited` при читаемой дате;
  `valid_to_raw` + `time_basis=system_local_assumed`; состояние active.
- Встроенная лицензия: детектор OID `1.2.643.2.2.49.2`; реального образца
  нет — явный пробел.
- Отсутствие CSP — успешный `not_installed`, ошибки COM — partial/unknown.

Доказательства: те же сводки; `.136` client/0, `.137` server/1.

## Следующие этапы

- P04: SQL Server, миграции, приём отчётов.
- P05: агентский API.
- P06: цикл агента.
- P07: сквозной стенд, приёмка, Gitea.

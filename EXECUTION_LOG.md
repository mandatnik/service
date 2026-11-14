# Журнал выполнения

Текущий этап: **P01 завершён, переход к P02**.

## P01 — контракты и каркас

Статус: завершён.

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
- Контрольные векторы JCS (в т.ч. кириллица, Unicode, числа), фиксированный
  вектор подписи, негативные проверки кривой/подмены.
- Документы `docs/protocol.md`, `docs/decisions.md`,
  `docs/configuration.md`, `docs/build.md`, `docs/stand-setup.md`,
  `api/openapi.yaml`.
- Каркас frontend Vue+Vite (P08), каталоги миграций/стенда.

Проверки:
- `go test ./internal/...` — успешно.
- `go vet ./...` — успешно.
- Все 20 фикстур + корень: SHA-256, serial, subject, validity, bits
  совпадают с `manifest.json`; PEM и DER эквивалентны.

Решения: D01–D16 в `docs/decisions.md`.

## Следующие этапы

- P02: Windows-служба, профили, offline hive, CryptoAPI, `.cer`.
- P03: версии/лицензии CSP, COM.
- P04: SQL Server, миграции, порядок применения.
- P05: агентский API.
- P06: цикл агента.
- P07: сквозной стенд, приёмка, Gitea.

# Telehack 2026 — модуль сбора сведений о СКЗИ

Курсовой/хакатонный проект по кейсу №03 ГРЧЦ: инвентаризация личных
сертификатов и лицензий КриптоПро CSP 4/5 на рабочих станциях Windows 10.

## Состав

- `cmd/agent` — Windows-служба LocalSystem, собирает сертификаты из личных
  хранилищ всех локальных профилей и из настроенных папок `.cer`.
- `cmd/backend` — один portable Go-процесс: агентский и административный
  HTTPS-listeners, миграции, SQL Server 2019.
- `cmd/acceptance` — воспроизводимый контрактный/приёмочный клиент.
- `internal/protocol` — версионированный протокол, JCS, подписи, DTO,
  валидация отчётов и конфигурации.
- `internal/certparse` — разбор X.509 (включая ГОСТ) без проверки доверия.
- `internal/agent/winapi` — WinAPI-адаптеры: профили, offline hive, CryptoAPI,
  COM-лицензии, DPAPI, ACL, SCM.
- `internal/backend` — HTTP API, SQL-хранилище, миграции.
- `migrations/` — SQL-миграции SQL Server 2019.
- `deploy/stand/` — воспроизводимая настройка стенда.
- `docs/` — контракты, решения, конфигурация, приёмочные протоколы.

Объём текущей реализации: **P01–P07** (ARCHITECTURE/IMPLEMENTATION_PLAN).
Админка P08, MSI P09, нагрузка P11 и финальная поставка P12 в этот объём не
входят; отсутствие этих функций не является незавершённостью P07.

## Сборка

Требуется Go 1.26+ (проверено на Go 1.26.3). CGO не требуется.

```bash
go build ./cmd/agent ./cmd/backend ./cmd/acceptance
go test ./...
```

Кросс-сборка под стенд:

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/telehack-agent.exe ./cmd/agent
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/telehack-backend.exe ./cmd/backend
```

Подробно: [docs/build.md](docs/build.md), [docs/configuration.md](docs/configuration.md),
[docs/protocol.md](docs/protocol.md), [docs/decisions.md](docs/decisions.md),
[docs/stand-setup.md](docs/stand-setup.md).

## Тестовые данные

`test-data/certificates-2026-11-14/` — публичные синтетические сертификаты,
манифест ожидаемых полей и SHA-256. Закрытые ключи тестового УЦ находятся
только в `.secrets/` и не публикуются.

# Мандатник — модуль сбора сведений о СКЗИ

Курсовой/хакатонный проект по кейсу №03 ГРЧЦ: инвентаризация личных
сертификатов и лицензий КриптоПро CSP 4/5 на рабочих станциях Windows 10.

## Состав

- `cmd/agent` — Windows-служба LocalSystem, собирает сертификаты из личных
  хранилищ всех локальных профилей и из настроенных папок `.cer`.
- `cmd/backend` — один portable Go-процесс: агентский, административный и
  интеграционный HTTPS-listeners, миграции, SQL Server 2019.
- `cmd/acceptance` — воспроизводимый контрактный/приёмочный клиент.
- `internal/protocol` — версионированный протокол, JCS, подписи, DTO,
  валидация отчётов и конфигурации.
- `internal/certparse` — разбор X.509 (включая ГОСТ) без проверки доверия.
- `internal/agent/winapi` — WinAPI-адаптеры: профили, offline hive, CryptoAPI,
  COM-лицензии, DPAPI, ACL, SCM.
- `internal/backend` — HTTP API, SQL-хранилище, миграции.
- `internal/backend/migrations/` — SQL-миграции SQL Server 2019.
- `frontend/` — Vue 3 + Vite; `internal/backend/web/dist/` — встроенный бандл.
- `deploy/msi/`, `deploy/gpo/` — MSI и GPO deployment.
- `docs/` — контракты, решения, конфигурация, приёмочные протоколы.

Объём текущей реализации: **P01–P10** (ARCHITECTURE/IMPLEMENTATION_PLAN).
P11 (нагрузка 200+) и P12 (финальная поставка) в этот объём не входят.

Админка — Vue 3/Vite, собирается в один HTML/CSS/JS и встроена в backend
EXE. MSI/GPO/upgrade/repair/uninstall описаны в `deploy/msi` и
`deploy/gpo`; приёмка — `docs/acceptance/P08.md`, `P09.md`, `P10.md`.

Версия **0.4.0** добавляет группы машин, назначаемые политики папок и
компактные таблицы сертификатов/лицензий. Правила и API:
[docs/folder-policies.md](docs/folder-policies.md); проверка на стенде:
[docs/acceptance/POLICIES-0.4.0.md](docs/acceptance/POLICIES-0.4.0.md).

Версия **0.5.0** добавляет пулы лицензий КриптоПро, зашифрованные конверты
параметров задач, удалённую установку без окон и единый журнал задач:
[планирование](docs/plans/remote-activation-and-tasks.md),
[протокол](docs/protocol.md), [конфигурация](docs/configuration.md),
[админка](docs/admin.md), [приёмка](docs/acceptance/REMOTE-ACTIVATION-0.5.0.md).

Интеграционный REST API для внешних систем добавлен поверх 0.5.0: отдельный
HTTPS-listener `8446`, префикс `/api/integration/v1`, Bearer-ключи
`mndk_<64 hex>` с IP/CIDR allowlist и только чтение текущей инвентаризации
(машины, группы, политики, сертификаты, лицензии, события) плюс идемпотентный
запуск scan. Ключи создаются в админке, токен показывается один раз. Контракт:
[api/integration-openapi.yaml](api/integration-openapi.yaml); эксплуатация:
[docs/admin.md](docs/admin.md), [docs/configuration.md](docs/configuration.md);
приёмка на стенде: [docs/acceptance/INTEGRATION-API-0.5.0.md](docs/acceptance/INTEGRATION-API-0.5.0.md).

Управляемый жизненный цикл установки агента добавлен поверх 0.5.0: повторная
установка с занятым именем создаёт заявку, администратор подтверждает замену
в карточке АРМ с сохранением `machine_id` и истории, а исторические карточки
архивируются отдельным действием. Отображаемое имя АРМ можно переименовать
через «…» в таблице или карточку; hostname и идентичность при этом не
меняются. Правила: [docs/protocol.md](docs/protocol.md),
[docs/admin.md](docs/admin.md), [docs/decisions.md](docs/decisions.md), [приёмка](docs/acceptance/INSTALLATION-LIFECYCLE.md).

## Сборка

Кроссплатформенные команды `make`, установка инструментов Windows/Linux и
Gitea CI/CD: [CONTRIBUTING.md](CONTRIBUTING.md).


Требуется Go 1.26+ (проверено на Go 1.26.3). CGO не требуется.

```bash
go build ./cmd/agent ./cmd/backend ./cmd/acceptance
go test ./...
```

Кросс-сборка под стенд:

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/mandatnik-agent.exe ./cmd/agent
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/mandatnik-backend.exe ./cmd/backend
```

Подробно: [docs/build.md](docs/build.md), [docs/configuration.md](docs/configuration.md),
[docs/protocol.md](docs/protocol.md), [docs/decisions.md](docs/decisions.md),
[docs/admin.md](docs/admin.md), [docs/stand-setup.md](docs/stand-setup.md).

## Тестовые данные

`test-data/certificates-2026-11-14/` — публичные синтетические сертификаты,
манифест ожидаемых полей и SHA-256. Закрытые ключи тестового УЦ находятся
только в `.secrets/` и не публикуются.

Правила обновления существующих установок: [переход на новое название](docs/renaming.md).

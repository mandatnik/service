# Статус реализации удалённой активации и задач

Дата: 14.11.2026. Ветка: `feature/remote-activation-tasks`.
Основная спецификация: [remote-activation-and-tasks.md](remote-activation-and-tasks.md).

## Этапы

| Этап | Состояние | Основные файлы |
| --- | --- | --- |
| DTO, состояния, SQL, совместимость jobs | Выполнено | `internal/protocol/tasks.go`, `internal/backend/migrations/0004_tasks_licenses.sql`, `0005_legacy_jobs_backfill.sql`, `internal/backend/store/jobs.go` |
| Метаданные провайдера, RSA/CAPI/CNG, бессрочная лицензия | Выполнено | `internal/agent/winapi/provider_windows.go`, `certstore_windows.go`, `logicalstore_windows.go`, `csp_license_windows.go`, `internal/licenseclass/provider.go` |
| Пулы, keyring/HMAC, атомарные резервы, настройки | Выполнено | `internal/backend/licensecrypto/keyring.go`, `internal/backend/store/pools.go`, `internal/backend/store/preview.go`, `config.go` |
| RSA-ключи РС, конверты, capabilities, ротация | Выполнено | `internal/protocol/taskcrypto.go`, `internal/agent/encryption.go`, `internal/backend/store/capabilities.go` |
| Durable-журнал, claim/cancel/reconcile, независимый polling | Выполнено | `internal/agent/taskjournal.go`, `taskruntime.go`, `runtime.go`, `internal/backend/store/task_agent.go` |
| Нативный install_license, верификация, rollback, 3 попытки | Выполнено; Windows E2E ограничен | `internal/agent/install_windows.go`, `internal/agent/winapi/license_windows.go` |
| UI пулов, модалка, задачи, настройки | Выполнено | `frontend/src/components/LicensePoolsView.vue`, `ActivationModal.vue`, `TasksView.vue`, `SettingsView.vue` |
| Контрактные/SQL/Windows/браузерные проверки | Частично | `internal/backend/store/tasks_integration_test.go`, `*_test.go`, acceptance-документ |

## Сознательные технические решения

- Старый `/sync` и `SyncResponse` не менялись. Новые поля конфигурации имеют
  `omitempty` и отправляются только агенту с `schedule_v2`; для старого агента
  сервер считает прежний хеш по legacy-проекции.
- Новые задания идут через добавочные `/api/agent/v1/tasks/*`. Исторические
  `jobs` мигрированы в `tasks` с `legacy_job_id`; для старого агента остаётся
  jobs-канал, для нового — task-канал без двойной выдачи.
- Для scan-элемента, созданного старым `AddJob`, конверт выпускается лениво при
  первом task-sync, когда у агента уже есть RSA-ключ.
- Полный номер лицензии не хранится в state.json, логах, HTTP-ответах, очереди
  отчётов и task item details. Он находится только в AES-256-GCM строке БД,
  RSA-конверте и DPAPI-журнале агента.
- `outcome_unknown` после возможной записи не освобождает ключ. Read-only
  сверка может подтвердить успех, но не доказывает, что номер никогда не был
  применён; автоматическая выдача другому адресату запрещена.

## Ограничения приёмки

- Реальный положительный тест с новым оплаченным ключом не выполнялся: ключ не
  предоставлялся отдельно. Рабочая лицензия WORKSTATION-1 не извлекалась,
  не менялась и не переносилась.
- Отрицательный Windows E2E на реальной SYSTEM-службе требует изолированной
  РС/согласованного снимка без действующей лицензии; в этой сессии такой снимок
  не предоставлялся.
- Windows-тесты провайдера/RSA подготовлены, но выполнены только в режиме
  cross-build; их нужно запустить на стенде.

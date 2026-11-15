# Приёмка интеграционного REST API (0.5.0)

Дата: 14.11.2026. Стенд: `192.168.189.138` (backend, SQL Server),
`192.168.189.136` (WORKSTATION-1, агент). Проверялся отдельный HTTPS-listener
`8446` и Python SDK из `../py-sdk`.

## Что развёрнуто

- Backend portable EXE с тремя listeners: `8443` (агент), `8444` (админка),
  `8446` (интеграционный API).
- Миграция `0006_integration_reported_licenses.sql`: таблицы
  `integration_api_keys` и `reported_licenses`. Применена автоматически при
  старте.
- Windows Firewall: входящее правило TCP 8446 для доверенных систем.
- Агент на `.136` обновлён; он передаёт `csp.licenses`, не передавая полный
  серийный номер.

## Проверенные сценарии

| Сценарий | Результат |
| --- | --- |
| `POST /api/admin/v1/api-keys` с непустым IP/CIDR | 201, токен `mndk_<64 hex>` показан один раз |
| `GET /api/admin/v1/api-keys` | 200, только префикс и allowlist, без токена |
| запрос с IP вне allowlist | 403 `ip_not_allowed` |
| `PUT /api-keys/{id}` с разрешённым CIDR | 200, следующий запрос 200 |
| `PUT /api-keys/{id}` с пустым allowlist | 200, запросы с ключом 403 |
| `DELETE /api-keys/{id}` | 200, запросы с ключом 401 |
| без `Authorization` / неизвестный ключ | 401 `unauthorized` |
| `GET /machines`, `/machines/{id}` | 200, машина, регистрации, пользователи, CSP, отчёты |
| `GET /licensing`, `/licensing/{license_id}` | 200, текущая лицензия CSP |
| `license_status` машины | `active` по активной лицензии CSP |
| `POST /scan-jobs` для свободной машины | 202, задание `pending` |
| повторный `POST /scan-jobs` при pending | 207, задание в `skipped` |
| `GET /scan-jobs`, `/scan-jobs/{id}` | 200, состояния `pending`/`completed` |
| неверные `page_size`, `license_status`, UUID | 400 `invalid_filter`/`invalid_request` |
| OpenAPI и документация | `api/integration-openapi.yaml`, `docs/admin.md`, `docs/protocol.md` |

## Лицензия на реальной станции

Реальный серийный номер станции `.136` в документации не публикуется.
Пример синтетического значения (агент передаёт только маску):

- `serial_masked = 99999X00000999ZZZZZ0*****` (пример);
- `license_id = cc4036b72546fa95edf6de0c9196e60153f72212a1eae180aaef208fb8b06e0d`
  (SHA-256 маски).

Полный номер в API, логах и БД отсутствует. После принудительного scan
`/licensing/{license_id}` вернул `license_state=active`,
`term_kind=perpetual`, `complete=true`, а машина — `license_status=active`.
Повторный scan заменил текущую запись, не создавая дубль.

## Python SDK

С `MANDATNIK_TEST_BASE_URL=https://192.168.189.138:8446` и тестовым ключом:

```text
tests/test_integration.py .. [100%] 2 passed
```

SDK использует только системное хранилище сертификатов; для проверки на стенде
корневой сертификат стенда временно импортировался в `CurrentUser\Root` и был
удалён после теста. Проверка `verify=False` не использовалась.

## Ограничения

- WORKSTATION-2 `.137` во время проверки была недоступна по SSH, поэтому
  второй реальный серийный номер не проверялся.
- Отчёт станции может оставаться `partial` из-за постороннего элемента
  file-store в профиле `mimbol`; на инвентаризацию CSP это не влияет.
- Проверялся продукт `csp`; OCSP/TSP агентом пока не собираются, хотя API
  принимает коды 1/2 по контракту.
- Полный цикл платной установки лицензии не входит в эту приёмку.

# Конфигурация и лимиты

## 1. Агент

### 1.1. Файл GPO/ручного запуска

По умолчанию: `C:\ProgramData\Telehack2026\agent-config.json`.
Путь переопределяется параметром `-config` (диагностика/стенд).

```json
{
  "server_url": "https://192.168.189.138:8443",
  "request_timeout_seconds": 30
}
```

- `server_url` обязателен, только `https://`, без логина/пароля в URL.
- `request_timeout_seconds` — 5…120, по умолчанию 30.
- Параметров отключения TLS-проверки нет.
- Файл читается при старте и периодически перечитывается; адрес сервера можно
  менять без переустановки. Очередь/ключ при этом сохраняются.

### 1.2. Фиксированные значения

| Параметр | Значение |
| --- | --- |
| Период опроса конфигурации/заданий | 60 с по умолчанию; 10…3600, настройка сервера |
| Первый сбор | сразу после регистрации |
| Интервал сбора по умолчанию | 1 день |
| Диапазон `scan_interval_days` | 1…365 |
| Свежесть инвентаризации | 86400 с по умолчанию; 60…2592000 |
| Срок задачи | 604800 с по умолчанию; 60…2592000 |
| Очередь отчётов | 2 последних |
| Логи | `current.txt` + `previous.txt`, по 10 MiB |
| Папки `.cer` по умолчанию | нет |
| Рекурсивный обход папок | да (можно отключить конфигом сервера) |
| Максимум файлов в папке | 2000 по умолчанию, 1…10000 |
| Максимум размера файла | 10 MiB |
| Максимум DER сертификата | 1 MiB |
| Максимум отчёта | 8 MiB |
| Тело HTTP-запроса | 16 MiB |
| Тайм-аут HTTP-запроса | 30 с (5…120) |

Старые агенты без `schedule_v2` продолжают использовать прежний 10-минутный
цикл; новые получают интервал из конфигурации и обновляют таймер без
рестарта службы.

### 1.3. Каталоги состояния

```
C:\ProgramData\Telehack2026\
  agent-config.json          # GPO/ручной файл, не удаляется агентом
  Agent\
    identity.dpapi           # единый DPAPI-bundle: UUID, hostname, ключ
    identity-public.json     # только публичные поля для диагностики
    pending_rename.dpapi     # подготовленный подписанный переход
    state.json               # scan_seq, last_scan_*, config cache
    jobs.json                # состояние ручных заданий
    encryption.dpapi         # DPAPI: RSA-3072 ring для параметров задач
    task-journal.dpapi       # DPAPI: durable журнал попыток/результатов
    queue\report-*.json      # не более двух
    logs\current.txt
    logs\previous.txt
```

`encryption.dpapi` привязан к `installation_id` внутри identity bundle. При
переустановке с новой идентичностью старый ring архивируется и не наследуется.
Для явной ротации остановите службу, выполните
`telehack-agent.exe rotate-encryption-key` и запустите службу снова: сервер
примет новый ключ только по подписанному запросу `capabilities`, старые ключи
останутся в ring для незавершённых конвертов.
`task-journal.dpapi` содержит исходное значение `ProductID`, необходимое для
rollback; файл защищён DPAPI + ACL. При повреждении он архивируется, создаётся
маркер `corrupt_at`, и установка лицензий блокируется до read-only сверки.

DACL каталога и файлов: SYSTEM и Administrators, наследование отключено.
`agent-config.json` — управляемый извне файл; при удалении агента он не
удаляется автоматически.

### 1.4. Конфигурация сбора с сервера

```json
{
  "version": 1,
  "scan_interval_days": 1,
  "poll_interval_seconds": 60,
  "inventory_freshness_seconds": 86400,
  "task_ttl_seconds": 604800,
  "cert_directories": [],
  "folder_policies": [{
    "id": "7f21dc53-18c4-40db-975a-e061772d37ed",
    "name": "Рабочие сертификаты",
    "rules": "C:/Certificates/\n!C:/Certificates/trash/",
    "level": "group"
  }],
  "recursive": true,
  "max_files": 2000,
  "max_file_bytes": 10485760
}
```

`config_hash` — SHA-256 от JCS этого объекта. Агент кэширует точный JSON и
хеш; при совпадении сервер не присылает тело конфигурации, но задания
присылает всегда. Изменение папок/интервала/расписания применяется к
следующему сбору; ручное задание запускает сбор немедленно.

Новые поля `poll_interval_seconds`, `inventory_freshness_seconds`,
`task_ttl_seconds` отправляются только агенту с `schedule_v2`. Старому агенту
сервер отдаёт прежнюю проекцию без этих полей и прежний хеш; его кэш
остаётся совместимым.

Папки определяются назначенными машине или её группам политиками. Без
назначений `folder_policies` отсутствует/пуст, обход папок не выполняется.
`cert_directories` — устаревшее поле, в эффективной конфигурации всегда пустое;
`recursive` сохранено для совместимости формата, правила политик задают
рекурсивный обход. Подробнее: [Политики папок](folder-policies.md).

## 2. Бэкенд

По умолчанию: `C:\ProgramData\Telehack2026\Backend\backend.json`.
Путь задаётся `-config`.

```json
{
  "agent_listen": "0.0.0.0:8443",
  "admin_listen": "0.0.0.0:8444",
  "integration_listen": "0.0.0.0:8446",
  "tls_cert_file": "C:\\ProgramData\\Telehack2026\\Backend\\tls\\backend.crt",
  "tls_key_file": "C:\\ProgramData\\Telehack2026\\Backend\\tls\\backend.key",
  "log_file": "C:\\ProgramData\\Telehack2026\\Backend\\logs\\backend.txt",
  "license_keyring_file": "C:\\ProgramData\\Telehack2026\\Backend\\license-keyring.json",
  "license_fingerprint_key_file": "C:\\ProgramData\\Telehack2026\\Backend\\license-fingerprint.key",
  "db": {
    "server": "192.168.189.138",
    "port": 1433,
    "database": "Telehack2026",
    "user": "telehack_app",
    "password_env": "TELEHACK_DB_PASSWORD",
    "encrypt": true,
    "trust_server_certificate": false,
    "server_name": "sql.telehack.test",
    "ca_file": "C:\\ProgramData\\Telehack2026\\Backend\\tls\\tls-ca.crt"
  },
  "max_concurrent_reports": 8,
  "max_concurrent_requests": 64,
  "admin_session_hours": 12
}
```

- `admin_session_hours` — срок жизни сессии администратора, 1–72 часа
  (по умолчанию 12). Cookie сессии HttpOnly/Secure/SameSite=Strict.
- `integration_listen` — отдельный HTTPS-listener интеграционного REST API
  (по умолчанию `0.0.0.0:8446`). Пустое значение заменяется значением по
  умолчанию; порт обязан отличаться от `agent_listen` и `admin_listen`.
  API использует Bearer-ключи `mndk_<64 hex>`, создаваемые в админке.
- Пароль БД не хранится в файле: только имя переменной окружения.
- `trust_server_certificate=true` допустим только как явная диагностическая
  настройка; в примере и на стенде — `false`.
- `ca_file` — PEM-корень, которым проверяется TLS SQL Server.
- `db.server_name` — имя для проверки SAN сертификата SQL Server.
- Порты агентского, административного и интеграционного API обязаны
  различаться.
- TLS-сертификат бэкенда — файл и ключ; минимальная версия TLS 1.2.

### 2.1. Keyring лицензий и резервное восстановление

Номера лицензий хранятся в БД только как AES-256-GCM ciphertext, HMAC-отпечаток
и маска. Ключ шифрования и отдельный HMAC-ключ дедупликации находятся вне БД:

```text
Backend\license-keyring.json       # AES-256 keyring, 0600/ACL backend+Administrators
Backend\license-fingerprint.key    # отдельный HMAC-SHA-256 ключ
```

Инициализация и ротация:

```bash
telehack-backend.exe license-init -config backend.json
telehack-backend.exe license-keyring-rotate -config backend.json
```

- `license-init` отказывается перезаписывать существующий keyring или HMAC-ключ.
- `license-keyring-rotate` добавляет новый активный ключ и сохраняет старые для
  чтения уже сохранённых строк. Удаление старого ключа допустимо только после
  перешифрования и проверки всех строк. После ротации перезапустите backend,
  чтобы он перечитал keyring.
- Резервная копия БД без keyring/HMAC-ключа не позволяет восстановить номера.
  Храните копию БД и оба файла раздельно, под разными ACL; не помещайте их в
  `backend.json`, ENV, миграции, тестовые фикстуры или артефакты.
- Если файлы отсутствуют или повреждены, операции с пулами/ключами возвращают
  явную ошибку `license_key_unavailable`; fallback к plaintext отсутствует.

### 2.1. Bootstrap и миграции

```bash
# Создание БД и runtime-логина (использует TELEHACK_SA_PASSWORD).
telehack-backend.exe bootstrap -config backend.json

# Только миграции (использует runtime-логин из config).
telehack-backend.exe migrate -config backend.json

# Запуск (миграции выполняются автоматически).
telehack-backend.exe run -config backend.json

# Проверка версии.
telehack-backend.exe version
```

Bootstrap создаёт БД, если её нет, логин `telehack_app` и пользователя в этой
БД с ролями `db_datareader`, `db_datawriter`, `db_ddladmin`. Таблицы
создаются миграциями в выбранной БД, не в `master`.

## 3. Переменные окружения

| Переменная | Где | Назначение |
| --- | --- | --- |
| `TELEHACK_SA_PASSWORD` | bootstrap | пароль `sa` только на время создания БД/логина |
| `TELEHACK_DB_PASSWORD` | backend | runtime-пароль приложения |
| `TELEHACK_GITEA_TOKEN` | публикация | не читается продуктом; только для git push |

Секреты не попадают в исходники, конфиги, логи и коммиты.

## 4. Сетевые порты

| Компонент | Порт | Направление |
| --- | --- | --- |
| Бэкенд, агентский API | 8443/tcp | входящий на сервере, исходящий у агента |
| Бэкенд, админка | 8444/tcp | входящий на сервере |
| Бэкенд, интеграционный API | 8446/tcp | входящий на сервере для доверенных систем |
| SQL Server | 1433/tcp | бэкенд → SQL Server |
| Агент | — | входящих портов нет |

Правила firewall на рабочих станциях для входящих соединений не создаются.

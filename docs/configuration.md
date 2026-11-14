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
| Период опроса конфигурации/заданий | 10 минут |
| Первый сбор | сразу после регистрации |
| Интервал сбора по умолчанию | 1 день |
| Диапазон `scan_interval_days` | 1…365 |
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
    queue\report-*.json      # не более двух
    logs\current.txt
    logs\previous.txt
```

DACL каталога и файлов: SYSTEM и Administrators, наследование отключено.
`agent-config.json` — управляемый извне файл; при удалении агента он не
удаляется автоматически.

### 1.4. Конфигурация сбора с сервера

```json
{
  "version": 1,
  "scan_interval_days": 1,
  "cert_directories": ["C:\\Certificates", "D:\\Exchange\\certs"],
  "recursive": true,
  "max_files": 2000,
  "max_file_bytes": 10485760
}
```

`config_hash` — SHA-256 от JCS этого объекта. Агент кэширует точный JSON и
хеш; при совпадении сервер не присылает тело конфигурации, но задания
присылает всегда. Изменение папок/интервала применяется к следующему сбору;
ручное задание запускает сбор немедленно.

## 2. Бэкенд

По умолчанию: `C:\ProgramData\Telehack2026\Backend\backend.json`.
Путь задаётся `-config`.

```json
{
  "agent_listen": "0.0.0.0:8443",
  "admin_listen": "0.0.0.0:8444",
  "tls_cert_file": "C:\\ProgramData\\Telehack2026\\Backend\\tls\\backend.crt",
  "tls_key_file": "C:\\ProgramData\\Telehack2026\\Backend\\tls\\backend.key",
  "log_file": "C:\\ProgramData\\Telehack2026\\Backend\\logs\\backend.txt",
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
- Пароль БД не хранится в файле: только имя переменной окружения.
- `trust_server_certificate=true` допустим только как явная диагностическая
  настройка; в примере и на стенде — `false`.
- `ca_file` — PEM-корень, которым проверяется TLS SQL Server.
- `db.server_name` — имя для проверки SAN сертификата SQL Server.
- Порт агентского и административного API обязаны различаться.
- TLS-сертификат бэкенда — файл и ключ; минимальная версия TLS 1.2.

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
| SQL Server | 1433/tcp | бэкенд → SQL Server |
| Агент | — | входящих портов нет |

Правила firewall на рабочих станциях для входящих соединений не создаются.

# Админка P08

Админка — Vue 3 + Vite, собирается в **один HTML, один CSS и один JS** и
встраивается в `telehack-backend.exe`. Node.js нужен только при сборке
интерфейса; на стенде отдельный Node/статserver/CDN не требуется.

## Сборка

```bash
cd frontend
npm ci
npm run build
```

Vite кладёт результат в `internal/backend/web/dist`:

```text
dist/index.html
dist/app.css
dist/app.js
```

Каталог `dist` закоммичен. Backend использует `go:embed` (пакет
`internal/backend/web`), поэтому свежий clone собирается без Node.js.
После изменения `frontend/src` повторите `npm run build` и закоммитьте
`dist` вместе с исходниками.

## Локальный администратор

Пароль не хранится в исходниках и не принимается аргументом командной
строки. Хеш — bcrypt cost 12.

Создание/смена пароля через backend:

```powershell
$env:TELEHACK_ADMIN_PASSWORD = '<сильный пароль>'
telehack-backend.exe admin-create -config C:\ProgramData\Telehack2026\Backend\backend.json -username admin
Remove-Item Env:TELEHACK_ADMIN_PASSWORD
```

Прямая SQL-вставка (если администратор создаётся DBA):

```powershell
$env:TELEHACK_ADMIN_PASSWORD = '<сильный пароль>'
telehack-backend.exe hash-password
# скопируйте полученный bcrypt-хеш в SQL ниже
Remove-Item Env:TELEHACK_ADMIN_PASSWORD
```

```sql
INSERT INTO dbo.administrators (username, password_hash, disabled, created_at)
VALUES (N'admin', N'<bcrypt-$2a$12-хеш>', 0, SYSUTCDATETIME());
```

Публичной регистрации администраторов нет.

## Сессии и защита

- Вход: `POST /api/admin/v1/login` (JSON, HTTPS).
- Пароль проверяется bcrypt; при неверном пароле/неизвестном логине
  возвращается одинаковый ответ.
- Сервер создаёт случайный 32-байтовый токен; в SQL хранится только
  SHA-256 токена. Сессия живёт `admin_session_hours` (по умолчанию 12 ч).
- Cookie `telehack_admin` — `HttpOnly`, `Secure`, `SameSite=Strict`.
- Cookie `telehack_csrf` доступна JS; для `POST/PUT/DELETE` требуется
  заголовок `X-CSRF-Token`, совпадающий с cookie (double-submit).
- На 401 интерфейс показывает форму входа; административные API без
  валидной сессии недоступны.
- В памяти backend действует ограничение попыток входа (5 неудач за 5 минут
  на источник).
- Статика отдаётся с CSP, `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: no-referrer`, HSTS.

## API

Все административные маршруты находятся под `/api/admin/v1` и требуют
cookie сессии; изменяющие методы дополнительно требуют CSRF.

| Метод | Маршрут | Назначение |
| --- | --- | --- |
| POST | `/login`, `/logout` | вход/выход |
| GET | `/session`, `/overview` | сессия и сводка |
| GET | `/machines`, `/machines/{machine_id}` | машины, пользователи, источники, CSP, отчёты, задания |
| POST | `/machines/{machine_id}/jobs` | ручное сканирование |
| GET | `/certificates`, `/certificates/{sha256}` | сертификаты и наблюдения |
| GET | `/licensing` | CSP product/core, тип, срок, пробность, источник |
| GET | `/events`, `/jobs` | события и задания |
| GET/PUT | `/config` | расписание и папки `.cer` |
| GET | `/hostnames` | резервирование hostname и конфликты |
| POST | `/hostnames/{name}/assign` | разрешённая администратором перепривязка hostname |
| POST | `/registrations/{id}/rebind` | замена публичного ключа регистрации |
| POST | `/registrations/{id}/revoke` | отзыв старой регистрации |

Тип лицензии (`client`/`server`/`unknown`) и `is_trial` берутся только из
источника (`CPCSPLicense.GetType`, raw-значение). Версия CSP и версия
Windows не используются для вывода типа или пробности.

## Ручное сканирование

`POST /machines/{id}/jobs` создаёт задание `scan` со стабильным `job_id`.
Агент получает его на следующем опросе (штатно 10 минут) даже при
неизменном `config_hash`; выполнение подтверждается `job_ack`. Результат
появляется в карточке машины после отправки отчёта.

## Изменение конфигурации

`PUT /config` проверяет `scan_interval_days`, `max_files`, `max_file_bytes`,
увеличивает версию и
пересчитывает JCS-хеш. Агент забирает новую конфигурацию на опросе; UI
показывает версию и хеш. Изменение фиксируется событием `config_changed`.

Папки управляются через отдельные политики с назначениями машинам и группам.
Непустой `cert_directories` в `PUT /config` отклоняется. Новые методы и точные
приоритеты: [Политики папок](folder-policies.md). Флажки таблицы машин позволяют
массово добавить машины в группу; состав группы редактируется отдельно.

## Ограничения и решения

- Админка работает только через HTTPS. HTTP-слушателя нет.
- Для ручного сканирования не требуется менять интервал опроса.
- Старые регистрации после переустановки/переименования остаются в истории,
  но могут быть отозваны администратором; hostname освобождается и
  назначается новой регистрации. Это явное действие, а не автоматическое
  доверие новому ключу.
- Бандл не использует CDN, внешние шрифты, `vue-router` или дополнительные
  JS-чанки.

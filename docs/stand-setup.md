# Стенд: развёртывание и проверка

Стенд: Ubuntu `192.168.189.140`, Windows Server 2022 `192.168.189.138`
(SQL Server 2019 Express), Windows 10 `192.168.189.136` (CSP 5.0.13003),
Windows 10 `192.168.189.137` (CSP 4.0.9963). SSH-пользователь Windows —
`agent` с административными правами; секреты — только в `.secrets/`.

## 1. TLS

Для стенда выпускается отдельный RSA TLS-УЦ (не ГОСТ-УЦ тестовых
сертификатов):

- корневой сертификат `tls-ca.crt` устанавливается в
  `LocalMachine\Root` на `.136`, `.137` и `.138` (необходимо для HTTPS
  агента и административного API);
- серверный сертификат бэкенда: SAN `192.168.189.138`,
  `SERVER-WINDOWS`, `backend.mandatnik.test`;
- серверный сертификат SQL Server: SAN `192.168.189.138`,
  `SERVER-WINDOWS`, `sql.mandatnik.test`; закрытый ключ получает право чтения
  для `NT SERVICE\MSSQL$SQLEXPRESS`; отпечаток прописывается в
  `SuperSocketNetLib\Certificate`, служба SQL перезапускается.

Бэкенд проверяет SQL TLS по `db.ca_file` и `db.server_name`, без
`TrustServerCertificate`. Корень TLS-УЦ является частью рабочего
развёртывания стенда; тестовый ГОСТ-корень в доверенные не устанавливается.

## 2. База данных

```powershell
$env:MANDATNIK_SA_PASSWORD = '<sa-password>'
mandatnik-backend.exe bootstrap -config C:\ProgramData\Mandatnik\Backend\backend.json
```

Создаётся отдельная БД `Mandatnik` и runtime-логин `mandatnik_app`.
Приложение не использует `master` для таблиц.

## 3. Бэкенд

`backend.json` размещается в
`C:\ProgramData\Mandatnik\Backend\backend.json` с ACL только для SYSTEM и
Administrators. Пароль БД — в отдельном ACL-защищённом файле, имя которого
задано `db.password_file`; переменная окружения `MANDATNIK_DB_PASSWORD`
поддерживается как альтернатива. Бэкенд — портативный EXE, не реализующий
SCM-диспетчер, поэтому на стенде он запускается планировщиком как SYSTEM:

```powershell
$action = New-ScheduledTaskAction -Execute 'C:\ProgramData\Mandatnik\Backend\mandatnik-backend.exe' `
  -Argument 'run -config "C:\ProgramData\Mandatnik\Backend\backend.json"' `
  -WorkingDirectory 'C:\ProgramData\Mandatnik\Backend'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'MandatnikBackend' -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings
Start-ScheduledTask -TaskName 'MandatnikBackend'
```

Это не является обязательным контейнером/службой продукта: EXE можно
запустить и вручную; требование «один portable процесс» сохранено.

Порты 8443/8444/8446 открываются в firewall только на сервере. Порт 8446
нужен только доверенным интеграционным системам; на рабочих станциях
входящие порты агента не создаются.

## 4. Агент

```powershell
mandatnik-agent.exe install -config C:\ProgramData\Mandatnik\agent-config.json
Start-Service MandatnikAgent
mandatnik-agent.exe status
```

Служба работает как LocalSystem. Первый сбор запускается сразу после
регистрации. Диагностика: `mandatnik-agent.exe diag`, логи —
`C:\ProgramData\Mandatnik\Agent\logs`.

## 5. Тестовые фикстуры

1. Войти в `C:\Users\user1` (`.136`) / `C:\Users\user2` (`.137`) нельзя;
   сертификаты добавляются временной SYSTEM-задачей с `reg load` и
   `CertAddEncodedCertificateToStore`.
2. В личное хранилище вошедшего `agent` импортируются выбранные `.cer` через
   `Import-Certificate -CertStoreLocation Cert:\CurrentUser\My`.
3. В `C:\ProgramData\Mandatnik\test-certs` копируются DER/PEM-файлы.
4. Перед импортом фиксируется исходный список; после приёмки удаляются только
   добавленные SHA-256, проверяется восстановление списка, hive выгружается.

Скрипты: `tools/stand/` (диагностические, не входят в продуктовый агент).

## 6. Приёмочный сценарий

```bash
go run ./cmd/acceptance contract -config acceptance.json -evidence evidence/
```

`acceptance.json` (не коммитится) содержит URL бэкенда, путь к TLS-корню и
параметры SQL для проверок. Сценарий создаёт синтетические идентичности,
проверяет регистрацию/переименование/конфликты, replay, report_id,
полный/частичный/пустой/запоздавший отчёт, конфигурацию и задания, затем
удаляет только свои записи. Реальные `.136/.137` проверяются отдельным
сценарием и SQL-запросами из `docs/acceptance/P07.md`.

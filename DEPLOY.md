# Мандатник: тестовая сборка и развёртывание на Windows

Миша, задача — взять исходники, самостоятельно собрать сервер EXE и агент
EXE/MSI, поднять сервер с чистой БД и получить инвентаризацию с Windows-АРМ.
Ниже — последовательность для отдельного тестового стенда, без зависимости
от нашего работающего сервера, CI и его секретов. Текущая версия кода — 0.5.0;
при сборке версия берётся из `internal/version/version.go`.

## 1. Что подготовить

Сначала выбери постоянный IPv4-адрес WS, доступный с АРМ. Во всех примерах
ниже **192.168.1.50 — пример, а не адрес готового сервера**. Заменяй его
на свой адрес в сертификате, URL браузера и конфиге агента. Порты: агент —
8443, админка — 8444, SQL на сервере — 127.0.0.1:1433.

До выполнения команд установи инструменты:

| Инструмент | Откуда взять и что выбрать |
| --- | --- |
| Git for Windows x64 | [Официальный установщик](https://git-scm.com/downloads/win). С ним поставляется OpenSSL: при стандартной установке `C:\Program Files\Git\usr\bin\openssl.exe` |
| Go | [Установщик Windows amd64](https://go.dev/dl/), версия 1.26+, проверен 1.26.3 |
| Node.js | [Официальный установщик](https://nodejs.org/en/download), ветка 22, компонент npm оставить включённым |
| GNU Make 4.x | [Пакет Chocolatey `make`](https://community.chocolatey.org/packages/make). Если Chocolatey ещё нет, сначала установи его по [инструкции Chocolatey](https://chocolatey.org/install), затем в PowerShell администратора выполни `choco install make --version=4.4.1 -y` |
| WiX Toolset 3.14.1 — Windows Installer XML Toolset | [Архив wix314-binaries.zip](https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip). Распакуй весь архив в `C:\Tools\wix314`: нужны `candle.exe`, `light.exe`, `WixUtilExtension.dll` и остальные файлы. WiX 4/5 не подходит |
| Microsoft .NET Framework 4.8 Runtime | [Страница Microsoft](https://dotnet.microsoft.com/en-us/download/dotnet-framework/net48), раздел **Runtime**, Windows. Developer Pack и современный .NET SDK для WiX не нужны. Если установщик сообщает, что эта или более новая версия уже есть, повторно ставить не надо |

Если не хочешь устанавливать Chocolatey и Make, ниже есть равнозначные команды
через Go-инструмент проекта. OpenSSL отдельно скачивать не обязательно:
добавь поставляемый с Git каталог в PATH **текущего окна PowerShell**:

```powershell
$env:Path = 'C:\Program Files\Git\usr\bin;' + $env:Path
openssl version
```

При нестандартном пути установки Git поправь путь. Повтори настройку в окне,
где будешь выпускать сертификат. На сервере без Git можно выполнить выпуск
на сборочной машине и перенести серверный сертификат/ключ по защищённому каналу.

Минимально нужны сервер и одна рабочая станция (можно виртуальные машины).
Сборочную машину можно совместить с сервером. Для ручной установки домен не
нужен; для проверки GPO нужны AD, доменная рабочая станция и права на тестовую OU.

| Где | Что требуется |
| --- | --- |
| Сборочная Windows x64 | Git, Go 1.26+ (в проекте проверен 1.26.3), Node.js 22 + npm, GNU Make 4.x (или команды Go ниже), WiX **3.14.1**, .NET Framework 4.x для WiX |
| Сервер | Windows Server 2022 x64 (проверенный вариант), SQL Server **2019**, например Express, права локального администратора |
| Рабочая станция | Windows 10 x64 (проверено на 19045), права локального администратора для установки агента |
| Для HTTPS | OpenSSL с поддержкой `-addext` на сервере или сборочной машине; можно использовать `openssl.exe` из Git for Windows |
| Для проверки лицензий | Установленный отдельно КриптоПро CSP 4 или 5 на АРМ; дистрибутив и лицензия предоставляются отдельно |

На сервере и АРМ Go, Node, Make и WiX для **запуска** не нужны. Docker,
WSL, IIS, SDK КриптоПро и браузерный плагин не требуются. Без CSP можно
проверять установку, связь и сбор сертификатов; полноценную проверку лицензий
делать на машине с CSP. Для загрузки зависимостей сборщику нужен Интернет.

Используй обычный **Windows PowerShell 5.1**. Настройку сервера и установку
агента выполняй в PowerShell **от имени администратора**. После установки
инструментов открой новое окно, чтобы обновился PATH.

## 2. Получить код и собрать

Получи репозиторий по переданной ссылке (или распакуй архив исходников).
Внутренний адрес репозитория доступен только при наличии маршрута к нашей сети:

Команды выполняй из корня исходников с `go.mod` и `Makefile`, в примере
`C:\src\mandatnik`. Для Windows-проверок `make check` открой PowerShell
**от имени администратора**: тесты агента создают файлы с рабочими ACL только
для SYSTEM и Administrators. В обычном окне возможны `Access is denied` при
ротации логов и повторном чтении DPAPI-файлов; это не исправляется сменой TEMP.

Первые команды только показывают ревизию и версии инструментов: так проверяем,
что PATH настроен и собираем нужный код. `Test-Path` должен вернуть `True`.
Это ещё не запуск продукта. После каждой команды проверяй результат;
при ошибке не переходи дальше.

```powershell
git clone http://10.10.26.11/pdoexception/telehack2026 C:\src\mandatnik
Set-Location C:\src\mandatnik

git rev-parse HEAD
go version
node --version
npm --version
make --version
Test-Path C:\Tools\wix314\candle.exe

go mod download
go mod verify
make check
if ($LASTEXITCODE -ne 0) { throw 'Проверки не прошли: сборку не продолжаем' }
make package WIX_DIR=C:/Tools/wix314
if ($LASTEXITCODE -ne 0) { throw 'Сборка не завершилась успешно' }
```

Все команды сборки запускаются **из корня исходников Мандатника**, где лежат
`go.mod` и `Makefile`. В примере clone это `C:\src\mandatnik`; если в переданном
архиве проект вложен в папку `mandatnik`, перейди в неё. Запиши ревизию Git; для архива сохрани имя/дату полученной версии.
Для проверки последних локальных изменений нужен архив текущих исходников
либо ревизия, в которую они уже включены: обычный clone получает только
опубликованный код. При ошибке любой команды остановись и разбери её перед следующим шагом.

Если Make не установлен, вместо `make check` и `make package` выполни
в той же папке следующие команды (это тот же сборочный инструмент):

```powershell
go run ./tools/build unit
if ($LASTEXITCODE -ne 0) { throw 'Unit-тесты не прошли' }
go run ./tools/build lint
if ($LASTEXITCODE -ne 0) { throw 'Статические проверки не прошли' }
go run ./tools/build frontend
if ($LASTEXITCODE -ne 0) { throw 'Не собрался интерфейс' }
go run ./tools/build build -out artifacts/ci
if ($LASTEXITCODE -ne 0) { throw 'Не собрались EXE' }
go run ./tools/build msi -out artifacts/ci -wix C:/Tools/wix314
if ($LASTEXITCODE -ne 0) { throw 'Не собрался MSI' }
```

`make check` запускает unit-тесты и `go vet`, без подключения к SQL.
`make package` собирает интерфейс через `npm ci`/Vite, встраивает его в сервер,
собирает Windows amd64 EXE и MSI. Отдельно запускать frontend при работе сервера
не нужно. В `artifacts\ci` появятся:

- `mandatnik-backend.exe` — сервер;
- `mandatnik-agent.exe` — агент;
- `mandatnik-acceptance.exe` — вспомогательный приёмочный клиент;
- `MandatnikAgent-0.5.0.msi` — установщик агента (номер зависит от версии кода);
- `build-info.json`, `SHA256SUMS` — сведения о сборке и контрольные суммы.

```powershell
.\artifacts\ci\mandatnik-backend.exe version
.\artifacts\ci\mandatnik-agent.exe version
Get-FileHash .\artifacts\ci\*.exe, .\artifacts\ci\*.msi -Algorithm SHA256
```

Сохрани всю папку результата. Установщик сервера не нужен: сервер — portable
EXE. MSI относится только к агенту. Для сборки только EXE есть `make build`;
`make binaries` использует уже сохранённый в коде интерфейс без его пересборки.
Подробности сборки: [CONTRIBUTING.md](CONTRIBUTING.md).

## 3. Подготовить сервер и SQL

Далее пример: сервер имеет постоянный адрес **192.168.1.50**, SQL стоит на
нём же. **Замени этот адрес во всех примерах на адрес своего сервера**, в том
числе в сертификате и конфиге агента. Не указывай `localhost` в конфиге удалённых
АРМ. Проверь корректное время на всех машинах.

Установи SQL Server 2019 Express с компонентом Database Engine:

1. Выбери смешанный режим аутентификации (SQL Server + Windows), задай и сохрани
   пароль `sa`, добавь себя SQL-администратором. Если SQL уже установлен,
   включи Mixed Mode и логин `sa` через SSMS, затем перезапусти SQL.
2. В **SQL Server Configuration Manager → SQL Server Network Configuration →
   Protocols for SQLEXPRESS** включи TCP/IP.
3. В TCP/IP → IP Addresses → IPAll очисти TCP Dynamic Ports и задай TCP Port
   `1433`. Убедись, что нужные IP включены. Перезапусти службу
   `SQL Server (SQLEXPRESS)`.
4. Проверь соединение. Приложение обращается к TCP-порту, не к имени экземпляра:

```powershell
Test-NetConnection 127.0.0.1 -Port 1433
```

SQL Browser для такого подключения не нужен. Порт SQL наружу открывать не
требуется, когда БД и backend на одной машине.

Создай каталоги, скопируй собранный сервер (путь к исходникам поправь при необходимости):

```powershell
$root = 'C:\ProgramData\Mandatnik\Backend'
New-Item -ItemType Directory -Force -Path $root, "$root\tls", "$root\logs" | Out-Null
icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
Copy-Item C:\src\mandatnik\artifacts\ci\mandatnik-backend.exe $root
Set-Location $root
```

Эти ACL оставляют доступ SYSTEM и локальным администраторам, независимо от
языка Windows. Дальнейшие действия с файлами сервера выполняй с повышенными правами.

## 4. Выпустить тестовый HTTPS-сертификат

Агент проверяет HTTPS: режима «игнорировать сертификат» нет. Для отдельного
стенда создадим свой корневой УЦ и сертификат сервера. Если уже есть корпоративный
УЦ, можно вместо этого выдать сертификат с Server Authentication и SAN для
реального имени/адреса сервера и использовать его PEM-сертификат и PEM-ключ.

Следующие команды выполняются в `C:\ProgramData\Mandatnik\Backend`.
`openssl` должен быть в PATH (настройка из раздела 1). Сначала введи
**реальный IP своего WS** в `$ServerIP`. Команды ниже выполняй по одной;
каждая команда занимает одну строку, визуальный перенос в просмотрщике не
означает новую команду.

```powershell
$ServerIP = Read-Host 'IPv4-адрес WS, по которому будут подключаться браузер и агент'
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 -keyout tls\tls-ca.key -out tls\tls-ca.crt -subj '/CN=Mandatnik Test Root' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -new -newkey rsa:3072 -nodes -keyout tls\backend.key -out tls\backend.csr -subj '/CN=Mandatnik Test Backend'
Set-Content -Encoding ascii -Path tls\backend.ext -Value @("basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature,keyEncipherment", "extendedKeyUsage=serverAuth", "subjectAltName=IP:$ServerIP")
openssl x509 -req -in tls\backend.csr -CA tls\tls-ca.crt -CAkey tls\tls-ca.key -CAcreateserial -out tls\backend.crt -days 180 -sha256 -extfile tls\backend.ext
openssl verify -CAfile tls\tls-ca.crt tls\backend.crt
openssl x509 -in tls\backend.crt -noout -ext subjectAltName
openssl x509 -in tls\tls-ca.crt -outform DER -out tls\tls-ca.cer
Import-Certificate -FilePath .\tls\tls-ca.cer -CertStoreLocation Cert:\LocalMachine\Root
```

В выводе `subjectAltName` должен быть **твой** IP. В браузере открывай
`https://ТВОЙ-IP:8444/`, в конфиге агента указывай `https://ТВОЙ-IP:8443`.
Доверие к корню не отменяет проверку адреса: `localhost`, имя WS и IP — разные
адреса. Если нужен доступ по DNS-имени, добавь его в строку расширений:
`"subjectAltName=IP:$ServerIP,DNS:имя-сервера"`, затем выпусти серверный
сертификат заново и обеспечь разрешение имени с АРМ.

Проверь успешное завершение каждой команды. Если используешь DNS-имя, добавь
в `subjectAltName` также `DNS:имя-сервера` и обеспечь его разрешение с АРМ.
Перенеси `tls-ca.key` в закрытое место хранения вне папки поставки: он нужен
для выпуска сертификатов, серверу для работы не нужен. `backend.key` остаётся
на сервере под указанными ACL. На АРМ передаётся **только `tls-ca.cer`**.

## 5. Конфигурация, БД и первый администратор

Создай `C:\ProgramData\Mandatnik\Backend\backend.json`:

```json
{
  "agent_listen": "0.0.0.0:8443",
  "admin_listen": "0.0.0.0:8444",
  "integration_listen": "127.0.0.1:8446",
  "tls_cert_file": "C:\\ProgramData\\Mandatnik\\Backend\\tls\\backend.crt",
  "tls_key_file": "C:\\ProgramData\\Mandatnik\\Backend\\tls\\backend.key",
  "log_file": "C:\\ProgramData\\Mandatnik\\Backend\\logs\\backend.txt",
  "license_keyring_file": "C:\\ProgramData\\Mandatnik\\Backend\\license-keyring.json",
  "license_fingerprint_key_file": "C:\\ProgramData\\Mandatnik\\Backend\\license-fingerprint.key",
  "db": {
    "server": "127.0.0.1",
    "port": 1433,
    "database": "Mandatnik",
    "user": "mandatnik_app",
    "password_file": "C:\\ProgramData\\Mandatnik\\Backend\\db-password.txt",
    "encrypt": true,
    "trust_server_certificate": true,
    "allow_insecure_db_tls": true
  }
}
```

**Здесь выбран упрощённый режим только для локальной тестовой БД:** SQL-трафик
шифруется, но сертификат SQL не проверяется. Это позволяет использовать
самоподписанный сертификат SQL без отдельной настройки SQL TLS. Два флага
`trust_server_certificate` и `allow_insecure_db_tls` нужны вместе. На проверку
HTTPS между агентами и backend это не влияет — она остаётся обязательной.
Для отдельного SQL-сервера или обычного развёртывания настрой доверенный SQL
TLS-сертификат, задай оба флага `false`, `db.server_name` по SAN и `db.ca_file`
по пути к PEM-корню; см. [docs/stand-setup.md](docs/stand-setup.md).

В том же административном PowerShell создай пароль приложения и БД. Пароль
приложения — новый сложный пароль, соответствующий политике SQL, не пароль `sa`.
Здесь ввод скрыт; файл пароля будет доступен только по ACL каталога сервера.

```powershell
Set-Location C:\ProgramData\Mandatnik\Backend
$appCredential = Get-Credential -UserName mandatnik_app -Message 'Новый пароль приложения для SQL'
[System.IO.File]::WriteAllText("$PWD\db-password.txt", $appCredential.GetNetworkCredential().Password)
Remove-Variable appCredential
$saCredential = Get-Credential -UserName sa -Message 'Пароль sa, заданный при установке SQL'
$env:MANDATNIK_SA_PASSWORD = $saCredential.GetNetworkCredential().Password
.\mandatnik-backend.exe bootstrap -config .\backend.json
# Должно быть: database Mandatnik and login mandatnik_app are ready
Remove-Item Env:\MANDATNIK_SA_PASSWORD
Remove-Variable saCredential

.\mandatnik-backend.exe migrate -config .\backend.json
.\mandatnik-backend.exe license-init -config .\backend.json

$adminCredential = Get-Credential -UserName 'misha@example.test' -Message 'Новый пароль админки: минимум 12 символов'
$env:MANDATNIK_ADMIN_PASSWORD = $adminCredential.GetNetworkCredential().Password
.\mandatnik-backend.exe admin-create -config .\backend.json -email misha@example.test -name 'Миша' -role superadmin
Remove-Item Env:\MANDATNIK_ADMIN_PASSWORD
Remove-Variable adminCredential
.\mandatnik-backend.exe health -config .\backend.json
```

После каждой команды проверяй отсутствие ошибок. `health` должен вывести `ok`:
это проверка доступности БД, а не запущенного HTTPS. `bootstrap` создаёт БД и
логин, `migrate` — таблицы, `license-init` — ключи шифрования лицензий.
`license-init` выполняется один раз и откажется перезаписывать существующие
ключи. При повторном запуске стенда эти шаги заново не нужны.
`admin-create` для того же email обновляет существующего администратора.

### Повторный запуск уже настроенного сервера

Раздел 5 — **однократная подготовка**. При обычном перезапуске не выполняй
`bootstrap`, `license-init` и `admin-create`, не создавай заново файл пароля.
Администратор и хеш его пароля сохраняются в БД; `admin-create` меняет пароль,
а не запускает сервер. Переменная `MANDATNIK_ADMIN_PASSWORD` нужна только
для создания/изменения администратора, работающему серверу она не требуется.

В новом административном окне достаточно:

```powershell
Set-Location C:\ProgramData\Mandatnik\Backend
.\mandatnik-backend.exe health -config .\backend.json
.\mandatnik-backend.exe run -config .\backend.json
```

Для входа используй прежний email и пароль. Если сервер уже работает через
планировщик, вместо второго процесса выполни `Stop-ScheduledTask -TaskName MandatnikBackend`,
затем `Start-ScheduledTask -TaskName MandatnikBackend` после остановки процесса.

## 6. Запустить сервер

Открой входящие порты для своей тестовой подсети (замени подсеть):

```powershell
New-NetFirewallRule -DisplayName 'Mandatnik test HTTPS' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8443,8444 -RemoteAddress '192.168.1.0/24'
.\mandatnik-backend.exe run -config .\backend.json
```

Оставь окно открытым: закрытие окна или Ctrl+C останавливает сервер.
Открой с сервера или другой машины **https://192.168.1.50:8444/** и войди
по email/паролю из предыдущего шага. На компьютере с браузером тоже установи
`tls-ca.cer` в `LocalMachine\Root`; предупреждений HTTPS быть не должно.
Агентский адрес — порт **8443**, админка — **8444**. Интеграционный порт 8446
в этом примере доступен только локально и для основной проверки не нужен.

Для работы после перезагрузки можно вместо ручного запуска создать задачу
планировщика (сначала останови ручной процесс, чтобы не занять порты дважды):

```powershell
$root = 'C:\ProgramData\Mandatnik\Backend'
$action = New-ScheduledTaskAction -Execute "$root\mandatnik-backend.exe" -Argument "run -config `"$root\backend.json`"" -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName MandatnikBackend -Action $action -Trigger $trigger -Principal $principal -Settings $settings
Start-ScheduledTask -TaskName MandatnikBackend
```

Backend не является Windows-службой SCM: регистрировать его через `sc.exe
create` нельзя. Пароль БД в защищённом файле позволяет задаче SYSTEM читать
его без переменных окружения твоего интерактивного окна.

## 7. Ручная установка агента на АРМ — основной быстрый путь

Скопируй на АРМ собранный MSI и `tls-ca.cer`, например в `C:\MandatnikDeploy`.
Не копируй туда серверные ключи и пароль SQL. Далее — PowerShell администратора
**на АРМ**, не на сервере:

```powershell
$ServerIP = Read-Host 'IPv4-адрес WS из SAN серверного сертификата'
Import-Certificate -FilePath C:\MandatnikDeploy\tls-ca.cer -CertStoreLocation Cert:\LocalMachine\Root
New-Item -ItemType Directory -Force C:\ProgramData\Mandatnik | Out-Null
@{ server_url = "https://${ServerIP}:8443"; request_timeout_seconds = 30 } | ConvertTo-Json | Set-Content -Encoding ascii C:\ProgramData\Mandatnik\agent-config.json

Test-NetConnection $ServerIP -Port 8443
$msi = 'C:\MandatnikDeploy\MandatnikAgent-0.5.0.msi'
$p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart /l*v C:\MandatnikDeploy\install.log" -Wait -PassThru
$p.ExitCode
Get-Service MandatnikAgent
& 'C:\Program Files\Mandatnik\Agent\mandatnik-agent.exe' status
```

Путь MSI поправь под свою версию. Код 0 — успешная установка, 3010 — успешная
установка с требованием перезагрузки; остальные коды разбирай по `install.log`.
MSI запускает службу автоматически от LocalSystem. Если она остановлена,
проверь лог и выполни `Start-Service MandatnikAgent`.
Рабочий конфиг надо создать **до установки**: MSI содержит только пример.
Входящие порты на АРМ открывать не нужно — агент сам обращается к серверу.

### Альтернатива: установка из EXE без MSI

На чистом АРМ после установки корня и создания того же конфига можно поставить
службу непосредственно из EXE. Выбери один способ установки на одной машине:

```powershell
New-Item -ItemType Directory -Force 'C:\Program Files\Mandatnik\Agent' | Out-Null
Copy-Item C:\MandatnikDeploy\mandatnik-agent.exe 'C:\Program Files\Mandatnik\Agent\mandatnik-agent.exe'
& 'C:\Program Files\Mandatnik\Agent\mandatnik-agent.exe' install -config C:\ProgramData\Mandatnik\agent-config.json
& 'C:\Program Files\Mandatnik\Agent\mandatnik-agent.exe' start
& 'C:\Program Files\Mandatnik\Agent\mandatnik-agent.exe' status
```

EXE должен оставаться по этому пути: служба запускает именно его. Для проверки
поведения в реальной эксплуатации используй службу LocalSystem. Команда `run`
запускает процесс в контексте текущего пользователя и не заменяет эту проверку.

## 8. Альтернатива: раскатка через GPO

Нужна доменная тестовая OU с выбранными компьютерами. Сервер приложения при
этом не обязан быть контроллером домена.

1. Создай сетевую папку, например `\\FILESERVER\MandatnikDeploy`. Размести там
   MSI под именем **`MandatnikAgent.msi`** и `agent-config.json` из раздела 7.
   Компьютерным учётным записям тестовых АРМ нужны права чтения **и на шару,
   и NTFS**; запись оставь только администраторам развёртывания.
2. Создай отдельную GPO, привяжи к тестовой OU. Через **Computer Configuration
   → Policies → Windows Settings → Security Settings → Public Key Policies →
   Trusted Root Certification Authorities** импортируй только `tls-ca.cer`.
3. Возьми `deploy\gpo\install-mandatnik.ps1` и `install-mandatnik.cmd` из кода.
   В копии PS1 замени `$share` с `\\SERVER-WINDOWS\MandatnikDeploy` на свою шару.
4. В этой GPO открой **Computer Configuration → Policies → Windows Settings →
   Scripts (Startup/Shutdown) → Startup → Show Files**, скопируй туда оба
   скрипта и через **Add** добавь `install-mandatnik.cmd` как startup script.
   Настраивай через редактор GPO: он зарегистрирует нужное расширение и версии.
5. Для доступности шары при старте включи **Computer Configuration → Policies →
   Administrative Templates → System → Logon → Always wait for the network
   at computer startup and logon**.
6. На тестовом АРМ выполни `gpupdate /force` и перезагрузи его. Если корень ещё
   не успел примениться при первом старте, после применения политики перезапусти
   службу агента. Проверь `gpresult /r /scope computer`, службу и админку.

Скрипт копирует конфиг, ставит MSI, если EXE ещё нет, и запускает службу.
**Автоматическое обновление уже установленного EXE этот скрипт не выполняет**:
для upgrade запусти новый MSI отдельно. Он также не ставит CSP и сертификаты
пользователей. Держи исходный MSI доступным для Windows Installer repair.
Логи: `C:\ProgramData\Mandatnik\gpo-install.log`,
`C:\Windows\Temp\mandatnik-gpo-msi.log`, `mandatnik-gpo-wrapper.log` в той же Temp.
Подробности ручного формирования GPO: [deploy/gpo/README.md](deploy/gpo/README.md).

## 9. Что проверить как проверяющий

1. В админке появился АРМ с правильным именем. Первый сбор идёт после
   регистрации; обновление статуса/задач по умолчанию опрашивается раз в 60 с.
2. В карточке видны результаты инвентаризации сертификатов и CSP (если он
   установлен), время последнего сбора и ошибки/неполнота сбора, если они есть.
3. Запусти ручной сбор из интерфейса и дождись завершения задания и новой даты
   отчёта. Плановый сбор по умолчанию раз в сутки — для проверки не надо ждать день.
4. Для проверки файлов `.cer` создай на АРМ папку `C:\MandatnikTestCerts`,
   скопируй туда выбранные публичные сертификаты из
   `test-data\certificates-2026-11-14`, создай в админке политику папок с правилом
   `C:/MandatnikTestCerts/`, назначь её машине или её группе и запусти новый сбор.
   Без назначенной политики агент папки не обходит. Ожидаемые данные сертификатов
   описаны в README/манифесте указанного набора.
5. Для проверки личного хранилища импортируй выбранный публичный `.cer` в
   `Cert:\CurrentUser\My` под тестовым пользователем, затем проверь сбор при
   входе и после выхода этого пользователя. Закрытые ключи для инвентаризации
   не нужны; тестовый ГОСТ-УЦ в доверенные корни устанавливать не надо.
6. Перезагрузи АРМ: служба должна подняться, карточка остаться той же.
   При включённой задаче сервера проверь и перезагрузку сервера.
7. Повтори установку/repair или обновление MSI: идентичность АРМ и история
   должны сохраниться. После обычного удаления и повторной установки тоже
   используется прежнее состояние.

Новая чистая установка с именем уже существующего АРМ может попасть в
**«АРМ → Ожидают подтверждения»**: подтверди замену в интерфейсе. Это ожидаемый
сценарий, а не повод удалять БД. Не копируй `ProgramData\Mandatnik\Agent`
с одной машины на другую и не клонируй уже зарегистрированный агент в шаблон VM.

Проверку удалённой установки лицензии делай отдельно на тестовой VM с CSP
и подходящим действительным ключом: она меняет лицензию CSP. Для обычной
проверки сборки, развёртывания и инвентаризации этот шаг не требуется.
Сценарий: [docs/acceptance/REMOTE-ACTIVATION-0.5.0.md](docs/acceptance/REMOTE-ACTIVATION-0.5.0.md).

## 10. Если что-то не работает

| Симптом | Что проверить |
| --- | --- |
| Сборка не видит команды | Новое окно PowerShell, PATH, версии Go/Node/Make; текущая папка `mandatnik` |
| PowerShell запрещает сборочный PS1 | Для текущего окна при допустимой политике организации: `Set-ExecutionPolicy -Scope Process Bypass`; доменную политику это не переопределяет |
| WiX/ICE завершился ошибкой | Полный WiX 3.14.1, .NET Framework, лог сборки; для неинтерактивной сборки повышенные права/контекст SYSTEM |
| SQL connection refused/timeout | Служба SQL, TCP/IP, фиксированный 1433, `Test-NetConnection`, перезапуск SQL после настройки |
| SQL login failed | Mixed Mode, включённый `sa`, правильный пароль, файл `db-password.txt`; bootstrap может обновлять пароль существующего `mandatnik_app` |
| Ошибка SQL TLS | В тестовом локальном варианте нужны оба флага из примера; при строгой проверке — CA, SAN и `server_name` |
| Браузер: ERR_CERT_COMMON_NAME_INVALID | Сравни адрес в URL с `openssl x509 -in tls\backend.crt -noout -ext subjectAltName`. В присланном сертификате есть только 192.168.189.138; другой адрес требует перевыпуска серверного сертификата и перезапуска backend. Корневой УЦ менять не требуется, если сохранился его ключ |
| `undefined: machineOffline` в тестах | Ошибка исходников, не прав Windows. В текущем коде функция присутствует в `internal/backend/store/admin.go`; обнови полную согласованную ревизию исходников и повтори `make check`. Не пропускай ошибку |
| Агент: x509/unknown authority | Корень в `LocalMachine\Root` именно на АРМ, совпадение SAN с URL, срок сертификата и время |
| АРМ не появился | Порт 8443, адрес без localhost, конфиг до установки, служба, очередь ожидающих подтверждения |
| Нет сертификатов из папки | Наличие файлов на АРМ, назначенная политика, доступ SYSTEM, новый ручной сбор |
| Нет доступа к админке | Сервер работает, порт 8444, firewall, корень в доверенных на машине браузера |

Диагностика на АРМ, из административного PowerShell:

```powershell
& 'C:\Program Files\Mandatnik\Agent\mandatnik-agent.exe' diag
Get-Content C:\ProgramData\Mandatnik\Agent\logs\current.txt -Tail 100
```

Лог сервера: `C:\ProgramData\Mandatnik\Backend\logs\backend.txt`.
Если потребуется разбор, передай ревизию/`build-info.json`, версии EXE, шаг,
текст ошибки, соответствующий лог и код msiexec. Пароли, `*.key`, keyring,
`identity.dpapi` и остальные DPAPI-файлы пересылать не нужно.

## 11. Остановка и удаление тестовой установки

Сначала отключи startup-скрипт GPO для тестового АРМ, иначе он поставит агент
снова при следующей загрузке. Обычное удаление сохраняет состояние агента:

```powershell
& 'C:\Program Files\Mandatnik\Agent\mandatnik-agent.exe' uninstall
```

Полный сброс нужен только при намеренной проверке новой установки:
`uninstall -purge` удаляет идентичность, ключи, очередь и журнал. Внешний
`agent-config.json` сохраняется. После сброса при занятом имени потребуется
подтверждение новой установки в админке.

Сервер останови Ctrl+C либо `Stop-ScheduledTask -TaskName MandatnikBackend`;
для отмены автозапуска — `Unregister-ScheduledTask -TaskName MandatnikBackend`.
БД и серверные ключи при этом не удаляются. Если стенд нужен для повторной
проверки, сохрани БД вместе с `license-keyring.json` и
`license-fingerprint.key`: без этих файлов номера лицензий из БД не восстановить.

# Разработка, ручная сборка и CI/CD

Все проверки и сборки запускаются из корня репозитория через **GNU Make**.
Makefile работает в Linux и Windows: реализацию команд выполняет Go-инструмент
`tools/build`, без зависимости от Bash, sed, cp или rm на Windows.

## Инструменты

| Инструмент | Требование / проверенная версия |
|---|---|
| GNU Make | 4.x; на стенде 4.4.1 |
| Go | 1.26+; CI зафиксирован на 1.26.3 |
| Node.js + npm | Node 22 LTS или новее; CI: 22.22.3 |
| Git | 2.34+; нужен также для метаданных сборки |
| WiX Toolset | **3.14.1**, нужен только на Windows-сборщике MSI |
| OpenSSH client | Только для удалённой MSI-сборки из Linux |
| SQL Server + стендовый конфиг | Только для integration / test-e2e |

КриптоПро, его SDK и SQL Server не требуются для unit-тестов и сборки.
Зависимости Go фиксируются `go.sum`, фронтенда — `frontend/package-lock.json`.
`make frontend` выполняет `npm ci`, затем Vite production build; сборка EXE
проверяет `go mod verify`. Бандл включается в бэкенд, CDN не используется.

### Linux (Ubuntu/Debian)

```sh
sudo apt-get update
sudo apt-get install -y make git curl ca-certificates xz-utils openssh-client
```

Go устанавливается из [официального архива](https://go.dev/dl/), Node.js — из
[официального дистрибутива](https://nodejs.org/en/download). Для Linux amd64,
как на CI-стенде:

```sh
curl -fSLO https://go.dev/dl/go1.26.3.linux-amd64.tar.gz
# SHA-256 сверить с go.dev/dl перед распаковкой.
sudo tar -C /usr/local -xzf go1.26.3.linux-amd64.tar.gz
curl -fSLO https://nodejs.org/dist/v22.22.3/node-v22.22.3-linux-x64.tar.xz
# SHA-256 сверить с SHASUMS256.txt того же официального каталога.
sudo tar -C /opt -xJf node-v22.22.3-linux-x64.tar.xz
export PATH="/usr/local/go/bin:/opt/node-v22.22.3-linux-x64/bin:$PATH"
make --version
go version
node --version
npm --version
```

Добавьте PATH в профиль оболочки. Для ARM64 выберите соответствующие архивы;
целевые продуктовые EXE всё равно собираются для Windows amd64.

### Windows 10 / Windows Server

Установите [Chocolatey](https://chocolatey.org/install), затем в PowerShell
администратора:

```powershell
choco install -y make git golang nodejs-lts
```

Либо установите Go/Node/Git официальными установщиками, а GNU Make — пакетом
`make`. После установки откройте **новый** PowerShell и проверьте:

```powershell
make --version
go version
node --version
npm --version
git --version
```

Для MSI распакуйте
[WiX 3.14.1 binaries](https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip)
в каталог, например `C:\Tools\wix314`. В нём должны быть `candle.exe`,
`light.exe`, `WixUtilExtension.dll` и остальные файлы архива.

```powershell
$env:WIX_DIR = 'C:\Tools\wix314'
make package
```

WiX 3.14 использует .NET Framework 4.x; на Windows 10 / Server 2022 он обычно
уже установлен. Windows SSH-сборщику также нужен OpenSSH Server и доступ
пользователя к временному каталогу и WiX.

Команды запускаются в обычном PowerShell или cmd.exe; Git Bash/WSL не нужны.
Makefile выбирает cmd.exe для рецептов Windows. Сборка не устанавливает MSI
и не требует прав администратора; права нужны при установке инструментов
в системные каталоги и при установке самого агента.

## Команды

```sh
make help
make deps         # Go modules + npm ci
make test-unit    # также make unit / make test
make lint         # go vet
make check        # unit + vet; без доступа к инфраструктуре
make build        # Vue + три Windows amd64 EXE
make msi          # MSI из уже собранного EXE
make package      # Vue + EXE + MSI
make clean        # только выбранный каталог сборки
```

Результаты по умолчанию в `artifacts/ci/`:

- `telehack-agent.exe`, `telehack-backend.exe`, `telehack-acceptance.exe`;
- `TelehackAgent-<version>.msi` после MSI-сборки;
- `build-info.json`, `SHA256SUMS`.

`make build` на Linux выполняет кросс-сборку Windows EXE. Linux-агент не
объявляется готовым: целевая первая платформа продукта — Windows 10.
`make binaries` использует уже существующий embedded-бандл и не требует Node.
Не запускайте отдельные изменяющие бандл/артефакты make-команды параллельно
в одном checkout. `make -j build` сам соблюдает порядок frontend → EXE.

Параметры передаются одинаково в обеих ОС:

```sh
make build OUT_DIR=artifacts/my-build
make build COMMIT=local-check BUILD_DATE=2026-11-14T00:00:00Z
make msi WIX_DIR="C:/Tools/wix314"
```

Версия берётся из `internal/version/version.go`. При изменении версии MSI
получает другой стабильный ProductCode; UpgradeCode не меняется. Для 0.4.0
сохранён ранее выпущенный ProductCode. `VERSION`, если указан, должен совпадать
с версией продукта. `PRODUCT_CODE` позволяет явно задать MSI GUID.

### MSI из Linux

Сам WiX 3.14 запускается на Windows. Для полной сборки из Linux нужен Windows
SSH-сборщик с WiX и разрешённым входом по ключу:

```sh
make package MSI_HOST=builder@windows-build WIX_DIR="C:/Tools/wix314"
# Для нестандартного порта используйте общий для ssh/scp параметр -o:
make msi MSI_HOST=builder@windows-build MSI_SSH_ARGS="-o Port=2222"
```

Передаются только EXE агента, WXS, сборочный PowerShell-скрипт и пример
конфигурации. MSI создаётся в отдельном временном каталоге Windows, скачивается
в OUT_DIR, затем временный каталог удаляется. Идентичность агента и секреты
в архив не включаются. Без MSI_HOST Linux-команда msi завершится понятной
ошибкой; она не выдаёт фиктивный MSI и не требует Wine.

## Интеграционные и конечные тесты

```sh
make integration E2E_CONFIG=/absolute/path/acceptance.json
make test-e2e E2E_CONFIG=/absolute/path/acceptance.json
```

В Windows:

```powershell
make test-e2e E2E_CONFIG="C:/TelehackCI/private/acceptance.json"
```

Используйте только согласованный тестовый SQL Server. Конфиг соответствует
`docs/stand-setup.md`: `server_url`, `ca_file`, `db` с адресом, именем БД,
runtime-логином, `password_file`, SQL TLS CA и именем сервера. Все файловые
пути в нём должны быть абсолютными и доступными пользователю тестов.
Конфиг и пароль хранятся вне Git; примеры секретов не публикуются.
Без E2E_CONFIG команда завершается ошибкой, а не пропускает проверку.

`make integration` запускает реальные SQL-проверки миграций, групп, политик,
транзакционных откатов и эффективных конфигураций.

`make test-e2e` дополнительно собирает и запускает **новый бэкенд из текущих
исходников** на временных loopback-портах с временным TLS-сертификатом.
Контрактный клиент проверяет подписанный HTTPS-протокол, повторы, отчёты,
исчезновения, частичные результаты, переименование и задания с реальной БД.
После проверки процесс и временные TLS-ключи удаляются. Работающий бэкенд
стенда не заменяется. Результаты — `evidence/local/ci/` или EVIDENCE_DIR.

Проверка временно меняет общие настройки тестовой БД и создаёт синтетические
записи; клиент восстанавливает настройки и удаляет свои записи. Запускайте
её последовательно на выделенном стенде. CI сериализует такие запуски и не
отменяет предыдущий запуск при новом push.

Эти тесты не устанавливают MSI на рабочие станции и не меняют лицензии CSP.
Проверка службы, невошедших профилей и установки/удаления MSI описана отдельно
в `docs/acceptance/P07.md`, `P09.md`, `POLICIES-0.4.0.md`.

## Gitea Actions и поставка

Репозиторий: `http://10.10.26.11/pdoexception/telehack2026`.
Workflow `.gitea/workflows/ci.yml`:

1. Linux: `make check`, `make build`, EXE как артефакт запуска.
2. Windows: `make check`, `make package`, MSI/EXE как артефакт запуска.
3. На main и тегах v*: `make test-e2e` с приватным конфигом раннера.
4. На теге vX.Y.Z: `make publish`, поставка файлов в Gitea Release.

Произвольный push ветки выполняет проверки и сборку без обращения к SQL-стенду.
Ручной workflow `acceptance.yml` позволяет отдельно проверить выбранную ревизию.
CI не устанавливает агент автоматически на машины кейсодержателя: результат
поставки — скачиваемые EXE/MSI и контрольные суммы.

Раннеры 5.2.0 зарегистрированы **только в этом репозитории**:

- `telehack-linux-140`: Ubuntu, `telehack-linux:host`, пользователь mimbol,
  `~/telehack-ci/`, автозапуск через его `crontab @reboot` и flock.
- `telehack-windows-138`: Windows Server, `telehack-windows:host`, LocalService,
  `C:\TelehackCI\`, задача планировщика `TelehackGiteaRunner` при старте ОС.

Host-раннеры предназначены для доверенного кода этого приватного репозитория.
Windows-конфиг SQL — в ACL-защищённом `C:\TelehackCI\private\acceptance.json`,
путь передаётся через TELEHACK_E2E_CONFIG. Пароль — отдельным защищённым файлом.
Runner registration tokens и `.runner` не хранятся в Git и не попадают
в артефакты. В каждом раннере capacity=1; логи задач сохраняются 7 дней.

Примеры конфигурации и автозапуска — `deploy/ci/`.
Официальные документы: [установка раннера](https://docs.gitea.com/runner/installation/binary/),
[регистрация](https://docs.gitea.com/runner/2/registration/),
[артефакты](https://docs.gitea.com/usage/actions/artifacts/).

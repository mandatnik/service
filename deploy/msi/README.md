# MSI агента

Источник MSI — WiX Toolset 3.14.1 (XML, `candle`/`light`). MSI не содержит
UUID, ключей, паролей или тестовых сертификатов: идентичность и DPAPI-ключ
создаются службой на конкретной машине.

## Инструмент

```text
WiX 3.14.1: https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip
```

Проверенная установка на стенде:

```text
C:\ProgramData\Mandatnik\build-tools\wix314
```

`build-msi.ps1` использует этот каталог по умолчанию. WiX требует .NET
Framework; runtime-зависимостей у самого агента нет (Go, CGO=0).

## Сборка

Сначала соберите Windows-агент:

```powershell
$env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
go build -trimpath -ldflags "-s -w" -o bin\mandatnik-agent.exe .\cmd\agent
```

Затем MSI:

```powershell
.\deploy\msi\build-msi.ps1 `
  -AgentExe .\bin\mandatnik-agent.exe `
  -ProductVersion 0.4.0 `
  -ProductCode '{35F44613-8F88-4599-8D86-C901BB368F47}' `
  -Output .\artifacts\MandatnikAgent-0.4.0.msi
```

`UpgradeCode` зафиксирован в WXS:
`{B1DDABDF-2151-4A9D-9E0C-6BC30E9E9BDB}`.

Версии/ProductCode:

| Версия | ProductCode |
| --- | --- |
| 0.2.0 (базовая для проверки upgrade) | `{F32AB857-DFF9-4FE9-8694-E5858ED51316}` |
| 0.4.0 (текущая) | `{35F44613-8F88-4599-8D86-C901BB368F47}` |
| 0.3.0 | `{64E20BF5-DDF6-4704-9374-E175CA30152F}` |

## Что устанавливает MSI

- `mandatnik-agent.exe` в `C:\Program Files\Mandatnik\Agent`.
- Службу `MandatnikAgent`, `LocalSystem`, автоматический запуск, recovery
  actions через `service-config` custom action.
- `C:\ProgramData\Mandatnik\Agent\{logs,queue}` с DACL только SYSTEM и
  Administrators.
- Пример `agent-config.example.json`; **рабочий**
  `C:\ProgramData\Mandatnik\agent-config.json` не входит в MSI и не
  перезаписывается. Его создаёт администратор или GPO.
- В MSI нет CryptoPro, браузерного плагина, пользовательских сертификатов,
  тестового корневого сертификата, UUID и приватных ключей.

## Установка, repair, upgrade, uninstall

```powershell
# молчаливая установка/обновление
msiexec /i .\MandatnikAgent-0.4.0.msi /qn /norestart /l*v install.log

# repair (источник MSI должен быть доступен)
msiexec /f {64E20BF5-DDF6-4704-9374-E175CA30152F} /qn /norestart /l*v repair.log

# удаление через CLI агента: сохраняет identity/state, затем вызывает msiexec /x
& 'C:\Program Files\Mandatnik\Agent\mandatnik-agent.exe' uninstall

# полное удаление с явной очисткой identity, ключей, очереди и журнала
& 'C:\Program Files\Mandatnik\Agent\mandatnik-agent.exe' uninstall -purge

# стандартное MSI-удаление (например, Add/Remove Programs) сохраняет состояние
msiexec /x {64E20BF5-DDF6-4704-9374-E175CA30152F} /qn /norestart
```

`uninstall` без `-purge` — обычное удаление продукта: identity, DPAPI-ключи,
очередь и журнал остаются, поэтому повторная установка не создаёт новую
машину молча. Только `uninstall -purge` выполняет полную очистку состояния
перед MSI uninstall. Стандартный MSI uninstall также сохраняет
`C:\ProgramData\Mandatnik`; GPO-конфиг не является собственностью MSI.

`repair`/upgrade не должны удалять `AgentDir`: в WXS это учтено; состояние
проверяется отдельно. Большой `RemoveFolderEx` намеренно не используется,
потому что он выполнялся при repair и мешал восстановлению.

## Безопасность

MSI не подписан (тестовый стенд). Для production необходима подпись
Authenticode; до этого распространять только по защищённому каналу и
проверять SHA-256 из `SHA256SUMS`.

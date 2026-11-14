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
C:\ProgramData\Telehack2026\build-tools\wix314
```

`build-msi.ps1` использует этот каталог по умолчанию. WiX требует .NET
Framework; runtime-зависимостей у самого агента нет (Go, CGO=0).

## Сборка

Сначала соберите Windows-агент:

```powershell
$env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
go build -trimpath -ldflags "-s -w" -o bin\telehack-agent.exe .\cmd\agent
```

Затем MSI:

```powershell
.\deploy\msi\build-msi.ps1 `
  -AgentExe .\bin\telehack-agent.exe `
  -ProductVersion 0.4.0 `
  -ProductCode '{35F44613-8F88-4599-8D86-C901BB368F47}' `
  -Output .\artifacts\TelehackAgent-0.4.0.msi
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

- `telehack-agent.exe` в `C:\Program Files\Telehack2026\Agent`.
- Службу `TelehackAgent`, `LocalSystem`, автоматический запуск, recovery
  actions через `service-config` custom action.
- `C:\ProgramData\Telehack2026\Agent\{logs,queue}` с DACL только SYSTEM и
  Administrators.
- Пример `agent-config.example.json`; **рабочий**
  `C:\ProgramData\Telehack2026\agent-config.json` не входит в MSI и не
  перезаписывается. Его создаёт администратор или GPO.
- В MSI нет CryptoPro, браузерного плагина, пользовательских сертификатов,
  тестового корневого сертификата, UUID и приватных ключей.

## Установка, repair, upgrade, uninstall

```powershell
# молчаливая установка/обновление
msiexec /i .\TelehackAgent-0.4.0.msi /qn /norestart /l*v install.log

# repair (источник MSI должен быть доступен)
msiexec /f {64E20BF5-DDF6-4704-9374-E175CA30152F} /qn /norestart /l*v repair.log

# удаление через CLI агента: останавливает службу, удаляет
# AgentDir (identity/DPAPI/queue/logs), затем вызывает msiexec /x
& 'C:\Program Files\Telehack2026\Agent\telehack-agent.exe' uninstall

# стандартное MSI-удаление (например, Add/Remove Programs)
msiexec /x {64E20BF5-DDF6-4704-9374-E175CA30152F} /qn /norestart
```

CLI-удаление — предусмотренный интерфейс полного удаления: оно удаляет
состояние агента перед штатным MSI uninstall. Стандартный MSI uninstall
удаляет продукт и службу; GPO-конфиг и каталог `C:\ProgramData\Telehack2026`
не являются собственностью MSI и сохраняются.

`repair`/upgrade не должны удалять `AgentDir`: в WXS это учтено; состояние
проверяется отдельно. Большой `RemoveFolderEx` намеренно не используется,
потому что он выполнялся при repair и мешал восстановлению.

## Безопасность

MSI не подписан (тестовый стенд). Для production необходима подпись
Authenticode; до этого распространять только по защищённому каналу и
проверять SHA-256 из `SHA256SUMS`.

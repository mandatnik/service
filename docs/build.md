# Сборка и воспроизводимость

## 1. Зафиксированные версии

| Компонент | Версия | Проверено |
| --- | --- | --- |
| Go | 1.26.3 (go.mod: 1.26.0) | macOS arm64, Windows amd64 |
| Node.js | 22.22.3 | macOS arm64 |
| Vue | 3.5.45 | P08 |
| Vite | 6.4.6 | P08 |
| `@vitejs/plugin-vue` | 5.2.4 | P08 |
| SQL Server | 2019 Express 15.0.2000.5 | Windows Server 2022 |
| КриптоПро CSP | 5.0.13003 / 4.0.9963 | Windows 10 19045 |
| WiX Toolset | 3.14.1 | Windows Server 2022 |

Go-зависимости фиксируются в `go.mod`/`go.sum`; frontend — в
`frontend/package-lock.json`. `go mod verify` и `npm ci` обязательны.
`cpro-go`/`gost-ca` не импортируются продуктом.

## 2. Backend/agent (без Node)

```bash
go mod download
go vet ./...
go test ./...
go build -trimpath -o bin/telehack-agent ./cmd/agent
go build -trimpath -o bin/telehack-backend ./cmd/backend
go build -trimpath -o bin/telehack-acceptance ./cmd/acceptance
```

Админка уже лежит в `internal/backend/web/dist` (закоммичена). Backend EXE
собирается без Node и содержит ровно три файла: `index.html`, `app.css`,
`app.js`.

## 3. Кросс-сборка для стенда

```bash
COMMIT=$(git rev-parse --short HEAD)
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w \
  -X telehack2026/internal/version.Commit=$COMMIT \
  -X telehack2026/internal/version.BuildDate=$BUILD_DATE" \
  -o bin/telehack-agent.exe ./cmd/agent

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w \
  -X telehack2026/internal/version.Commit=$COMMIT \
  -X telehack2026/internal/version.BuildDate=$BUILD_DATE" \
  -o bin/telehack-backend.exe ./cmd/backend
```

Проверка:

```bash
file bin/telehack-agent.exe bin/telehack-backend.exe
shasum -a 256 bin/telehack-agent.exe bin/telehack-backend.exe
```

## 4. Frontend

```bash
cd frontend
npm ci
npm run build
```

Результат — `internal/backend/web/dist/{index.html,app.css,app.js}`.
Vite настроен на `entryFileNames: app.js`, `assetFileNames: app.[ext]`,
`cssCodeSplit: false`; динамических чанков нет. После изменения исходников
пересоберите и закоммитьте `dist`.

## 5. MSI

См. `deploy/msi/README.md`. Кратко:

```powershell
.\deploy\msi\build-msi.ps1 `
  -AgentExe .\bin\telehack-agent.exe `
  -ProductVersion 0.3.0 `
  -ProductCode '{64E20BF5-DDF6-4704-9374-E175CA30152F}' `
  -Output .\artifacts\TelehackAgent-0.3.0.msi
```

WiX 3.14.1:
`https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip`.
MSI не содержит идентичности/ключей; состояние создаётся службой. GPO-скрипт
и требования к `scripts.ini`/extension names — `deploy/gpo/README.md`.

## 6. Воспроизводимая проверка из чистого clone

```bash
git clone <repo> /tmp/telehack2026-fresh
cd /tmp/telehack2026-fresh
go mod verify
go test ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /tmp/telehack-agent.exe ./cmd/agent
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /tmp/telehack-backend.exe ./cmd/backend
(cd frontend && npm ci && npm run build)
# на Windows с WiX:
# build-msi.ps1 из этого же clone
```

`go.sum` и `frontend/package-lock.json` должны соответствовать исходникам.
Сборка без `dist` невозможна намеренно: админка является частью backend.

## 7. Свежий clone P10

Проверено на `/tmp/telehack2026-fresh-p10` из Gitea:

- `go mod verify` — all modules verified;
- `go test ./...` — PASS;
- `npm ci && npm run build` — три файла, совпадающие с закоммиченным `dist`;
- Windows backend/agent пересобраны; fresh backend `health` вернул `ok`;
  fresh agent `version` — `0.3.0 (commit 41e8968)`;
- MSI пересобран из fresh clone (`deploy/msi/build-msi.ps1`).

Байтовый SHA-256 Go EXE зависит от VCS stamping (`vcs.revision`,
`vcs.modified`): published-артефакты собраны из рабочего дерева вокруг
коммита `41e8968`, fresh clone имеет другой VCS stamp. Для побайтово
воспроизводимой будущей сборки используйте `-buildvcs=false` и фиксируйте
`Commit`/`BuildDate`. MSI также содержит кабинетные timestamp-поля; хеш
свежей сборки MSI поэтому не обязан совпадать с опубликованным. Код и
поведение при этом те же; приемочные артефакты и их хеши перечислены в
`artifacts/SHA256SUMS` и `docs/acceptance/P09.md`.

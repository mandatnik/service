# Сборка и воспроизводимость

## 1. Зафиксированные версии

| Компонент | Версия | Проверено |
| --- | --- | --- |
| Go | 1.26.3 (go.mod: 1.26.0) | macOS arm64, Windows amd64 |
| Node.js | 22.22.3 (только frontend P08) | macOS arm64 |
| SQL Server | 2019 Express 15.0.2000.5 RTM | Windows Server 2022 |
| КриптоПро CSP | 5.0.13003 / 4.0.9963 | Windows 10 19045 |

Go-зависимости фиксируются в `go.mod` и `go.sum`. CGO не требуется.
`node_modules/` не является источником продуктовых зависимостей: `cpro-go`
и `gost-ca` не импортируются продуктом (см. `docs/decisions.md`, D02).

## 2. Локальная сборка и тесты

```bash
go mod download
go vet ./...
go test ./...
go build -trimpath -o bin/telehack-agent ./cmd/agent
go build -trimpath -o bin/telehack-backend ./cmd/backend
go build -trimpath -o bin/telehack-acceptance ./cmd/acceptance
```

## 3. Кросс-сборка для стенда

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w -X telehack2026/internal/version.Commit=$(git rev-parse --short HEAD) -X telehack2026/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o bin/telehack-agent.exe ./cmd/agent

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w -X telehack2026/internal/version.Commit=$(git rev-parse --short HEAD) -X telehack2026/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o bin/telehack-backend.exe ./cmd/backend
```

Проверка артефактов:

```bash
file bin/telehack-agent.exe bin/telehack-backend.exe
shasum -a 256 bin/telehack-agent.exe bin/telehack-backend.exe
```

Агент не требует mingw: WinAPI вызывается через `syscall`/`x/sys/windows`,
COM — через `go-ole`. Это позволяет собрать EXE на любом хосте с Go.

## 4. Воспроизводимая сборка из чистого clone

```bash
git clone <repo> /tmp/telehack2026-fresh
cd /tmp/telehack2026-fresh
go mod verify
go test ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /tmp/telehack-agent.exe ./cmd/agent
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /tmp/telehack-backend.exe ./cmd/backend
```

`go.sum` должен совпасть; изменения `go.mod` без `go.sum` не коммитятся.

## 5. Frontend (P08, вне текущего объёма)

`frontend/` содержит каркас Vue + Vite. Сборка в один HTML/CSS/JS и embed
в backend EXE выполняются в P08. Для P07 Node.js не требуется.

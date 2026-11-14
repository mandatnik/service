# Приёмка удалённой активации и задач 0.5.0

Дата: 14.11.2026. Спецификация:
[remote-activation-and-tasks.md](../plans/remote-activation-and-tasks.md).

## Что проверено

### Go unit и контракты

```text
go test ./...                 PASS
go vet ./...                  PASS
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...   PASS
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c ./internal/agent ./internal/agent/winapi  PASS
```

Покрыты:

- четыре списка классификации, default/disabled/trial, несовместимости,
  суточная свежесть и неизвестная привязка провайдера;
- RSA-3072 + RSA-OAEP-SHA256 + AES-256-GCM: перестановка task/item/machine/
  registration/kind/expiry/key_id, изменённый nonce/ciphertext и чужой ключ;
- нормализация/маска номера, отсутствие полного номера в маске;
- legacy-проекция `AgentConfig` и отдельный хеш для `schedule_v2`;
- keyring AES-GCM, отдельный HMAC fingerprint, ротация с сохранением старых
  ключей, отказ при слабых правах файла;
- повреждение task journal: архив, маркер `corrupt_at`, отсутствие plaintext
  номера в DPAPI-файле, сохранение счётчика попыток;
- агрегаты состояний задач, включая `requires_attention` и поздние события;
- OLE zero date `1899-12-30` → perpetual, не expired;
- реальный CryptoAPI context: CryptoPro/Microsoft/unknown provider names,
  `private_key_state=not_checked` (Windows test собран, запуск — на стенде).

### SQL Server 2019 (реальный стенд)

```text
TELEHACK_POLICY_TEST_CONFIG="$PWD/.secrets/acceptance.json" \
  go test ./internal/backend/store -run TestPoliciesSQLServer -v
# PASS: migrations 0004/0005 applied, повторная миграция безопасна

TELEHACK_POLICY_TEST_CONFIG="$PWD/.secrets/acceptance.json" \
  go test ./internal/backend/store -run TestTasksSQLServer -v
# PASS: 9 SQL integration subtests
```

Подтесты:

- preview, атомарный резерв двух ключей и идемпотентное создание задачи;
- legacy `AddJob`/`AckJob` обновляют одно и то же task item;
- дефицит: вся задача отклонена, частичных task/items/резервов нет;
- claim, затем отмена: начатый item не cancelled, его ключ остаётся reserved;
  неначатый item освобождён;
- истечение срока до старта: item expired, ключ available;
- успешный результат: ключ used, задача completed;
- две конкурентные задачи на один свободный ключ: ровно одна успешна, вторая
  получает `license_deficit`, второй резерв не создан;
- scan success принимается только с существующим report_id, legacy job
  переходит в completed;
- report apply пишет provider binding в наблюдение и сохраняет DER в общем
  certificate без смешивания bindings;
- один DER с CryptoPro binding и Microsoft binding на разных машинах не
  смешивается: первая попадает в list 1, вторая — в list 2.

### Frontend

```text
cd frontend && npm ci && npm run build   PASS
```

Браузерная проверка (Playwright) выполнялась на локальном HTTP-просмотре
собранного embedded-бандла с контрактным mock API, повторяющим ответы backend.
Проверены:

- «Активировать лицензию» рядом с «Добавить в группу»;
- модалка с одним пулом и четырьмя списками;
- list 3 и list 4 disabled, их checkbox неактивны;
- list 2 с select-all; после включения optional возникает дефицит
  «нужно 2, свободно 1», кнопка подтверждения disabled;
- trial в list 1 по умолчанию снят, но checkbox enabled; без лицензии —
  включён;
- пулы лицензий: счётчики, импорт, маска, блокировка;
- задача: агрегаты, детали, журнал, кнопки «Отменить»/«Сверить»;
- настройки: 60 / 86400 / 604800 и их подписи;
- в DOM/ответах mock нет полного номера, только маска.

Скриншоты: [activation-modal.png](../../evidence/remote-activation-0.5.0/activation-modal.png),
[license-pools.png](../../evidence/remote-activation-0.5.0/license-pools.png),
[tasks-detail.png](../../evidence/remote-activation-0.5.0/tasks-detail.png),
[settings.png](../../evidence/remote-activation-0.5.0/settings.png).

## Что не проверено и почему

1. **Реальный положительный ключ.** Отдельный действующий номер для нового
   теста не предоставлялся. WORKSTATION-1 с оплаченной бессрочной лицензией не
   читалась в логи, не менялась и не переносилась. Положительный paid-key E2E
   не заявляется.
2. **Отрицательный Windows E2E на реальной SYSTEM-службе.** Нужна изолированная
   РС или согласованный снимок без действующей лицензии. В этой сессии такой
   снимок не предоставлялся; существующие лицензии не изменялись.
3. **Реальный RSA CryptoPro binding на стенде.** Windows-тест
   `TestProviderBindingsFromRealCertificateContext` собран под Windows, но не
   запускался на стенде. Нельзя заменить реальную привязку подстановкой имени
   провайдера в mock.
4. **E2E новой службы с сервером.** SQL-миграция и store-операции проверены на
   реальном SQL Server; полный HTTPS-цикл нового backend + нового агента на
   Windows не выполнялся в этой сессии.

Эти пункты нужно закрыть на согласованном стенде до заявления production
deployment.

## Миграция и настройка

1. Остановить backend, сделать резервную копию БД.
2. Создать keyring и HMAC-ключ:
   `telehack-backend.exe license-init -config backend.json`.
3. Запустить backend: миграции 0004/0005 применятся автоматически и сохранят
   исторические jobs как tasks с `legacy_job_id` (включая jobs, созданные
   старым backend во время rolling upgrade).
4. Раздать новый агент; старые агенты продолжают штатный sync/scan.
5. Резервная копия: БД + `license-keyring.json` + `license-fingerprint.key`
   раздельно, под ACL backend/Administrators. Без keyring номера не
   восстанавливаются.
6. Ротация: `license-keyring-rotate`, затем перешифрование строк; старый ключ
   не удалять до проверки.

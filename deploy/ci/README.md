# Раннеры Gitea

Рабочая конфигурация, команды ручной сборки и зависимости:
[CONTRIBUTING.md](../../CONTRIBUTING.md).

Проверенный раннер — **Gitea Runner 5.2.0**, Gitea — **1.27.3**.
Бинарники и SHA-256: https://dl.gitea.com/gitea-runner/5.2.0/.
Инструменты стенда: Go 1.26.3, Node 22.22.3, GNU Make 4.4.1, WiX 3.14.1.
Go/Node берутся с go.dev/nodejs.org с проверкой официальных SHA-256;
Windows make — пакет Chocolatey `make` 4.4.1, Git — MinGit 2.56.1.

## Регистрация

В настройках **репозитория**, Actions → Runners, получить registration token.
Сохранить его в закрытом файле; не передавать значением аргумента командной строки.
Скопировать соответствующий example config в `runner/config.yaml` и поправить пути.

```sh
gitea-runner register --no-interactive --config config.yaml \
  --instance http://10.10.26.11 --token-file /private/registration.token \
  --name telehack-linux-140 --labels telehack-linux:host
```

Для Windows аналогично, имя `telehack-windows-138`, label `telehack-windows:host`.
Конфигурация уже содержит label и имеет приоритет перед параметром `--labels`.
После регистрации удалить исходный token-файл; `.runner` остаётся закрытым.

## Запуск Linux

`start-linux.example.sh` показывает проверенный PATH и запуск под flock.
Пути заменить под пользователя и место установки инструментов.

```sh
chmod 700 ~/telehack-ci/runner ~/telehack-ci/runner/start.sh
# В crontab текущего пользователя:
# @reboot /home/mimbol/telehack-ci/runner/start.sh
nohup ~/telehack-ci/runner/start.sh >/dev/null 2>&1 </dev/null &
```

На данном стенде mimbol не имеет sudo без пароля, поэтому использован его
`crontab @reboot`; root/systemd-конфигурация сервера не менялась. flock не
позволяет запускать два daemon с одной `.runner`. Лог — `runner/daemon.log`.

## Запуск Windows

`start-windows.example.cmd` запускает daemon без преобразования его stderr
в PowerShell NativeCommandError. Перенесите его в `C:\TelehackCI\runner\start.cmd`.
WiX ICE требует SYSTEM/администратора в неинтерактивном сеансе; -sval не используется.

```powershell
$action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\cmd.exe' `
  -Argument '/d /c C:\TelehackCI\runner\start.cmd' `
  -WorkingDirectory 'C:\TelehackCI\runner'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId SYSTEM `
  -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
  -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName TelehackGiteaRunner -Action $action `
  -Trigger $trigger -Principal $principal -Settings $settings
Start-ScheduledTask TelehackGiteaRunner
```

Корень C:\TelehackCI защищён ACL только SYSTEM и Administrators. Сборочные
инструменты, рабочие каталоги и cache-system не доступны для записи обычным
пользователям. `private/acceptance.json`, SQL пароль и CA находятся здесь же;
никаких секретов в примерах конфигурации нет. .runner и registration token
нельзя копировать между разными раннерами.

Проверка состояния: вкладка Actions → Runners, оба раннера online.
Перезапускать daemon только когда у него нет выполняющегося job.

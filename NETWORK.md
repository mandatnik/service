# Сетевая инфраструктура и WireGuard VPN

Документ описывает текущую инфраструктуру, целевую схему VPN и то, что уже сделано на сервере `mimbol`, а также действия на стороне сервера Михаила.

## 1. Что есть по факту

### 1.1. Сервер `mimbol` (hub)

| Параметр | Значение |
| --- | --- |
| Доступ | `mimbol@192.168.11.34` |
| Фактический интерфейс | `eth0`, `10.10.26.10/24` |
| Шлюз | `10.10.26.1` |
| Публичный IP | `212.220.200.34` |
| ОС | Ubuntu 22.04.5 LTS |
| Hostname | `hackaton-vpn-router` |
| Публикация наружу | gateway-VM `hackaton-edge`: `192.168.11.101` (DHCP) и `192.168.11.34/32`; DNAT на `10.10.26.10` |
| Публичный роутер | Iskratel RT-GM-3, `192.168.11.1`, WAN `212.220.200.34` |

Важно: внутри самой VM адреса `192.168.11.34` нет. Это адрес на gateway-VM `hackaton-edge`, которая DNAT-ит трафик на `10.10.26.10`. Роутер с публичным IP — `192.168.11.1` (RT-GM-3), а не `192.168.9.1`. `192.168.9.1` — нижестоящий роутер, его port-forward не видит `192.168.11.34`.

- снаружи сервер доступен как `212.220.200.34`;
- на RT-GM-3 проброс делается на `192.168.11.101` (DHCP-адрес gateway-VM), а не на `.34`;
- внутри VPN-туннеля hub имеет адрес `10.66.0.1`.

TCP 22 на `212.220.200.34` уже работает. UDP 51820 на момент первой настройки не подтверждён: тест с рабочей машины не показал пакет на `eth0`, но эта машина ходит через прокси/VPN (`utun6`), поэтому результат не окончательный. Локальный тест hub ↔ клиент внутри сервера прошёл: handshake и `ping 10.66.0.1` работают, значит конфиги WireGuard корректны. Внешний порт VPN перенесён на UDP 51830, чтобы не конфликтовать с собственным WireGuard gateway-VM на 51820; внутри hub по-прежнему слушает 51820.

### 1.2. Сеть Михаила

| Параметр | Значение |
| --- | --- |
| Подсеть | `192.168.189.0/24` |
| Маска | `255.255.255.0` |
| Шлюз | `192.168.189.2` |
| Ubuntu Server | `192.168.189.140` |
| Windows Server | `192.168.189.138` |
| Workstation 1 | `192.168.189.136` |
| Workstation 2 | `192.168.189.137` |
| Выход в интернет | через NAT с серым динамическим IP |
| Проброс портов | невозможен |

### 1.3. Клиенты

Рабочие машины разработчиков. Подключаются к публичному адресу `212.220.200.34:51830/udp` и получают адреса из VPN-подсети.

## 2. Целевая схема

Схема «hub-and-spoke»:

```text
              публичный IP 212.220.200.34 (RT-GM-3 192.168.11.1)
                              |
              UDP 51830 / TCP 4444 -> 192.168.11.101
                              |
              hackaton-edge (DNAT) -> 10.10.26.10
                              |
                 +----------------------------+
                 |   hub: wg0 10.66.0.1/24    |
                 |   Ubuntu 22.04             |
                 +-------------+--------------+
                               |
              +----------------+----------------+
              |                                 |
   Михаил: wg0 10.66.0.2/24            Клиенты: 10.66.0.10+
   Ubuntu 192.168.189.140               рабочие машины
              |
   LAN 192.168.189.0/24
   .138 Windows Server, .136/.137 Workstations
```

Ключевые принципы:

1. Публичный endpoint только у hub: `212.220.200.34:51830/udp`.
2. Ubuntu Михаила сам инициирует туннель, потому что у него нет возможности пробросить порт. `PersistentKeepalive = 25` держит NAT-сессию открытой.
3. Hub маршрутизирует `192.168.189.0/24` через peer Михаила.
4. Ubuntu Михаила делает NAT для трафика из VPN в свою LAN, чтобы хосты `192.168.189.0/24` отвечали на `192.168.189.140`.
5. Клиенты тоже сами инициируют туннель и получают доступ к `10.66.0.0/24` и `192.168.189.0/24`.
6. Hub делает NAT для трафика из VPN в свою LAN `10.10.26.0/24` (на случай, если понадобится доступ к сервисам на hub).

## 3. Адресация и порты

| Объект | Адрес | Примечание |
| --- | --- | --- |
| VPN-подсеть | `10.66.0.0/24` | WireGuard |
| Hub | `10.66.0.1/24` | слушает UDP 51820 |
| Ubuntu Михаила | `10.66.0.2/32` | site gateway для `192.168.189.0/24` |
| Клиенты | `10.66.0.10` … `10.66.0.99/32` | выдаются скриптом |
| Публичный endpoint | `212.220.200.34:51830/udp` | RT-GM-3 -> `192.168.11.101:51830` -> `10.10.26.10:51820` |
| LAN Михаила | `192.168.189.0/24` | доступна через туннель |
| LAN hub | `10.10.26.0/24` | доступна через туннель, с NAT на hub |

Маршруты:

- hub → `192.168.189.0/24` через peer Михаила;
- Михаил → `10.66.0.0/24`, `10.10.26.0/24` через hub;
- клиент → `10.66.0.0/24`, `192.168.189.0/24` через hub.

## 4. Что уже сделано на hub

На сервере `10.10.26.10` (доступ через gateway-VM `hackaton-edge` `192.168.11.101`/`.34`) выполнено:

- установлен пакет `wireguard-tools`;
- созданы ключи в `/etc/wireguard/keys` с правами `600`;
- создан `/etc/wireguard/wg0.conf`;
- создан готовый конфиг для Михаила `/etc/wireguard/clients/mikhail.conf`;
- создан пример клиентского конфига `/etc/wireguard/clients/dev-01.conf` (адрес `10.66.0.10`);
- создан скрипт выдачи новых клиентов `/usr/local/sbin/wg-add-client.sh`;
- включён и запущен `wg-quick@wg0`;
- включён `net.ipv4.ip_forward=1` и сохранён в `/etc/sysctl.d/99-wireguard.conf`;
- добавлены правила `iptables` для forwarding и NAT;
- добавлены правила UFW (сам UFW оставлен выключенным).

Публичные ключи:

```text
hub:      EtmsYLJ3xZdQ3W4urs17kKeKLCXop1yAk1zWnjrbYkU=
Михаил:   +Fos8ABMDCfD+DxnmZF0T+BKcVxpY1UDgDdUKJ6b4Hs=
dev-01:   rZ0f3LsL85DqmzjwQdJXGdbeIfBRi8XS88cO6VfK0Ro=
```

Приватные ключи и PSK в этом документе не приводятся. Они лежат только на сервере в `/etc/wireguard/keys` и в конфигах клиентов.

### 4.1. Конфиг hub (приватный ключ и PSK скрыты)

```ini
[Interface]
Address = 10.66.0.1/24
ListenPort = 51820
PrivateKey = <HUB_PRIVATE_KEY>
MTU = 1420

PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT
PostUp = iptables -t nat -C POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE
PostUp = iptables -t nat -C POSTROUTING -s 192.168.189.0/24 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 192.168.189.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -s 192.168.189.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true

[Peer]
# mikhail-ubuntu (192.168.189.140)
PublicKey = +Fos8ABMDCfD+DxnmZF0T+BKcVxpY1UDgDdUKJ6b4Hs=
PresharedKey = <MIKHAIL_PSK>
AllowedIPs = 10.66.0.2/32, 192.168.189.0/24

[Peer]
# dev-01
PublicKey = rZ0f3LsL85DqmzjwQdJXGdbeIfBRi8XS88cO6VfK0Ro=
PresharedKey = <DEV_01_PSK>
AllowedIPs = 10.66.0.10/32
```

### 4.2. Проверка на hub

```bash
sudo wg show
sudo systemctl status wg-quick@wg0
ip route
sudo iptables -t nat -S POSTROUTING
```

Ожидаемо:

- интерфейс `wg0` с адресом `10.66.0.1/24`;
- маршрут `192.168.189.0/24 dev wg0`;
- peer Михаила с `allowed ips: 10.66.0.2/32, 192.168.189.0/24`;
- правила MASQUERADE для `10.66.0.0/24` и `192.168.189.0/24`;
- `wg-quick@wg0` в состоянии `active (exited)` или `active`.

### 4.3. Результаты проверки

Что проверено фактически:

- `wg-quick@wg0` на hub запущен и включён в автозапуск;
- `wg show` на hub показывает peer Михаила (`sJLE...`) и peer `dev-01`;
- маршрут `192.168.189.0/24 dev wg0` присутствует;
- правила MASQUERADE для `10.66.0.0/24` и `192.168.189.0/24` присутствуют;
- на Ubuntu Михаила `wg-quick@wg0` запущен и включён в автозапуск;
- handshake между hub и клиентом есть, transfer растёт;
- `ping 10.66.0.1` с клиента — 3/3;
- `ping 10.66.0.2`, `ping 192.168.189.140`, `ping 192.168.189.138` с hub — успешно;
- SMB `192.168.189.138:445` с hub — открыт;
- MSSQL `192.168.189.138:1433` — таймаут и с клиента, и с hub, то есть SQL Server не слушает 1433 или блокирует Windows Firewall; это не проблема VPN;
- Workstation `.136`/`.137` не отвечают ни по ICMP, ни по SMB 445 даже с самого клиента; скорее всего, выключены или блокируют firewall. ARP-записи на клиенте есть, то есть машины в сети;
- важный нюанс: при эфемерном source port `52563` handshake не проходил, хотя простые UDP-пакеты доходили. После добавления `ListenPort = 51820` в конфиг клиента handshake сразу прошёл. Поэтому `ListenPort = 51820` обязателен для клиентов.

Вывод: VPN работает. Hub видит сеть `192.168.189.0/24`, Windows Server `.138` доступен по SMB. Осталось поднять MSSQL на `.138` (если он нужен) и проверить workstations.

## 5. Проброс на RT-GM-3 (сделано)

### 5.1. Проброс на RT-GM-3

Публичный IP `212.220.200.34` принадлежит роутеру **Iskratel RT-GM-3 `192.168.11.1`**. Именно на нём нужно делать port-forward. Роутер `192.168.9.1` — нижестоящий, его UI не видит `192.168.11.34`.

На RT-GM-3:

```text
UDP 51830 -> 192.168.11.101:51830
TCP 4444  -> 192.168.11.101:4444
```

UDP 51830 — рабочий проброс для VPN. TCP 4444 — временный, был нужен для reverse shell; после настройки его можно удалить.

Почему `192.168.11.101`, а не `.34`: `.101` — это DHCP-адрес gateway-VM `hackaton-edge`, он есть в списке клиентов роутера. `.34` — вторичный IP на той же VM, и UI RT-GM-3 может его не предлагать.

Почему UDP 51830, а не 51820: на `hackaton-edge` уже есть свой WireGuard на UDP 51820 (`wg0` 10.99.0.1/24). Чтобы не ломать его, внешний порт хакатонного VPN — 51830. Внутри hub по-прежнему слушает 51820.

### 5.2. Что уже сделано на gateway-VM `hackaton-edge`

На `hackaton-edge` добавлены правила nftables:

```text
prerouting:  .101:51830 -> 10.10.26.10:51820
prerouting:  .101:4444  -> 10.10.26.10:4444
postrouting: ответы от 10.10.26.10:51820 -> SNAT .101
postrouting: ответы от 10.10.26.10:4444  -> SNAT .101
```

Правила добавлены в живую таблицу `inet mpt` и продублированы systemd-таймером `hackaton-portforward.timer`, который раз в 10 секунд возвращает их, если агент MPT пересоберёт таблицу. Резервная копия исходного ruleset: `/root/nft-backup-hackaton.nft` на `hackaton-edge`.

### 5.3. Проверка

На hub:

```bash
sudo tcpdump -ni eth0 udp port 51820
```

С внешней машины (не из сети `192.168.11.0/24` и лучше не с машины, где включён прокси/VPN):

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"test", ("212.220.200.34", 51830))'
```

Если `tcpdump` показывает пакет — проброс работает. Если нет — проверить правило на RT-GM-3 и DNAT на `hackaton-edge`.

Для reverse shell проверка проще: listener на hub уже слушает TCP 4444. После проброса TCP 4444 с внешней машины:

```bash
nc -vz 212.220.200.34 4444
```

Должно быть `succeeded`.

### 5.4. Если порт блокируется

Для WireGuard не важен номер порта. Можно сделать внешний проброс, например:

```text
UDP 443 -> 192.168.11.101:51830
```

и заменить `Endpoint` в конфигах Михаила и клиентов на `212.220.200.34:443`. На `hackaton-edge` при этом нужно добавить DNAT `.101:443 -> 10.10.26.10:51820` и SNAT ответов на `.101:443`.

## 6. Что сделать на сервере Михаила (`192.168.189.140`)

### 6.1. Установить WireGuard

```bash
sudo apt update
sudo apt install -y wireguard-tools iptables
```

### 6.2. Конфиг

Конфиг уже установлен на сервере Михаила:

```text
/etc/wireguard/wg0.conf
```

Приватный ключ сгенерирован на его сервере и никуда не передавался. Публичный ключ `sJLEffBR1ZP55t11SvfeIKMo2klCJZUd0P1yY9V4uQo=` добавлен на hub в peer `mikhail-ubuntu`. PSK не используется.

Если нужно пересоздать конфиг, используйте шаблон из 6.3. Если Михаил хочет сгенерировать новую пару ключей:

```bash
wg genkey | tee privatekey | wg pubkey > publickey
```

Он отправляет `publickey` вам, вы заменяете `PublicKey` в peer `mikhail-ubuntu` в `/etc/wireguard/wg0.conf` на hub, перезапускаете `wg-quick@wg0`, а в его конфиг подставляете его `privatekey`. Готовый конфиг с уже сгенерированными ключами проще — можно использовать его.

### 6.3. Положить конфиг

На Ubuntu Михаила:

```bash
sudo install -d -m 700 /etc/wireguard
sudo nano /etc/wireguard/wg0.conf
```

Вставить содержимое `mikhail.conf`, сохранить, затем:

```bash
sudo chmod 600 /etc/wireguard/wg0.conf
```

Конфиг должен выглядеть так (приватный ключ и PSK — из файла):

```ini
[Interface]
Address = 10.66.0.2/24
ListenPort = 51820
PrivateKey = <MIKHAIL_PRIVATE_KEY>
MTU = 1420

PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT
PostUp = iptables -t nat -C POSTROUTING -s 10.66.0.0/24 ! -o wg0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.66.0.0/24 ! -o wg0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -s 10.66.0.0/24 ! -o wg0 -j MASQUERADE 2>/dev/null || true

[Peer]
# hub
PublicKey = EtmsYLJ3xZdQ3W4urs17kKeKLCXop1yAk1zWnjrbYkU=
Endpoint = 212.220.200.34:51830
AllowedIPs = 10.66.0.0/24, 10.10.26.0/24
PersistentKeepalive = 25
```

Пояснения:

- `Address = 10.66.0.2/24` — адрес Ubuntu в VPN.
- `ListenPort = 51820` — обязателен. С эфемерным портом (например, `52563`) NAT/роутер не пропускал handshake, хотя простые UDP-пакеты доходили. Порт 51820 на клиенте не конфликтует с hub: это разные машины.
- `AllowedIPs = 10.66.0.0/24, 10.10.26.0/24` — в туннель идут только VPN-сеть и LAN hub. Интернет Михаила остаётся напрямую.
- `PersistentKeepalive = 25` — обязательно, иначе NAT на стороне Михаила закроет сессию и hub не сможет инициировать соединение.
- `PostUp` с `MASQUERADE` нужен, чтобы трафик из VPN в `192.168.189.0/24` уходил с адресом `192.168.189.140`. Иначе хосты LAN не знают, куда отвечать на `10.66.0.x`.
- `! -o wg0` означает «NAT для всего, что уходит не в туннель», поэтому имя LAN-интерфейса (`eth0`, `ens33`, `enp0s3` и т.п.) знать не нужно.

### 6.4. Включить forwarding и запустить

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-wireguard.conf
sudo sysctl --system
sudo systemctl enable --now wg-quick@wg0
```

`PostUp` сам выставит `ip_forward` и правила iptables. Файл в `/etc/sysctl.d` нужен, чтобы forwarding сохранился после перезагрузки.

### 6.5. Если на Ubuntu включён UFW

Проверить:

```bash
sudo ufw status
```

Если `Status: active`, добавить:

```bash
sudo ufw route allow in on wg0 out on eth0
sudo ufw route allow in on eth0 out on wg0
```

Исходящий UDP на `51830` по умолчанию разрешён. Если у вас политика запрета исходящих, разрешите его отдельно:

```bash
sudo ufw allow out 51830/udp
```

Вместо `eth0` подставить LAN-интерфейс:

```bash
ip route show default
```

Если UFW выключен, эти команды не обязательны.

### 6.6. Проверить туннель на стороне Михаила

```bash
sudo wg show
ip addr show wg0
ip route
ping -c 3 10.66.0.1
```

Ожидаемо:

- `wg show` показывает peer с публичным ключом hub;
- `latest handshake` — несколько секунд назад;
- `transfer` растёт;
- `ping 10.66.0.1` проходит.

Если handshake есть, но `ping 10.66.0.1` не проходит, проверьте `AllowedIPs` и `Address`.

### 6.7. Проверить доступ к LAN Михаила

С hub:

```bash
ping -c 3 192.168.189.140
ping -c 3 192.168.189.138
ping -c 3 192.168.189.136
ping -c 3 192.168.189.137
```

Если `.140` пингуется, а `.138` нет:

- на Ubuntu Михаила проверить `sysctl net.ipv4.ip_forward` (должно быть `1`);
- проверить `sudo iptables -t nat -S POSTROUTING` (должен быть MASQUERADE для `10.66.0.0/24`);
- проверить, не блокирует ли UFW forwarding;
- проверить Windows Firewall на `.138` — разрешить ICMP и нужные порты (MSSQL 1433, SMB 445 и т.д.) из `192.168.189.0/24`. После NAT источник для Windows будет выглядеть как `192.168.189.140`.

Важно: не добавляйте `192.168.11.0/24` в `AllowedIPs`. Внутри туннеля hub доступен по `10.66.0.1`; адрес `192.168.11.34` — это внешний DNAT-алиас, а не адрес на интерфейсе VM.

## 7. Подключение разработчиков

На hub для каждого разработчика:

```bash
sudo /usr/local/sbin/wg-add-client.sh dev-02
```

Скрипт:

- выдаст следующий свободный адрес (`10.66.0.11`, `10.66.0.12`, …);
- сгенерирует ключи и PSK;
- добавит peer в `/etc/wireguard/wg0.conf`;
- применит конфиг через `wg syncconf` без разрыва существующих сессий;
- добавит `ListenPort = 51820` в клиентский конфиг;
- создаст `/etc/wireguard/clients/dev-02.conf`.

Выдать конфиг разработчику:

```bash
sudo cat /etc/wireguard/clients/dev-02.conf
```

Разработчик:

1. Устанавливает WireGuard для своей ОС.
2. Импортирует `.conf`.
3. Включает туннель.
4. Проверяет:

```bash
ping 10.66.0.1
ping 192.168.189.138
```

Клиентский конфиг — split tunnel: через VPN идут только `10.66.0.0/24` и `192.168.189.0/24`, интернет разработчика остаётся напрямую.

Если разработчику нужен доступ к LAN hub `10.10.26.0/24`, добавить в его конфиг:

```ini
AllowedIPs = 10.66.0.0/24, 192.168.189.0/24, 10.10.26.0/24
```

Если нужен полный туннель через hub:

```ini
AllowedIPs = 0.0.0.0/0
DNS = 1.1.1.1
```

NAT на hub для `10.66.0.0/24` уже настроен, поэтому интернет через hub работать будет.

### 7.1. Пример готового клиента

`dev-01` уже создан:

```text
IP:     10.66.0.10
Config: /etc/wireguard/clients/dev-01.conf
```

Его можно выдать первому разработчику или удалить, если не нужен.

Для Mac создан отдельный конфиг в корне проекта:

```text
IP:     10.66.0.11
Config: mac-wg.conf
```

Приватный ключ сгенерирован на Mac и лежит только в `mac-wg.conf`; файл не коммитить в git.

Локальный вариант для сети `192.168.11.0/24` — `mac-wg-local.conf`:

```text
IP:       10.66.0.11
Config:   mac-wg-local.conf
Endpoint: 192.168.11.34:51820
```

На `.34` стоит catch-all DNAT на `10.10.26.10`, поэтому локальный порт — **51820**, а не 51830. Альтернатива: `192.168.11.101:51830` (specific DNAT `.101:51830 -> 10.10.26.10:51820`). Конфиг работает только из сети, откуда доступен `192.168.11.34`; с текущей сети Mac `192.168.9.0/24` этот адрес сейчас не маршрутизируется.

### 7.2. Отзыв клиента

Вручную:

1. Удалить блок `[Peer]` с комментарием `# dev-02` из `/etc/wireguard/wg0.conf`.
2. Удалить файлы:

```bash
sudo rm -f /etc/wireguard/clients/dev-02.conf \
           /etc/wireguard/keys/dev-02.key \
           /etc/wireguard/keys/dev-02.pub \
           /etc/wireguard/keys/dev-02.psk
```

3. Применить конфиг:

```bash
sudo wg syncconf wg0 <(sudo wg-quick strip wg0)
```

## 8. Сквозная проверка

### 8.1. Со стороны hub

```bash
sudo wg show
ping -c 3 10.66.0.2
ping -c 3 192.168.189.140
ping -c 3 192.168.189.138
ping -c 3 192.168.189.136
ping -c 3 192.168.189.137
```

### 8.2. Со стороны Михаила

```bash
sudo wg show
ping -c 3 10.66.0.1
ping -c 3 10.10.26.10
```

### 8.3. Со стороны клиента

```bash
ping 10.66.0.1
ping 192.168.189.138
nc -vz 192.168.189.138 1433
nc -vz 192.168.189.138 445
```

Для MSSQL с Windows-клиента:

```powershell
sqlcmd -S 192.168.189.138,1433 -U sa -P "<пароль>"
```

## 9. Диагностика

| Симптом | Вероятная причина | Что проверить |
| --- | --- | --- |
| `wg show` без `latest handshake` с обеих сторон | UDP 51830 не проброшен, неверный endpoint, firewall, ISP блокирует UDP | `tcpdump` на hub, проброс на RT-GM-3 и DNAT на `hackaton-edge`, `Endpoint` в конфиге |
| Handshake есть, `ping 10.66.0.1` не идёт | неверные `Address`/`AllowedIPs` | `ip addr show wg0`, `AllowedIPs` на обеих сторонах |
| Handshake есть, `192.168.189.138` не пингуется | нет forwarding/NAT на Ubuntu Михаила, UFW, Windows Firewall | `sysctl net.ipv4.ip_forward`, `iptables -t nat -S`, `ufw status`, firewall на `.138` |
| Пингуется `.140`, но не `.138` | NAT на Ubuntu Михаила не работает или Windows Firewall | `iptables -t nat -S POSTROUTING` на `.140`, правила Windows Firewall |
| Мелкие пакеты идут, крупные — нет | MTU | уменьшить `MTU` до `1380` или `1280` на обеих сторонах |
| После перезагрузки VPN не поднялся | сервис не включён | `systemctl is-enabled wg-quick@wg0`, `systemctl status wg-quick@wg0` |
| После включения UFW всё сломалось | `DEFAULT_FORWARD_POLICY=DROP` | `ufw route allow ...`, `ufw status verbose` |
| Порт снаружи не виден | проброс только на RT-GM-3, но не на `hackaton-edge`, или наоборот | проверить `nft list chain inet mpt prerouting` на `hackaton-edge`, сравнить с TCP 22 |

Полезные команды:

```bash
sudo wg show
sudo wg show wg0 latest-handshakes
sudo tcpdump -ni eth0 udp port 51820
sudo journalctl -u wg-quick@wg0 -n 50 --no-pager
sudo iptables -S FORWARD
sudo iptables -t nat -S POSTROUTING
ip route get 192.168.189.138
```

## 10. Безопасность и эксплуатация

- Приватные ключи и PSK не коммитить в git и не публиковать в общих чатах.
- Права: `/etc/wireguard` — `700`, `wg0.conf` и клиентские конфиги — `600`.
- Конфиг hub содержит приватный ключ hub; доступ только root.
- Потеря ноутбука разработчика: удалить его peer, сгенерировать новый конфиг, выдать новый.
- Периодически проверять `wg show` и `journalctl -u wg-quick@wg0`.
- Бэкапить `/etc/wireguard` (с учётом того, что там секреты).
- Публичный IP должен быть статическим. Если он динамический — использовать DDNS и обновлять `Endpoint` в конфигах.

## 11. Ограничения текущей схемы

1. Hub не даёт доступ ко всей сети `192.168.11.0/24`. Внутри VM есть только `10.10.26.0/24`; `192.168.11.34` — это DNAT-алиас. Для доступа ко всей `192.168.11.0/24` нужен маршрут/NAT на KVM-хосте, это отдельная задача.
2. Хосты `192.168.189.0/24` не могут сами инициировать соединение к VPN-клиентам: их шлюз `192.168.189.2` не знает маршрут до `10.66.0.0/24`. Обратный трафик для соединений, инициированных из VPN, работает за счёт NAT на Ubuntu Михаила.
3. Внутренний DNS для имён `192.168.189.0/24` не настроен. Используйте IP или hosts-файлы.
4. IPv6 в VPN не настроен.
5. VPN работает. TCP 4444 на RT-GM-3 был временным пробросом для reverse shell; после настройки его можно убрать. UDP 51830 остаётся.

## 12. Быстрая шпаргалка

```text
Публичный endpoint:      212.220.200.34:51830/udp
Внутренний порт hub:     51820/udp
Hub WG:                  10.66.0.1
Михаил WG:               10.66.0.2
LAN Михаила:             192.168.189.0/24
LAN hub:                 10.10.26.0/24
Клиенты:                 10.66.0.10 - 10.66.0.99
Mac:                     10.66.0.11 (mac-wg.conf)
Клиентам обязателен:     ListenPort = 51820

Hub config:              /etc/wireguard/wg0.conf
Конфиг Михаила:          /etc/wireguard/wg0.conf на 192.168.189.140
Пример клиента:          /etc/wireguard/clients/dev-01.conf
Новый клиент:            sudo /usr/local/sbin/wg-add-client.sh <name>
Проверка:                sudo wg show
TCP 4444:                временный reverse shell, можно убрать
```

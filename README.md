# VLAN Hopping Attack — Deep Dive

> **Цель этого материала:** разобрать VLAN Hopping не как абстрактную угрозу, а на уровне пакетов — что происходит внутри фрейма, почему коммутатор ведётся, и как это закрыть конкретными командами.

---

## Содержание

- [Что такое VLAN — кратко](#что-такое-vlan--кратко)
- [Структура 802.1Q фрейма](#структура-8021q-фрейма)
- [Атака 1: Double Tagging](#атака-1-double-tagging)
- [Атака 2: Switch Spoofing через DTP](#атака-2-switch-spoofing-через-dtp)
- [Защита](#защита)
- [Верификация](#верификация)
- [Лабораторная работа](#лабораторная-работа)

---

## Что такое VLAN — кратко

VLAN (Virtual LAN) — логическое разделение одного физического коммутатора на несколько изолированных сетей. Хосты в разных VLAN не видят друг друга на L2 **без маршрутизатора**, даже если физически подключены к одному свитчу.

Два типа портов:

| Тип | Описание |
|-----|----------|
| **Access** | Принадлежит одному VLAN. Конечное устройство не знает о VLAN — фреймы без тегов |
| **Trunk** | Несёт несколько VLAN одновременно. Каждый фрейм тегируется по 802.1Q |

### Native VLAN — ключевое понятие

На trunk-порту один VLAN особенный — **native VLAN**. Его фреймы передаются **без тега 802.1Q**. По умолчанию на всех Cisco-устройствах это **VLAN 1**. Именно это и эксплуатирует Double Tagging.

> ⚠️ **VLAN 1** — дефолтный native VLAN. Все управляющие протоколы (CDP, STP, VTP) по умолчанию ходят в VLAN 1. Если атакующий попадает в VLAN 1 — он уже в привилегированной позиции.

---

## Структура 802.1Q фрейма

### Обычный Ethernet фрейм (без тега, access-порт)

```
+----------+----------+-----------+------------------+-----+
| DST MAC  | SRC MAC  | EtherType |       Data       | FCS |
| (6 байт) | (6 байт) | (2 байта) | (46–1500 байт)   |(4б) |
+----------+----------+-----------+------------------+-----+
```

### 802.1Q Tagged фрейм (trunk-порт)

```
+----------+----------+--------+----------+-----------+--------+-----+
| DST MAC  | SRC MAC  |  TPID  | PCP+DEI  | EtherType |  Data  | FCS |
| (6 байт) | (6 байт) |0x8100  |  +VID    | (2 байта) |        |(4б) |
|          |          |(2 байт)| (2 байта)|           |        |     |
+----------+----------+--------+----------+-----------+--------+-----+
                       ^^^^^^^^^^^^^^^^^
                       802.1Q тег (4 байта)
                       VID = номер VLAN (12 бит, диапазон 0–4095)
```

**Как работает:** коммутатор видит `TPID = 0x8100` — понимает что фрейм тегированный, читает 12-битный `VID` и знает в какой VLAN его направить.

<!-- СКРИНШОТ 1: Wireshark — захват 802.1Q тегированного фрейма.
     Фильтр: vlan. Видно поле 802.1Q Virtual LAN, VLAN ID.
     Сделай захват на trunk-интерфейсе в GNS3/EVE-NG или реальном железе. -->

<img width="717" height="611" alt="image" src="https://github.com/user-attachments/assets/bf6fdaa8-8fdd-49ed-9887-95b642fe9c94" />

---

## Атака 1: Double Tagging

### Условия для атаки

- Атакующий подключён к **access-порту** в **native VLAN (VLAN 1)**
- Между двумя коммутаторами есть **trunk-линк** с native VLAN = 1 (дефолт)
- Цель находится в **другом VLAN** (например, VLAN 20)

### Топология

```
+------------+         +--------+   trunk   +--------+         +--------+
| Атакующий  |-------->|  SW1   |-----------|  SW2   |-------->| Жертва |
| VLAN 1     | access  | access |  VLAN 1+  | core   | access  | VLAN 20|
| (double-   |  port   | коммут.|   20+...  | коммут.|  port   |        |
| tagged     |         +--------+           +--------+         +--------+
| фрейм)     |
+------------+
```

### Фрейм атакующего — двойной тег

```
+----------+----------+===========+----------+-----------+--------+-----+
| DST MAC  | SRC MAC  | ВНЕШНИЙ   | ВНУТР.   | EtherType |  Data  | FCS |
|          |          | ТЕГ       | ТЕГ      |           |        |     |
|          |          | VLAN 1    | VLAN 20  |           |        |     |
|          |          | (native)  | (жертва) |           |        |     |
+----------+----------+===========+==========+-----------+--------+-----+
                       ^^^^^^^^^^^
                       SW1 снимет этот тег —
                       останется только VLAN 20
```

### Механика по шагам

**Шаг 1.** Атакующий вручную собирает фрейм с двумя 802.1Q тегами:
- Внешний тег: `VLAN 1` (native VLAN на trunk)
- Внутренний тег: `VLAN 20` (целевой VLAN жертвы)

**Шаг 2.** Фрейм приходит на SW1 (access-порт, native VLAN 1).
SW1 видит: *"внешний тег совпадает с native VLAN — снимаю его"*.
Пересылает фрейм по trunk к SW2. Теперь у фрейма **только один тег — VLAN 20**.

**Шаг 3.** SW2 получает фрейм по trunk. Видит тег `VLAN 20`.
Считает трафик легитимным. Пересылает в VLAN 20 — доставляет жертве.

**Шаг 4.** Жертва получает фрейм. **Ответный трафик вернуться не может** — у жертвы нет маршрута в VLAN 1 атакующего.

<!-- СКРИНШОТ 2: Схема топологии в Packet Tracer или GNS3.
     Два коммутатора, trunk между ними, атакующий в VLAN 1, жертва в VLAN 20.
     Подпиши порты и VLAN. -->

### Ограничения атаки

> ⚠️ Атака **односторонняя** — ответного трафика нет. TCP-сессию не поднять. Но можно:
> - Инъецировать ARP-запросы в чужой VLAN
> - Отправить DHCP DISCOVER в серверный сегмент
> - Обойти L3 ACL между VLAN (трафик идёт на L2, минуя роутер)
> - Проводить flood/DoS атаки

---

## Атака 2: Switch Spoofing через DTP

### Что такое DTP

**DTP (Dynamic Trunking Protocol)** — проприетарный протокол Cisco. Коммутаторы автоматически договариваются стать trunk-линком без ручной настройки администратора.

Режимы портов и их опасность:

| Режим | Поведение | Уязвимость |
|-------|-----------|------------|
| `dynamic auto` | Пассивно ждёт — станет trunk если другая сторона хочет | 🔴 Высокая |
| `dynamic desirable` | Активно предлагает стать trunk | 🔴 Очень высокая |
| `trunk` | Всегда trunk, шлёт DTP-пакеты | 🟡 Средняя |
| `access` | Всегда access, не слушает DTP | 🟢 Нет |
| `nonegotiate` | Trunk без DTP-пакетов | 🟢 Нет |

> По умолчанию большинство Cisco-портов находятся в режиме **`dynamic auto`** или **`dynamic desirable`** — это и есть уязвимость.

### Топология

```
+------------+  DTP Desirable  +-------------------+  trunk!  +----------+
| Атакующий  |---------------->| SW1 порт           |--------->| Все VLAN |
| (Yersinia/ |  EtherType      | dynamic auto       |          | видны    |
|  scapy)    |  0x2004         | ← становится trunk |          | атакующему|
+------------+                 +-------------------+          +----------+
```

### Механика по шагам

**Шаг 1.** Атакующий подключается к обычному access-порту коммутатора.

**Шаг 2.** Запускает инструмент (Yersinia, scapy) который генерирует **DTP-фреймы** с флагом `desirable`. DTP использует multicast MAC `01:00:0C:CC:CC:CC`.

**Шаг 3.** Порт SW1 в режиме `dynamic auto` получает DTP от "соседа" и **автоматически переходит в trunk-режим**. Это штатное поведение DTP.

**Шаг 4.** Порт атакующего становится trunk. Он получает фреймы **всех VLAN** которые разрешены на trunk. Может инъецировать трафик в любой VLAN напрямую.

### Чем опаснее Double Tagging

В отличие от Double Tagging — эта атака **двусторонняя**. Атакующий становится полноценным участником всех VLAN. Можно поднять TCP-сессии, захватить трафик, атаковать любые хосты в любом VLAN.

```bash
# Linux: атака через Yersinia
yersinia dtp -attack 1

# или через интерактивный GUI
yersinia -G
```

<!-- СКРИНШОТ 3: Вывод команды "show interfaces trunk" ДО защиты —
     видно что порт перешёл в trunk после DTP-атаки.
     Можно воспроизвести в GNS3/EVE-NG. -->

---

## Защита

Всё закрывается **конфигурацией коммутатора**. Никакого дополнительного оборудования не нужно.

### 1. Отключить DTP на всех access-портах

```cisco
interface range GigabitEthernet0/1 - 24
 switchport mode access          ! явно access — порт не станет trunk
 switchport nonegotiate          ! выключить DTP полностью
```

> ✅ Закрывает Switch Spoofing полностью. Порт перестаёт слать и принимать DTP-фреймы.

**Важный нюанс:** `switchport mode access` и `switchport nonegotiate` — это разные вещи. Первая говорит порту "ты access", но DTP-пакеты он всё ещё слышит в некоторых версиях IOS. `nonegotiate` выключает DTP протокол целиком. Нужны **оба**.

---

### 2. Сменить native VLAN на неиспользуемый

```cisco
interface GigabitEthernet0/24        ! trunk-порт между коммутаторами
 switchport mode trunk
 switchport nonegotiate              ! trunk без DTP-пакетов
 switchport trunk native vlan 999    ! native VLAN = несуществующий
 switchport trunk allowed vlan 10,20,30  ! только нужные VLAN явно
```

> ✅ Закрывает Double Tagging. Атакующий в VLAN 1, но native VLAN на trunk теперь 999. Его outer-тег (VLAN 1) не совпадёт с native — SW1 не снимет его, фрейм уйдёт как обычный тегированный VLAN 1 трафик, а не "прыгнет" в VLAN 20.

**Почему 999?** VLAN 999 должен существовать в конфиге, но без реальных хостов. Это "мусорный" (black hole) VLAN — трафик попадает туда и умирает. Создай его заранее:

```cisco
vlan 999
 name BLACK_HOLE
```

---

### 3. Тегировать native VLAN явно

```cisco
! Глобальная команда — тегировать трафик native VLAN
vlan dot1q tag native
```

> ✅ Теперь даже native VLAN получает 802.1Q тег при передаче по trunk. Двойного тега не появится — первый коммутатор не будет снимать outer-тег с native VLAN трафика.

---

### 4. Убрать VLAN 1 с trunk-линков

```cisco
interface GigabitEthernet0/24
 switchport trunk allowed vlan remove 1  ! VLAN 1 не проходит по trunk
```

> ✅ Даже если native VLAN = 1, сам трафик VLAN 1 не будет проходить между коммутаторами.

---

### 5. Выключить и изолировать неиспользуемые порты

```cisco
interface range GigabitEthernet0/10 - 24  ! неиспользуемые порты
 shutdown                                  ! выключить физически
 switchport mode access
 switchport access vlan 999               ! посадить в black hole VLAN
```

> ✅ Атакующий не может подключиться к неиспользуемому порту и начать атаку.

---

### Итоговая таблица защиты

| Команда | Закрывает Double Tagging | Закрывает DTP Spoofing |
|---------|:---:|:---:|
| `switchport mode access` | частично | ✅ |
| `switchport nonegotiate` | — | ✅ |
| `switchport trunk native vlan 999` | ✅ | — |
| `vlan dot1q tag native` | ✅ | — |
| `switchport trunk allowed vlan remove 1` | ✅ | — |
| `shutdown` неиспользуемых портов | ✅ | ✅ |

<!-- СКРИНШОТ 4: Итоговый конфиг коммутатора — show running-config
     с видимыми командами защиты на портах.
     Можно сделать в Packet Tracer. -->

---

## Верификация

После настройки **обязательно проверяем** — команды `show` подтвердят что защита работает.

### Проверить режим порта и статус DTP

```cisco
show interfaces GigabitEthernet0/1 switchport
```

Хороший вывод выглядит так:

```
Name: Gi0/1
Administrative Mode:       static access      ← не dynamic!
Operational Mode:          static access
Negotiation of Trunking:   Off                ← DTP выключен
Access Mode VLAN:          10                 ← нужный VLAN
```

---

### Проверить trunk и native VLAN

```cisco
show interfaces trunk
```

```
Port      Mode    Encapsulation  Status    Native vlan
Gi0/24    on      802.1q         trunking  999         ← не 1!

Port      Vlans allowed on trunk
Gi0/24    10,20,30                          ← VLAN 1 отсутствует!
```

---

### Проверить статус DTP на конкретном порту

```cisco
show dtp interface GigabitEthernet0/1
```

```
DTP information for GigabitEthernet0/1:
  TOS/TAS/TNS:       ACCESS/ACCESS/ACCESS
  Neighbor address 1: 000000000000    ← нет DTP-соседей
  Hello timer expiry: never           ← DTP не работает
```

---

### Быстрая проверка всех портов

```cisco
show interfaces status
```

Все активные порты должны показывать явный режим (`access` или `trunk`), не `auto`.

<!-- СКРИНШОТ 5: Вывод "show interfaces trunk" ПОСЛЕ защиты —
     Native VLAN = 999, VLAN 1 отсутствует в allowed list.
     Сравни с тем что было до — это наглядно покажет разницу. -->

---

## Лабораторная работа

Воспроизвести атаку и защиту можно в **Cisco Packet Tracer** или **GNS3/EVE-NG**.

### Минимальная топология

```
[PC-Attacker]---[SW1]---trunk---[SW2]---[PC-Victim]
  VLAN 1       Gi0/1   Gi0/24  Gi0/24  VLAN 20
  (access)             native=1        (access)
```

### Шаги лабораторной

**1. Собери топологию:** два коммутатора, три ПК (атакующий, жертва, легитимный хост)

**2. Настрой базовые VLAN:**
```cisco
! На обоих коммутаторах
vlan 10
 name USERS
vlan 20
 name SERVERS
vlan 999
 name BLACK_HOLE
```

**3. Настрой порты ДО защиты** (уязвимая конфигурация):
```cisco
! SW1 — access-порт атакующего (VLAN 1, дефолт)
interface GigabitEthernet0/1
 switchport mode access
 ! native VLAN остаётся 1 — уязвимо!

! SW1-SW2 trunk — уязвимый
interface GigabitEthernet0/24
 switchport mode trunk
 ! native VLAN = 1, DTP включён — уязвимо!
```

**4. Воспроизведи атаку** — в реальной лабе используй Yersinia или scapy. В Packet Tracer — отправь фрейм вручную или используй PDU с double tag.

**5. Примени защиту** (команды из раздела выше) и убедись что атака больше не работает.

<!-- СКРИНШОТ 6: Packet Tracer / GNS3 — топология лабораторной.
     Подписи портов, VLAN, trunk-линки. -->

---

## Источники

- Cisco CCNA 200-301 Official Cert Guide, Volume 2 — Chapter 4 (Security Architectures), Chapter 6 (Switch Port Security)
- [Cisco Security Best Practices: Catalyst Switch Security](https://www.cisco.com/c/en/us/support/docs/lan-switching/8021q/17056-741-4.html)
- [IEEE 802.1Q Standard](https://standards.ieee.org/ieee/802.1Q/10323/)
- [Cisco DTP Configuration Guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/12-2SX/configuration/guide/book/trunk.html)

---

> **Важно:** весь материал — в образовательных целях. Применяй только к своим сетям или с письменным разрешением владельца.

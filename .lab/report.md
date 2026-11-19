# HuesOS — раунд 3: `ProcessTerminate` + Ctrl-C и `fdisk` для «голого» HxFS

Ветка: `arena/1de9778a-huesos` (от `main@4531666`). Проверка — живая QEMU 11.0.2
(OVMF, q35, 2 CPU, NVMe-диск с томом HxFS v7) плюс CI-прогоны.

---

## 1. Что сделано

### 1.1 Сисколл `ProcessTerminate(process_handle, exit_code)` (номер 83)

| Слой | Файл | Суть |
|---|---|---|
| ABI | `crates/huesos-abi/src/lib.rs` | `Syscall::ProcessTerminate = 83`, `COUNT = 84`, `from_raw(83)`, тест на стабильность номера |
| syscalls | `crates/huesos-syscalls/src/process.rs` | `sys_process_terminate`: `WRITE` на handle, отказ на self (`InvalidArgs`), на критичный процесс (`AccessDenied`), идемпотентность (`Ok(0)` для уже вышедшего), `NotSupported` без хука |
| syscalls | `callbacks.rs`, `lib.rs` | `ProcessTerminateFn`, `set_process_terminate_fn`, диспатч |
| kernel | `scheduler.rs` | `terminate_process(&Arc<Process>, code, cpu)` — общее тело self-exit и внешнего убийства; `terminate_process_by_koid` — реализация хука |
| kernel | `init.rs` | регистрация хука |
| libcanvas | `process/objects.rs` | `Process::terminate(code)`, `Process::exit_code()` |

Семантика завершения (атомарно, «первый победил»):

1. `set_exit_code` публикует код — второй вызов возвращает `false` и ничего не трогает;
2. `record_process_exit` будит `ProcessWait`, exit-порты и `ThreadWait`;
3. у всех CPU задачи процесса помечаются `finished`, вычищаются из fair-очередей,
   стек уходит в `REAP_QUEUE`, а address space / таблица handle — в обычный
   `PROCESS_TEARDOWN` (тот же путь, что при `ProcessExit`, поэтому page tables не
   освобождаются, пока процесс ещё «текущий» на каком-то CPU);
4. остальные CPU получают IPI и переключаются с задач жертвы.

Утечек нет: освобождение идёт через существующий teardown-путь, повторное
завершение невозможно (idempotent).

### 1.2 Ctrl-C в `hsh.elf`

* `hsh` дублирует свой `stdin`-канал и во время ожидания дочернего ELF читает его:
  пакет `TAG_KEY_EVENT` с `0x03` → `Process::terminate(130)` по handle ребёнка.
* Прочие нажатия во время работы ребёнка не теряются: они складываются в
  `pending_packets` и проигрываются в промпт после возврата.
* После убийства печатается `^C`, статус ребёнка — 130 (128+SIGINT), промпт
  возвращается сразу; страховочный дедлайн 300 тиков не даёт зависнуть, если
  пайпы ребёнка не закрываются.
* Появился `/bin/sleep.elf` (coreutils): опрос `ClockGetMonotonic` + `yield_now`,
  т.е. процесс полностью вытесняемый — иначе путь завершения был бы ненаблюдаем.

### 1.3 `fdisk` и «голый» том `HxFS v7`

* `huesos-hxfs`: `BareVolume` + `probe_bare_volume()` — проверка суперблока на LBA 0
  **тем же** кодом (`read_superblock`), что использует монтирование (CRC,
  format/type-system version, block size).
* `fdisk list` на голом томе печатает вместо `bad GPT signature`:

  ```
  disk   layout     label                size_mib   status
  disk0  raw-hxfs   HxFS v7 superfloppy  96         OK
  ```

* `fdisk inspect` — `layout/label/total_lbas/size_mib/format_version(=7)/
  type_system_version(=7)/block_size(=4096)/instance_uuid/sequence_number/
  root_state/gpt=absent/status=OK`.
* `fdisk verify` — `ok=true`, `superblock_crc=ok`.
* `fdisk gpt-init` на голом томе **отказывается** стирать ФС:
  `refusing to overwrite raw-hxfs (HxFS v7 superfloppy) ... pass --force to erase it`.
* `fdisk gpt-init --dry-run` на голом томе разрешён (ничего не пишет) и печатает
  `warning=raw-hxfs volume (...) detected, the real run needs --force`.
* Новый `--force/-f` обходит защиту осознанно.
* Новый целевой диск `/dev/mem` — записываемая in-memory площадка: позволяет
  гонять реальный `gpt-init/add/del/verify` (настоящий GPT-writer, настоящие CRC)
  на машине, где единственный блочный диск уже занят живым томом HxFS.

---

## 2. Живая проверка в QEMU (скриншоты в `.lab/shots/`)

| Скриншот | Что видно |
|---|---|
| `01-fdisk-list.png` | `disk0 raw-hxfs HxFS v7 superfloppy 96 OK` — вместо `bad GPT signature` |
| `02-fdisk-inspect.png` | все поля суперблока, `gpt=absent`, `status=OK` |
| `03-gpt-init-guard.png` | отказ стирать голый том + подсказка `--force` |
| `04-sleep-running.png` | `sleep 30` работает, title bar `sleep.elf [21]`, промпт не вернулся |
| `05-ctrl-c-killed.png` | после Ctrl-C: `^C` и промпт `hsh / >` — ребёнок убит, шелл жив |
| `06-fdisk-verify.png` | `ok=true`, `superblock_crc=ok` на голом томе |
| `07-dry-run.png` | `fdisk gpt-init --dry-run` (до фикса — отказ; см. баг №1) |
| `08-hxfs-write-at-bug.png` | воспроизведение бага №3: `fdisk: hxfs write_at 512: syscall not supported` |

---

## 3. Найденные баги и их причины

**1. `gpt-init --dry-run` отказывал там, где он нужнее всего.**
Прогон `fdisk gpt-init --dry-run` по NVMe-тому дал
`refusing to overwrite raw-hxfs ... pass --force`: защитная проверка стояла
*перед* ветвлением dry-run. Причина — проверка «есть ли на устройстве живая ФС»
писалась как безусловный guard, хотя dry-run не пишет ни байта. Исправлено:
dry-run проходит, но печатает `warning=raw-hxfs ... needs --force`; боевой запуск
по-прежнему отказывает. Добавлен маркер смоук-теста
`[hsh] fdisk raw-hxfs dry-run OK`.

**2. `fdisk list` на голом томе сообщал `bad GPT signature`.**
Причина: `list`/`inspect`/`verify` трактовали любую ошибку `GptDisk::read_from`
как «диск битый», не различая «нет GPT» и «GPT повреждён». Для superfloppy это
нормальное состояние. Исправлено пробой суперблока HxFS тем же валидатором,
которым пользуется монтирование (а не отдельной «магической» проверкой).

**3. Нельзя записать файл-образ диска внутри HxFS: `hxfs write_at 512: syscall not supported`.**
Причина — в `huesos-hxfs/src/fixed_writer.rs::write_file_at`: произвольная запись
принимается только когда `offset == 0` (полная перезапись файла) или
`offset == size && offset % 4096 == 0` (последовательный дозаписывающий блок 4 КиБ).
Всё остальное, в т.ч. 512-байтовые сектора GPT-writer'а, возвращает
`HxfsError::Unsupported` → сервис отдаёт `HxfsStatus::Unsupported` → в userspace
это `syscall not supported`. Это ограничение гранулярности записи HxFS, а не
ошибка `fdisk`. Обход в этой итерации: площадка `/dev/mem`.
Предложение на будущее: read-modify-write на уровне 4 КиБ блока в сервисе
(загрузить блок, пропатчить, записать блок целиком) — тогда файл-образы станут
рабочими без ослабления контракта.

**4. Смоук `.elf pipe` на NVMe падал с `unknown column 'type'`.**
Причина: тест фильтровал `fdisk list` по колонке `type`, которой у «голого» тома
нет (там `disk/layout/label/size_mib/status`). Тест был привязан к форме GPT-диска.
Исправлено: фильтр выбирается по фактической форме диска (`where status == OK`
для raw-hxfs, `where type == hxfs` для GPT-демо).

**5. `clippy::needless_ifs` в `driver-manager`.** Пустой `if close {}` остался от
предыдущей правки и после `cargo fmt` схлопнулся в одну строку, что подняло
`clippy::needless_ifs` при `-D warnings` — статический гейт PR стал красным.
Удалено.

**6. `-D dead-code` на `hsh::is_file`.** После перехода на безусловное разрешение
относительных путей хелпер перестал использоваться; clippy-гейт это поймал.
Удалено.

**7. Инфраструктурный: публикация артефактов терялась.** Шаг публикации
(CI-ветка `arena/**`) делал `git push` поверх сдвинувшегося `HEAD` и падал на
конфликте бинарных артефактов, из-за чего прогон терял единственный канал
доставки ISO. Исправлено: публикация делает `git reset --mixed FETCH_HEAD` и
пере-добавляет артефакты (конфликт невозможен), плюс повторные попытки.

---

## 4. Проверка

* CI `arena-iso-handoff` (сборка ISO + два смоук-гейта, обычный и с NVMe-томом):
  маркеры
  `[hsh] ProcessTerminate smoke OK (ProcessWait woke with 130)`,
  `[hsh] Ctrl-C child kill smoke OK`,
  `[hsh] fdisk gpt-init dry-run OK`,
  `[hsh] fdisk gpt init/add/del/verify OK`,
  `[hsh] fdisk raw-hxfs list OK`,
  `[hsh] fdisk raw-hxfs dry-run OK`,
  `[hsh] fdisk raw-hxfs gpt-init guard OK`
  — см. §5 для номера прогона и статуса.
* Host-тесты (`cargo test` для `huesos-abi/hxfs/syscalls/object/kernel`) и
  `clippy -- -D warnings` по всем крейтам — отдельный workflow `arena-tests`
  (лог коммитится в ветку, потому что в песочнице нет Rust-тулчейна).

## 5. Статус на момент отчёта

* ISO + оба смоук-гейта: см. последний прогон `arena-iso-handoff` в ветке.
* Host-тесты и clippy: см. `ci-artifacts/arena-tests/` в ветке.

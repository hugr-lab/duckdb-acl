# ACL Rewriter — контракт (v0.1)

Механизм: `parser_override` (ParserExtension) перехватывает запросы с префиксом `ACL …`,
переписывает распарсенный AST (резолв имён → физика, проекция/маски колонок, RLS, capability для DML)
и возвращает **настоящие `SQLStatement`**, которые идут в штатный bind→optimize→execute. DML/DDL/CTAS
работают как top-level стейтменты в транзакции вызывающего. Никакой регенерации SQL — правим AST-объекты.

Проверенные факты ядра (2.0-preview):
- `parser_override` возвращает `vector<unique_ptr<SQLStatement>>`, которые становятся результатом
  парсинга (`parser.cpp:236-263`). Гейт — `allow_parser_override_extension` (scope `GLOBAL_DEFAULT` ⇒
  **settable per-session**), режимы `DEFAULT/FALLBACK/STRICT`.
- `parse_function` (не `parser_override`) вызывается только при провале PEG (кастомный синтаксис) —
  не наш путь.
- `getvariable('name')` → **константа на бинде** всегда (в т.ч. под PREPARE), вне namespace параметров
  (`getvariable.cpp`). `$name` падает на user-переменную только вне PREPARE, и это параметр —
  **для claim-значений использовать `getvariable`, не `$var`**.
- `Connection/ClientContext::Query(unique_ptr<SQLStatement>)`, `ExtractStatements`,
  `Parser::ParseExpressionList/ParseColumnList` — context-free парс-хелперы (только `ParserOptions`).

## 0. Модель и доверие

- **Gateway поверх доверенного канала.** Инвариант деплоя: к DuckDB подключается **только обвязка**
  (сетевая/процессная изоляция). Прямое соединение мимо обвязки обходит ACL.
- Режим `FALLBACK` (strict не требуется): `ACL …` → rewrite; без префикса → обычный парсер
  (служебные/тулинговые запросы проходят). Per-connection отключение: `SET
  allow_parser_override_extension='default'` (+ вайтлист этого SET в override, чтобы обойти STRICT).
- **Резолверы и верификатор — READ-ONLY**: ничего не создают/не пишут, только возвращают.

## 1. Синтаксис входа

```
ACL ROLE  "<role>"   <sql> ; <sql> ; ...
ACL TOKEN '<token>'  <sql> ; <sql> ; ...
ACL ADMIN            <sql>            -- passthrough без rewrite (bypass)
```

- Значение **квотируется**; отрезаем **ровно один** ведущий префикс, остаток парсим родным `Parser`.
- Role/claims применяются **ко всему батчу** (парсер может вернуть несколько стейтментов).
- `ACL …` внутри строкового литерала запроса — это данные, не второй префикс.

## 2. Верификация токена (offline)

```cpp
struct Principal { string role; case_insensitive_map_t<string> claims; }; // tenant, org, ...
using VerifyToken = std::function<bool(const string &token, Principal &out)>;
```

- **Оффлайн**: предзагруженный ключ (публичный для подписи / секрет для HMAC), без IO/сети/контекста.
- Онлайн-интроспекция токена — **не здесь** (её делает обвязка и шлёт `ACL ROLE`).
- `ROLE`-форма: principal.role берётся из префикса, claims могут быть пустыми (доверяем обвязке).

## 3. Загрузка политики (ленивая, батчем)

```cpp
struct ObjectPolicy { /* см. §4 */ };
using LoadPolicy = std::function<
    case_insensitive_map_t<ObjectPolicy>(const Principal &, const vector<QualifiedName> &names)>;
```

- Вызывается **на cache-miss** для объектов, реально названных в стейтменте (собраны в проходе 1).
- Реализация read-only; допускается **пул долгоживущих read-only соединений** внутри расширения
  (открывать новое на каждый miss — нельзя, переиспользовать под мьютексом). Транзакции/локи неважны
  (политика внешняя, read-only).
- Один round-trip на стейтмент (за незакэшированные имена), амортизируется до ~0 при прогреве.

## 4. Формы возврата резолверов

```
Table/View:  { allow, phys{db,schema,name},
               capability{select,insert,update,delete,merge},
               columns[ {name, allow, readonly, mask_expr?} ],
               rls_predicate_template }        -- ссылается на getvariable('acl_*') или плейсхолдеры
Scalar fn:   { allow, replace_expr_template? } -- макро-выражение, формальные параметры = аргументы
Table fn:    { allow, replace_macro_template, formal_params[], columns[] }
Schema:      { allow }
```

- `rls_predicate_template` хранит **форму** (какая колонка — фильтр), **значения** приезжают из claims.
- `mask_expr` — выражение маскирования (`NULL AS ssn`, `md5(ssn) AS ssn`).

## 5. Правила переписывания (parse-time, два прохода)

**Проход 1 — сбор имён:** обход AST, собрать все `BaseTableRef` / `TableFunctionRef` /
`FunctionExpression`; вести **стек скоупов** (имена CTE и алиасы подзапросов НЕ считать объектами).
Догрузить политику батчем для незакэшированных имён.

**Проход 2 — rewrite:**

- **Таблица/View `t`** → `SubqueryRef`:
  `(SELECT <проекция> FROM <phys> WHERE <rls>)`
  - проекция: разрешённая колонка — как есть; маскируемая — `mask_expr AS name`; запрещённая —
    **не включать** (⇒ биндер сам отвергнет `SELECT denied`);
  - `<rls>` = предикат с **вшитыми константами claims** (дефолт, см. §7); `getvariable('acl_*')` —
    альтернатива только для «соединение = один пользователь».
- **Скалярная функция** → `replace_expr` (макро-подстановка аргументов) либо отказ, если `!allow`.
- **Табличная функция** `vfunc(args)` → **макро-раскрытие**: копия `replace_macro_template`,
  подстановка AST-аргументов вызова в формальные параметры (по позиции/имени). Не query-параметры.
- **DML-цель**: проверить `capability.{insert|update|delete|merge}`; нет → отказ. Встроенный
  `SELECT`/`FROM`/`USING` переписывается теми же правилами (весь AST — единица, бинд целиком).
- **Неизвестное имя** (нет в политике) → **ОТКАЗ** (никогда не «пропустить как есть» — иначе биндер
  зарезолвит в реальный каталог = обход).

## 6. Золотое правило параметров

**Rewriter НЕ добавляет query-параметров.** Тогда пользовательские `$1`/`?` — единственные параметры,
проходят насквозь, биндятся клиентом, номера не сдвигаются. Свои значения:

- claim/RLS → `getvariable('acl_*')` (константа на бинде) **или** вшитая константа claim;
- аргументы заменяемой функции → подстановка AST-поддеревьев (макро), не параметры.

## 7. Claims и пул соединений

**РЕШЕНО: claim-значения вшиваются КОНСТАНТАМИ** (per-request, из верифицированного токена). Это
дефолт: stateless, пул-безопасно (нет сессионной переменной → нет класса багов «забыл сбросить» и
стейл-переменной), доверие на подписи токена (не на обвязке). Механика: template-cache хранит статичный
AST шаблона с **плейсхолдерами** claim'ов (напр. узел-маркер `@claim(tenant)`); per-request копируешь
шаблон и заменяешь плейсхолдеры на `BoundConstant`/`ConstantExpression` со значением из
`principal.claims`. Аргументы функций подставляются тем же копи-и-замени проходом.

- `getvariable('acl_*')` — **альтернатива только** для «соединение = один пользователь, claims
  стабильны»: тогда AST кэшируется как есть, обвязка один раз `SET VARIABLE`. Под пул между юзерами
  не использовать.
- Prepared + константы: claim вшит на этапе rewrite (до PREPARE), поэтому в prepared-плане он статичен;
  при смене пользователя — новый `ACL TOKEN` → новый rewrite → новый prepared (или прямой запрос).
  Никаких query-параметров для claim'ов, никакого prepend-SET.

## 8. Кэши (конечные, bounded LRU)

- **policy-cache**: `(policy_version, role, object)` → `ObjectPolicy`. LRU по числу записей/памяти.
- **template-cache**: `(policy_version, object)` → **распарсенный AST шаблона** (подзапрос таблицы /
  тело макроса). Статичный (getvariable-ссылки / формальные параметры / плейсхолдеры). LRU.
- **Инвалидация**: бамп `policy_version` ⇒ старые записи протухают/вытесняются.
- 200K каталог: держим только working set; per-request — копия шаблона + подстановка аргументов
  функции; claim-значения через getvariable/константу.

## 9. Где живёт enforcement

- **Колонки** — parse-time, структурно (проекция подзапроса). Второго хука нет.
- **Строки (RLS)** — parse-time, предикат в подзапросе.
- **Таблица/функция: существование + capability** — резолвер на parse-time; финальная валидация
  (типы/существование физики) — штатный бинд.

## 10. Инварианты и гигиена

- Резолверы/верификатор — read-only, без DDL/write; IO на parse только read-only policy-запрос (пул).
- Отрезать ровно один `ACL`-префикс; role/claims — на весь батч.
- Токены короткоживущие; **маскировать в логах/профайлере** (текст SQL логируется).
- Безопасность = «только обвязка коннектится» (инвариант деплоя) + подпись токена.

## 11. Открытые вопросы

- Enforcement инварианта деплоя (кто гарантирует, что мимо обвязки не подключиться).
- DDL-политика: schema-level `create/drop` capability (пока вне scope).
- Полнота обхода AST (главный риск) — проверять отдельным набором тестов на обход.

## 12. Статус и план скелета PoC (точка возобновления)

### СКЕЛЕТ СОБРАН И ЗЕЛЁНЫЙ (обновление)

`test/extension/acl_rewrite_demo.cpp` (+ блок в `test/extension/CMakeLists.txt`) и `test/extension/acl_rewrite.test`
реализованы; **44 assertions passed**. Соседние тесты не задеты (gate 57 / rls 48 / columns 33 / facade 44).
Билд: `make reldebug`; прогон: `build/reldebug/test/unittest test/extension/acl_rewrite.test`.

Что реализовано в скелете:
- `parser_override` (FALLBACK): распознаёт `ACL ROLE "…"` / `ACL TOKEN '…'` / `ACL ADMIN`, отрезает один
  префикс (свой мини-сканер с обработкой doubled-quote), остаток парсит родным парсером на **копии**
  ParserOptions с `DEFAULT_OVERRIDE` (не реентрит override, «ровно один префикс»). Не-`ACL` → `NONE` →
  падаем в родной парсер (unprefixed сервис-трафик проходит). `ADMIN` → passthrough без rewrite.
- Отказ = **throw** из override (в FALLBACK non-success молча падает в родной парсер и был бы обойдён —
  поэтому denial бросаем исключением, а не возвращаем error-result).
- `AclRewriter`: рекурсивный обход **всех** QueryNode-подтипов (SELECT/SET_OP/CTE/RECURSIVE_CTE и
  DML-ноды INSERT/UPDATE/DELETE/MERGE через типизированный `stmt.node`), TableRef (BASE/SUBQUERY/JOIN/
  TABLE_FUNCTION/EXPRESSION_LIST) и выражений (подзапросы в SELECT/WHERE). Стек скоупов CTE — по значению
  (snapshot/restore), имя CTE НЕ резолвится как объект (проверено тестом shadowing).
- Таблица → `SubqueryRef(SELECT <проекция/маски> FROM phys [WHERE <rls>])`, alias сохранён; **claims
  вшиты константами**: шаблон RLS содержит маркер `acl_claim('<name>')`, после парса подзапрос обходится
  и маркеры заменяются на `ConstantExpression` (незарегистрированная функция ⇒ fail-closed, если промах).
- DML-цель: `capability` + resolve-in-place имени в физическое (без оборачивания в подзапрос).
- Неизвестное/физическое имя → **ОТКАЗ**. Стаб-резолверы: `acl_grant_table(role,vname,phys,cols,rls,caps)`,
  `acl_define_token(token,role,claims)`, `acl_define_role(role,claims)`.

Проверено тестом: ROLE/TOKEN claim-RLS, срез+маскирование колонок, `SELECT *` = только разрешённые,
невидимость дропнутой колонки (в проекции и в WHERE), скалярный подзапрос + alias, CTE-body rewrite,
CTE-shadowing, INSERT…VALUES (resolve цели + capability), отказ по capability, ADMIN passthrough, отказ
верификации токена, проход не-`ACL` запросов.

### Резолв view + гейтинг функций (обновление, commit `95f3b063a9`)

**Как отделить системные функции от гейтящихся — решено через РЕЗОЛВЕР-SEAM, не хардкодом:**
Rewriter сам НЕ решает «хорошая/плохая функция» — он прогоняет **каждую** функцию (и table, и scalar)
через единый seam `ResolveFunctionAllowed(principal, kind, qualified_name) -> bool`. Классификация
(читает ли функция внешние данные / ходит ли мимо ACL) — дело этого колбэка. Сюда подключается будущий
role-aware ACL-резолвер.
- **Большинство функций не режем.** Расширения добавляют в основном чистые трансформы (`ST_AsGeoJSON`,
  `lower`, арифметика) — они проходят. Режем только **читателей источников / обход прав**:
  - file/blob readers: `read_csv*`, `read_parquet`, `parquet_scan`, `read_json*`, `read_ndjson*`,
    `read_text`, `read_blob`, `sniff_csv`, `glob`;
  - spatial readers: `st_read`, `st_readosm`, `st_read_meta` (но НЕ `st_asgeojson`);
  - внешние сканеры / SQL-passthrough (обход шлюза): `postgres_query/scan/execute`, `mysql_*`,
    `mssql_query/scan/execute`, `sqlite_*`, `iceberg_scan`, `delta_scan`, `query`, `query_table`;
  - session/secret: `getvariable`, `which_secret`, `current_setting`, `current_query`.
- Матч по **последнему компоненту** имени (квалифицированный алиас `db.schema.read_csv` не проскочит).
- **Дефолт стаба = denylist читателей, остальное allow.** Реальный резолвер может классифицировать иначе
  и, что важно, для **незнакомых table-функций разумно default-deny** (неизвестная table-fn может быть
  читателем) — стаб намеренно permissive, это заглушка. `kind` (SCALAR/TABLE) передаётся в seam, чтобы
  прод-резолвер мог применять разные дефолты по типу.
- Админ-хелперы: `acl_deny_function(name)` / `acl_allow_function(name)` (снять из denylist — если дефолт
  широковат). Едины для scalar и table (имя-based).
- **Pragma/CALL/DDL** (напр. `postgres_execute` в pragma-форме) — не доходят до rewrite: любой
  не-DML/SELECT statement → отказ statement-гейтом (`RewriteStatement` default).

**Views:** `acl_grant_view(role, vname, select_sql)` — имя → полный SELECT (его SQL = определение),
claims вшиваются как в таблицах; read-only (DML через view → отказ). Таблица и view делят один namespace
резолвера (`TablePolicy.query` != пусто ⇒ view).

Покрыто тестом (72 assertions): view-резолв + отказ DML через view; функция allow (`lower`, `range`) /
deny (`read_csv`/`query`/`postgres_query` в т.ч. в подзапросе; `getvariable` в SELECT и в WHERE);
policy-driven: `acl_deny_function('lower')`→отказ→`acl_allow_function('lower')`→снова ok; `md5` после
`acl_deny_function`. Плюс полнота обхода: скаляр-подзапрос-колонка, коррелированный EXISTS, IN,
derived-table с модификаторами, запрещённая колонка/функция внутри вложенных подзапросов.

### Формы замены: RENAME vs SUBQUERY (обновление, commit TBD)

**Резолвер отдаёт ФОРМУ замены + данные; rewriter только применяет.** Две формы на объект:
- **RENAME** — перезаписать имя на месте на физическое (полный путь `a.b.c` → `pdb.psch.pobj`),
  `BaseTableRef` остаётся настоящей таблицей ⇒ **writable** (INSERT/UPDATE/DELETE идут в физику).
  Виртуальное имя сохраняем как alias, чтобы `vname.col` резолвился. Для незапрещённого объекта.
- **SUBQUERY** — обернуть SELECT: проекция (маски + **вычисляемые колонки** `expr AS name`), RLS-предикат
  (claims-константы), либо полный SQL view/vfunc. **Read-only by construction** (в подзапрос не пишут) ⇒
  DML по такому объекту → отказ «read-only relation».

Дефолт-политика (вариант 1, выбран юзером): проекция и/или RLS заданы → SUBQUERY (read-only); обе пусты →
RENAME (writable). Решает это резолвер (в PoC — при регистрации `acl_grant_table`: cols='' и rls='' →
RENAME). View (`acl_grant_view`) и vfunc — всегда SUBQUERY.

Таксономия по объектам:
1. **Таблица** — RENAME (обычно) или SUBQUERY (если маска/RLS/вычисляемые колонки).
2. **View** — RENAME на физ-view **или** SUBQUERY (SQL). RLS на view = просто `WHERE … acl_claim('x')`
   внутри его SQL (вшивается `BakeClaims`, бесплатно — уже работает).
3. **vfunc** — как view (SUBQUERY-SQL с параметрами: формальные ← AST-аргументы вызова), плюс возможен
   RENAME-alias на физическую/`main`-функцию источника. RLS так же через `acl_claim` в SQL. **Не сделано.**

Ключ резолва — **полный путь** (`VirtualKey` = `QualifiedName.Path()` join '.'), не последнее имя.

Покрыто тестом (85 assertions): RENAME writable (SELECT/INSERT/**DELETE** e2e), вычисляемая колонка
(`amount*2`), многоуровневый путь `analytics.sales.orders`→phys, read-only отказ DML по SUBQUERY-таблице
и по view, capability-отказ на RENAME без insert. Плюс всё прежнее (RLS/маски/функции/подзапросы/CTE).

### vfunc сделано (commit TBD)

**Виртуальные табличные функции — две формы (как view, плюс аргументы):**
- **RENAME-alias** (`acl_grant_table_function_alias(role, vname, phys_fn)`): переименовать вызов на месте
  на физическую/`main`-функцию, аргументы как есть. Гейт seam'а на alias-target НЕ применяется (админ
  авторизовал). Тест: `my_range(5)` → `range(5)`.
- **SUBQUERY-macro** (`acl_grant_table_function(role, vname, sql)`): SQL-шаблон, где аргументы вызова
  подставляются маркером **`acl_arg(N)`** (1-based), а RLS — через `acl_claim('x')`. `BakeMarkers`
  делает оба замещения одним обходом; аргумент вставляется **копией AST-поддерева** (не текстом), read-only.
  Тесты: `report(200)`, `report(100+100)` (аргумент = выражение), внутри подзапроса, отказ `bad_report`
  при `acl_arg(2)` без 2-го аргумента.

**Golden rule (§6) соблюдён:** rewriter параметров не добавляет — `acl_arg(N)` заменяется **копией
аргумента пользователя** (константа/выражение/`?`/подзапрос). Если аргумент = `?`/`$n`, он переезжает
узлом и остаётся параметром пользователя. Порядок: сначала `RewriteFunctionArgs` (резолв вложенных
vname в аргументах), потом подстановка → nested-vname в аргументах тоже переписывается.
Маркеры `acl_arg`/`acl_claim` не регистрируются как реальные функции ⇒ промах = fail-closed на бинде.

### СДЕЛАНО (commits `4576cf1ba3` params, `795ecf210d` DML, `bb5e469645` scalar)

- **Параметры `?`/$1** — C++ API prepared-тест (`test_acl_rewrite_params.cpp`, 17 assertions):
  `GetParameterCount()==1` (rewriter параметров не добавил) и в outer-WHERE, и как аргумент vfunc;
  bound-значение меняется между Execute, RLS-claim остаётся вшитой константой. Golden rule подтверждён.
- **UPDATE / MERGE / INSERT…SELECT из vtable** — e2e по writable-RENAME: UPDATE, INSERT…SELECT с источником
  из vfunc `report`, MERGE (WHEN MATCHED UPDATE + WHEN NOT MATCHED INSERT). Закрыт пробел обхода:
  `RewriteMergeNode` теперь обходит merge-actions (SET/INSERT-выражения и их условия).
- **Скалярный vfunc** — две формы: `acl_grant_scalar_alias` (RENAME-alias на физ/`main`-скаляр) и
  `acl_grant_scalar` (expr-macro: шаблон-выражение с `acl_arg(N)` + `acl_claim`). Резолвится ДО allow/deny
  seam'а; аргументы переписываются первыми (вложенные vscalar/vname в аргументах резолвятся). Тесты:
  `tenant_tag('u1')`→`u1@acme`/`u1@globex`, `shout(name)` над vrelation, alias `lc`, в WHERE, вложенные
  `lc(shout('Hi'))`.

Итого зелёных: `acl_rewrite.test` — 120 assertions; `test_acl_rewrite_params` — 17.

### Вынос стора из глобалей — сделано (commit `7538c7a365`)

`PolicyRegistry`-синглтон убран. `PolicyStore` создаётся **по одному на DatabaseInstance** в
`LoadAclRewriteDemo`; носится:
- в `parser_override` — через `AclParserInfo : ParserExtensionInfo` (`ParserExtension::parser_info`),
  `info->Cast<AclParserInfo>().store`;
- в admin-функции (`acl_grant_*`) — через `AclScalarInfo : ScalarFunctionInfo`
  (`ScalarFunction::SetExtraFunctionInfo`), доступ в теле функции:
  `state.expr.Cast<BoundFunctionExpression>().Function().GetExtraFunctionInfo().Cast<AclScalarInfo>()`.
Резолверы стали методами `PolicyStore` (`VerifyPrincipal/ResolveTable/ResolveTableFunction/
ResolveScalarFunction/FunctionAllowed`). Нет process-global состояния → инстансы изолированы (тест
«policy store is isolated per database instance»: политика из db1 не видна в db2). Это же — точка
подключения будущего read-only role-aware резолвера/пула соединений (§2/§3).

### template-cache + multi-statement — сделано (commits `d72ab8b2d7`, `b35f76b7a9`)

- **template-cache** (§8): `TemplateCache<T>` — bounded LRU (256) распарсенных прототипов в `PolicyStore`
  (`select_cache` для subquery-шаблонов relation/vfunc, `expr_cache` для scalar-macro). Шаблон парсится
  **один раз**, per-request копируется (`Copy()`), маркеры бейкаются в копию (прототип чист). Ключ — текст
  шаблона (пере-регистрация = новый ключ). Тест: один view-шаблон под acme и globex → верный claim каждый
  раз (нет утечки в прототип).
- **multi-statement батч**: один `ACL`-префикс + несколько `;`-стейтментов → все переписываются под одним
  принципалом (override верифицирует principal один раз, гоняет весь вектор). Тест: два INSERT (VALUES +
  INSERT…SELECT из vfunc) под одним `ACL TOKEN`.

### Дальнейшие шаги (не сделано)
1. **policy-cache + ленивая батч-догрузка (§3)** — в PoC политика целиком in-memory (регистрируется
   `acl_grant_*`), внешнего источника нет ⇒ policy-cache/`policy_version`/read-only пул `Connection`
   осмысленны только в проде (реальная policy-БД). Место в `PolicyStore` готово (методы-резолверы —
   точка подключения). Не PoC-задача.
2. **Логи**: маскировать токен в тексте SQL (§10). Технически текст запроса логируется ядром
   (`ClientContext`), из `parser_override` его не переписать ⇒ маскировать должна обвязка перед отправкой
   (или короткоживущие токены). Деплой-инвариант, не код расширения.
3. **DDL-политика** (schema-level create/drop capability) — вне scope (§11).
4. **Инъекция через admin-текст**: значения claim/аргументы вставляются узлами (`Value`/AST-копия), не
   текстом — инъекция пользователем невозможна; но `phys`/`cols`/`rls`/шаблоны — доверенный admin-текст
   (инвариант: админ-конфиг доверенный; задокументировано).

### (исходный план — выполнен)

Контракт согласован (v0.1). **Решения зафиксированы:** `parser_override` + FALLBACK; вход
`ACL ROLE|TOKEN|ADMIN`; claim-значения — **вшитые константы** (§7, не `getvariable`, не `$var`); аргументы
функций — макро-подстановка AST; **ноль новых query-параметров**; два конечных LRU (policy + template),
ключ с `policy_version`; ленивая батч-догрузка политики (read-only пул) под каталоги 200К; резолверы и
верификатор read-only. Enforcement колонок/RLS — на parse-time в подзапросе-замене.

Это **новая ветка работы**, отдельная от `feat/acl-sandbox-poc` (тот PoC — hook/post-bind/facade подход,
3 фазы зелёные, коммиты `f9ea13cfc1`/`f3f42d861e`/`a7ede1ada3`, не запушен). Новый PoC — модель
«parser_override + AST-rewrite», её и собираем.

**План скелета (в порядке сборки):**
1. Новый loadable-extension в `test/extension/` (напр. `acl_rewrite_demo.cpp`) + блок в
   `test/extension/CMakeLists.txt` (образец — `acl_gate_demo` там же).
2. `AclParserInfo : ParserExtensionInfo` — несёт: `verify_token` (§2), `load_policy` (§3), два LRU
   (§8), пул read-only `Connection` (пока можно без реальной policy-БД).
3. `parser_override` (FALLBACK): распознать `ACL ROLE|TOKEN|ADMIN`, отрезать один префикс,
   `duckdb::Parser(options).ParseQuery(остаток)`; `ADMIN` → вернуть как есть (passthrough).
4. `Rewrite(stmt, principal, acl)` — проход 1 (сбор имён, стек скоупов CTE/алиасов) → батч-догрузка →
   проход 2: таблица→`SubqueryRef(SELECT <проекция/маски> FROM phys WHERE <rls-константы>)`,
   функция→макро-раскрытие, отказ по неизвестному имени. Резолверы — C++-заглушки с сигнатурами §4.
5. Тесты (`acl_rewrite.test`): `ACL analyst SELECT` (резолв+RLS+срез колонок), `ACL analyst INSERT …
   SELECT …` (DML работает top-level), `ACL analyst SELECT <неизвестное/запрещённое>` (отказ),
   `ACL admin …` (passthrough), пользовательский `?`/`$1` проходит насквозь, CTE-shadowing (имя CTE
   не резолвится как объект).

**Главный риск для проверки скелетом:** полнота обхода AST (§11) — тесты на обход (CTE-тени,
квалиф-имена, вложенные подзапросы, table-функции) обязательны.

Билд/прогон: `make reldebug` → `build/reldebug/test/unittest test/extension/acl_rewrite.test`.
Включение override в тесте: `SET allow_parser_override_extension='fallback';` после LOAD.

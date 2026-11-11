# `wolp-device-trust` — API для приложения (S1)

Руководство по интеграции библиотеки. Нормативные документы: `android-messenger/docs` → `specs/S2-device-trust-lib.md` (библиотека) и `specs/S3-gateway.md` (шлюз, источник правды по кодам). Здесь — что вызывать, когда и что делать с результатом. Ссылки вида §N — на S2.

Публичный API — только объект `org.wolpmessenger.devicetrust.DeviceTrust` и пакет `…devicetrust.api`. Всё остальное `internal` или закрыто opt-in `@InternalDeviceTrustApi` (нужно `sample` и тестам, но не S1).

## 1. Подключение

| Что | Как |
|---|---|
| Зависимость | `implementation(project(":devicetrust"))` или AAR. Транзитивно приходят OkHttp (часть API), WorkManager, lifecycle-process, корутины. Firebase и Play Services в дереве запрещены (`checkForbiddenDependencies`, §15 п. 1) |
| `minSdk` | 33 |
| **`ndkVersion`** | **обязательно** указать в модуле приложения (`28.2.13676358`): приложение само урезает `libwolpdt.so` своим NDK, без установленного NDK `.so` уйдёт в APK с символами и отладочной информацией |
| R8 | включать; правила библиотеки (`consumer-rules.pro`: класс JNI) подключаются сами. Проверено на A37 в release-сборке `pilot/` |
| Манифест | библиотека добавляет `INTERNET` и `<queries>` для пакетов root-менеджеров (`ROOT_MANAGER_PKG`); `QUERY_ALL_PACKAGES` не нужен |
| Подпись | одна и та же release-подпись для product и pilot; её SHA-256 — в `expectedSigningDigests` |

Образец сборки — модуль [`pilot/`](../pilot/build.gradle.kts) (§3 ниже).

## 2. Инициализация

```kotlin
class WolpApp : Application() {
    override fun onCreate() {
        super.onCreate()
        DeviceTrust.init(this, DeviceTrustConfig(
            enrollBaseUrl = "https://enroll.<host>",
            appBaseUrl = "https://app.<host>",
            serverPins = listOf("sha256/<основной>", "sha256/<запасной>"),   // RUNBOOK: «серверные ключи TLS»
            expectedSigningDigests = listOf("<sha256 hex release-сертификата>"),
            cookieProvider = { CookieManager.getInstance().getCookie("https://<host>") },
            buildKind = BuildKind.valueOf(BuildConfig.BUILD_KIND),
            raspDryRun = BuildConfig.RASP_DRY_RUN,
        ))
        // единственный подписчик событий на весь процесс (§5)
        appScope.launch { DeviceTrust.events.collect(::onTrustEvent) }
    }
}
```

- `init` быстрый и неблокирующий; процесс поднимается и ради FCM — вызывать в `Application.onCreate`, **один раз**. Повторный вызов игнорируется (даже с другой конфигурацией).
- `init` бросает `IllegalArgumentException`, если: URL не `https`; пинов меньше двух или они не `sha256/…`; приложение не debuggable, а `expectedSigningDigests` пуст; отпечаток — не SHA-256 в hex (двоеточия и пробелы допустимы).
- После `init` асинхронно: сверка состояния (§6.6), RASP, планирование `RenewWorker`, `ensureFresh()`. До конца сверки `state` = `Uninitialized`.

### `DeviceTrustConfig`

| Поле | По умолчанию | Смысл |
|---|---|---|
| `enrollBaseUrl`, `appBaseUrl` | — | хосты шлюза: регистрация/восстановление и mTLS (S3 §5) |
| `serverPins` | — | ≥ 2 пина ключей сервера (основной + запасной), для обоих хостов |
| `expectedSigningDigests` | `[]` | SHA-256 сертификатов подписи; обязателен вне debuggable. Проверяется дважды: PackageManager и native-разбор блока подписи установленного APK (§7.5) |
| `deviceKeyStrongBox` | `false` | ключ устройства в StrongBox (с откатом на TEE), R4 |
| `maxPatchAgeMonths` | 12 | предпроверка: возраст патча безопасности |
| `enrollReplayTtl` | 15 мин | = `DEVICES_ENROLL_REPLAY_TTL` шлюза |
| `reattestGrace` | 7 сут | = `DEVICES_REATTEST_GRACE` шлюза |
| `httpTimeouts` | 10 с / 20 с | connect / read |
| `workInterval` | 12 ч | период `RenewWorker` |
| `cookieProvider` | `{ null }` | cookie Kratos: повтор потерянного `enroll/finish` и неподписанные сообщения до регистрации |
| `reportRateLimit` | 24 ч, 20, 100 | REPORT: окно на (ID, detail), пачка, очередь |
| `raspPolicy` | по умолчанию §7.1 | `RaspPolicy.default().with(id, reaction)`; понижение в `RELEASE` игнорируется |
| `raspIntervalForeground` | 5 мин | RASP на переднем плане |
| `buildKind` | `RELEASE` | `RELEASE` / `PILOT` / `DEBUG`; при работе перепроверяется (§3) |
| `pilotVersionCode` | `pp ≥ 90` | пилотный диапазон `versionCode` |
| `raspDryRun` | `false` | BLOCK → REPORT `dryRun;BLOCK;…`; только в `PILOT`/`DEBUG` |

## 3. Сборки: product, pilot, debug (§7.3)

- `versionCode = MMmmpp`: `pp` 00–89 — продукт, 90–99 — пилот **перед** следующим релизом (пилот 10290 → релиз 10300). Один `applicationId`: пилот обновляется до релиза поверх, без переустановки (проверено на A37).
- Действующий тип сборки библиотека определяет сама: debuggable → как объявлен; `PILOT` + пилотный `versionCode` → `PILOT`; иначе `RELEASE`. Объявленный `DEBUG` в не-debuggable APK — это `RELEASE`.
- В `RELEASE` понижение реакций и `raspDryRun` игнорируются. Debug-сборке S1, как `sample`, нужны понижения `APP_DEBUGGABLE` и `DEBUGGER` до REPORT, иначе первый же RASP её заблокирует.
- CI S1 повторяет `verify<Variant>BuildKind` из `pilot/build.gradle.kts`: тип против flavor, диапазон `versionCode`, нет dry run в product, release не debuggable, подпись есть и её отпечаток ∈ `expectedSigningDigests`.
- После пилота шлюз поднимает `DEVICES_MIN_APP_VERSION_CODE` до первого релиза — пилотные сборки перестают получать сертификаты.

## 4. Состояние: `DeviceTrust.state`

`StateFlow<TrustState>`, пересчитывается по `TrustClock` (§5.2). Что показывает S1:

| `TrustState` | Значит | S1 |
|---|---|---|
| `Uninitialized` | идёт сверка после `init` | заставка |
| `NotEnrolled` | ключей нет | `precheck()` → экран регистрации |
| `Active(notAfter, renewAfter)` | сертификат действует | веб-клиент через mTLS |
| `RenewalDue(notAfter)` | пора продлевать; сертификат ещё действует | как `Active`; продление идёт само |
| `ExpiredGrace(graceUntil)` | сертификат истёк, восстановление возможно | `ensureFresh()`; веб-клиент шлюз не пустит |
| `ReEnrollRequired` | восстановление невозможно; ключи устройства удалены, **Vault сохранён** | повторная регистрация (новый пароль от админа) |
| `UpdateRequired(APP\|OS, reason)` | шлюз требует обновления; ключи сохранены | экран обновления (`updateHttpClient()` для манифеста/APK) |
| `Blocked(reason)` | конечное: всё стёрто | экран блокировки по `BlockReason` (`RASP`, `REVOKED`, `REPLACED`, `IDENTITY_REVOKED`, `POLICY`) |

`credentialsVersion: StateFlow<Long>` растёт при каждой смене ключа/сертификата и при удалении ключей. S1 на каждое изменение пересоздаёт всё, что держит клиентский сертификат (WebView: `clearClientCertPreferences`). Это не событие — пропустить его нельзя.

`trustNow(): Instant?` — серверное время или `null` после перезагрузки до первого ответа шлюза (тогда — системные часы с допуском).

## 5. События: `DeviceTrust.events`

`Flow<TrustEvent>`: события **копятся, пока их не заберут** (до 64), и каждое доставляется **один раз**. Подписчик должен быть ровно один на процесс — в `Application.onCreate` сразу после `init`. Событие, испущенное до подписки (сверка при старте идёт асинхронно), не теряется.

| Событие | Когда | S1 |
|---|---|---|
| `Blocked(reason)` | вход в `Blocked` и **каждый старт** в этом состоянии | стереть свои данные (WebView storage, cookie, FCM-токен) — повторно и идемпотентно |
| `VaultReset` | ключи Vault потеряны и созданы заново (§6.6 п. 4) | очистить данные E2EE веб-клиента, перерегистрировать push |

## 6. Вызовы

Все `suspend`-функции **main-safe** (работают на `Dispatchers.IO`), потокобезопасны; одновременные `ensureFresh()` объединяются. До `init` `suspend`-вызовы, `okHttpClient()`, `updateHttpClient()` и `vault` бросают `IllegalStateException`; `state` = `Uninitialized`, `clientCredentials()` и `trustNow()` — `null`.

| Вызов | Когда | Результат |
|---|---|---|
| `precheck()` | перед экраном регистрации | `Supported(info, reports)` / `Unsupported(reasons)` → экран «устройство не поддерживается» (`SOFTWARE_KEYSTORE`, `PATCH_TOO_OLD`) / `Compromised(report)` — BLOCK уже выполнен |
| `enroll(cookie, password)` | пользователь ввёл пароль онбординга | `Ok(deviceId)`, `WrongPassword(attemptsLeft ≥ 1)`, `PasswordBurned`, `PasswordExpired`, `NoPassword`, `NoSession` (перелогин в Kratos), `PolicyRejected(reason)`, `UpdateRequired(kind)`, `Unsupported`, `Blocked`, `Transient(cause, retryAfter)` — повторить. Массив `password` затирается |
| `ensureFresh()` | старт, `onResume`, заголовок `X-Device-Renew: 1` | новое состояние; продление/восстановление по сроку |
| `onGatewayDenied(code, source, reason?)` | шлюз отказал (`X-Device-Deny` / тело `{"error":…}`) | новое состояние. `PINNED_CLIENT` — ответ на `okHttpClient()`, выполняется по таблице §5.3. **`WEBVIEW` ничего не удаляет сам**: запускает `GET /v1/device/ping` по закреплённому каналу (≤ раз в 30 с), действие — по ответу ping (R3). `reason` — только для `UPDATE_REQUIRED` |
| `checkSessionBinding(cookie)` | `USER_MISMATCH` от шлюза | `Match`; `Mismatch` (подтверждено) → выйти из Kratos, «обратитесь к администратору»; `NoSession`; `Failed(NO_CREDENTIALS\|NETWORK\|DENIED)`. Отвязку **не** предлагать (D15) |
| `checkIntegrity()` | по желанию (RASP и так идёт при `init`, выходе на передний план, раз в 5 мин и перед регистрацией/продлением) | `RaspReport`; BLOCK уже выполнен (§8), REPORT отправлены с ограничением частоты |
| `unenroll()` | смена пользователя (в S1 v1 не предлагается) | `Ok(PENDING\|NOT_NEEDED)`; локально завершается всегда (R5) |
| `deviceInfo()` | диагностика | `DeviceSecurityInfo?` последней предпроверки |

### Коды шлюза (`GatewayCode`, S3 §5.9)
S1 разбирает код через `GatewayCode.parse(header или error)` и передаёт в `onGatewayDenied`. Сам S1 обрабатывает только `NO_SESSION` (перелогин) и `USER_MISMATCH` (→ `checkSessionBinding`). Остальное решает библиотека по §5.3:
- `CERT_INVALID` / `CERT_UNKNOWN` / `CERT_EXPIRED` → `ensureFresh()`; `CERT_SUPERSEDED` → восстановление;
- `DEVICE_REVOKED` / `DEVICE_REPLACED` / `IDENTITY_REVOKED` / `DEVICE_POLICY` → BLOCK (из WebView — только после подтверждения ping);
- `UPDATE_REQUIRED` → `UpdateRequired` (только по закреплённому каналу);
- `RATE_LIMITED`, `UNKNOWN` → ничего.

## 7. Сеть и WebView

| | |
|---|---|
| `okHttpClient()` | mTLS + закрепление ключей сервера: всё, кроме обновлений. Сертификат выбирается в момент рукопожатия; при смене `credentialsVersion` пул сбрасывается и новые соединения идут с новым `SSLContext` (возобновлённая TLS-сессия иначе несёт старую идентичность). R7 встроен: отказ для вытесненного сертификата повторяется один раз с текущим |
| `updateHttpClient()` | только системные CA, без mTLS и пинов — **только** подписанный манифест обновлений и APK |
| `clientCredentials()` | `ClientCredentials(privateKey, chain)` для `WebViewClient.onReceivedClientCertRequest` → `request.proceed(privateKey, chain)`; `null` — нет действующего сертификата: `request.ignore()`, **не** `cancel()` — WebView запоминает решения `proceed`/`cancel` до `clearClientCertPreferences`, а `ignore` нет (S1 §4.1). Ключ — дескриптор AndroidKeyStore, байтов ключа нет |

## 8. Vault

`DeviceTrust.vault` — конвертное шифрование секретов E2EE (§9): `wrap(plain, purpose, extraAad?)` / `unwrap(blob, purpose, extraAad?)`. Назначение (`VaultPurpose`) входит в AAD: блоб одного назначения не расшифруется как другой. Из JS (плагин S1) доступны только `E2EE` и `E2EE_PLAINTEXT`.

Ошибки (`VaultException`): `KeyGone` — ключи уничтожены (BLOCK, отвязка) или не созданы, данные не восстановить; `Locked` — временно недоступно, ничего не потеряно: до первой разблокировки после перезагрузки **или пока проход RASP этого процесса не завершился без блокирующих находок** (см. §9); повторить позже; `Corrupt` — повреждён, чужое назначение или AAD.

## 9. RASP коротко (§7)

ID проверок — `RaspCheck.*`, реакции по умолчанию — `RaspCheck.DEFAULTS`. BLOCK: сообщение подписывается текущим ключом **до** удаления → намерение → удаление всех `dt.*` и DEK → `Blocked` → отправка из очереди (§8). REPORT: подписанные пачки, не чаще раза в 24 ч на (ID, detail). `HOOK_TAMPER` (расхождение Kotlin и native, подмена результата JNI) пока только REPORT — данные пилота решат.

Изменения `specs/001-rasp-hardening` (истории 1 и 3):

- **Сначала проверка, потом секреты.** `wrap`/`unwrap` ждут первого прохода RASP процесса (обычно доли секунды после `init`, не дольше 20 с) и бросают `VaultException.Locked`, если последний проход нашёл блокирующий признак или не смог выполниться. Закрытый Vault — не стирание: стирает реакция BLOCK.
- **В release-сборке без native-проверок Vault закрыт.** Не загрузилась `libwolpdt.so` или её ответ не прошёл проверку — находка остаётся `HOOK_TAMPER` (REPORT), но секреты не выдаются. В pilot и debug Vault при этом открыт.
- **Второй проход.** Блокирующая находка эвристической проверки (`ROOT_*`, `HOOK_*`, `DEBUGGER`, `EMULATOR`) приводит к BLOCK, только если немедленный повторный проход её подтвердил; иначе уходит REPORT с пометкой `unconfirmed;BLOCK;…`. `APK_SIGNATURE`, `APP_DEBUGGABLE`, `KEYSTORE_SOFTWARE` блокируют с первого прохода.
- **`ROOT_TEST_KEYS`** — новый ID (`test-keys` в тегах сборки), по умолчанию REPORT; раньше входил в `ROOT_PROPS` и блокировал.
- **Повреждённый `state.json`** откладывается как `state.json.corrupt`, устройство становится `NotEnrolled` (нужен новый онбординг) — вместо падения при каждом запуске.

RASP — дополнительная защита (R2): на устройстве с root его можно обойти. Сильный сигнал — серверная проверка аттестации и ежедневное продление.

## 10. Что библиотека не делает

UI, Capacitor-плагин, FCM, загрузка и установка обновлений, хранение данных веб-клиента. Не пишет в журнал пароли, cookie, nonce, ключи и DEK.

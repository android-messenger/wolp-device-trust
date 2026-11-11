# Руководство разработчика библиотеки

Документ для того, кто меняет саму библиотеку: как её собрать, какие есть тесты и как их запускать, как устроена непрерывная интеграция и как выполнять типовые задачи — добавить проверку RASP, обновить тестовые векторы и замеры. Устройство библиотеки описано в [`ARCHITECTURE.md`](ARCHITECTURE.md), проверки среды выполнения — в [`RASP.md`](RASP.md).

Все команды выполняются из корня репозитория.

## 1. Окружение

| Что | Версия | Зачем |
|---|---|---|
| JDK | 17 или 21 | Gradle 8.14.3 из обёртки не работает на более новых JDK. Код компилируется под Java 17 |
| Android SDK | платформа 36 (`compileSdk`), build-tools | сборка; `apksigner` из build-tools нужен тестам native-части |
| NDK | `28.2.13676358` | сборка `libwolpdt.so` |
| CMake | `3.22.1` (ставится через SDK Manager) | то же |
| `cc`, `keytool` | любые | тесты native-части на сборочной машине |
| `adb` и устройство с Android 13 или новее | — | тесты на устройстве, замеры, экспорт векторов |

```bash
export JAVA_HOME=/opt/jdk-21.0.2 ANDROID_HOME=$HOME/Android/Sdk
```

Версии Android Gradle Plugin (8.13.0), Kotlin (2.2.21) и всех зависимостей заданы в `gradle/libs.versions.toml`. Если зависимости уже загружены в кэш Gradle, любую команду можно выполнять без сети, добавив `--offline`.

Скрипты в `tools/` находят JDK и SDK сами (`tools/adb-env.sh`): если `JAVA_HOME` не задан или указывает не на JDK 17 или 21, они ищут подходящий в `/opt` и `/usr/lib/jvm`; SDK берётся из `ANDROID_HOME`, а без него — из `$HOME/Android/Sdk`.

## 2. Модули и сборка

| Модуль Gradle | Что собирается | Команда | Результат |
|---|---|---|---|
| `:devicetrust` | библиотека вместе с `libwolpdt.so` | `./gradlew :devicetrust:assembleRelease` | `devicetrust/build/outputs/aar/devicetrust-release.aar` |
| `:sample` | демонстрационное приложение | `./gradlew :sample:assembleDebug` | `sample/build/outputs/apk/debug/sample-debug.apk` |
| `:pilot` | образец сборки приложения | см. [раздел 6](#6-модуль-pilot) | `pilot/build/outputs/apk/<вариант>/release/` |

Каталог `devicetrust-native/` — не модуль Gradle: его собирает CMake из модуля `:devicetrust` (`externalNativeBuild`). Перед настройкой CMake задача `:devicetrust:generateNativeStrings` создаёт заголовок с зашифрованными строками `devicetrust/build/generated/wolpdt/wolpdt_strings.h` из `devicetrust-native/strings.txt`. Ключи шифрования выводятся из содержимого `strings.txt`, поэтому сборка воспроизводима; свойство `-Pwolpdt.obfSeed=<строка>` задаёт другое начальное значение.

Особенности модуля `:devicetrust`:

- Включён режим Kotlin `explicitApi()`: у каждого объявления видимость указывается явно. Новое объявление по умолчанию делайте `internal`.
- То, что должно быть видно модулю `sample` и тестам, но не приложению, помечается `@InternalDeviceTrustApi`. Использование такого объявления без opt-in — ошибка компиляции; в `:devicetrust` и `:sample` opt-in включён в настройках компилятора.
- Обращения к платформе Android спрятаны за интерфейсами (`KeyStoreBackend`, `RaspEnv`, `DeviceEnvironment`, `ClockSource`, `Kek`, `ScreenLock`, `UnlockState`), чтобы логика тестировалась на JVM. Сохраняйте это разделение.
- В журнал (`Journal.event`) передаются только названия событий, коды и состояния — никогда пароли, cookie, одноразовые числа и ключи.

## 3. Тесты

| Вид | Где лежат | Команда | Что нужно |
|---|---|---|---|
| Тесты на JVM | `devicetrust/src/test`, `devicetrust/src/sharedTest` | `./gradlew :devicetrust:testDebugUnitTest` | только JDK и SDK |
| Тесты на устройстве | `devicetrust/src/androidTest`, `devicetrust/src/sharedTest` | `./gradlew :devicetrust:connectedDebugAndroidTest` | подключённое устройство |
| Тесты native-части на сборочной машине | `devicetrust-native/test` | `devicetrust-native/test/run.sh <любой.apk>` | `cc`, `keytool`, `apksigner` |
| Проверка зависимостей | `build.gradle.kts` | `./gradlew checkForbiddenDependencies` | — |
| Проверка шифрования строк | `devicetrust/build.gradle.kts` | `./gradlew :devicetrust:checkNativeStrings` | NDK, CMake |
| Проверка параметров сборки приложения | `pilot/build.gradle.kts` | `./gradlew $SIGN :pilot:verifyProductReleaseBuildKind` | ключ подписи, см. [раздел 6](#6-модуль-pilot) |

### 3.1 Тесты на JVM

Сейчас их 160. Они используют настоящий `org.json` и `MockWebServer`, а Keystore, часы и среду RASP заменяют поддельными реализациями из `Fakes.kt` и из самих тестовых классов.

| Файл | Что проверяет |
|---|---|
| `KeystoreKeysTest` | создание ключа, откат со StrongBox на TEE, отказ от программного ключа, нумерацию и уборку «сирот» |
| `AttestationChainTest`, `DerCsrTest` | разбор цепочки аттестации, кодировщик DER и запрос на сертификат |
| `PrecheckTest` | предпроверку и её кэш |
| `EnrollStartBodyTest`, `EnrollerTest` | тело первого запроса регистрации, сценарии регистрации и её повтора |
| `CertManagerTest` | продление, восстановление, сверку при запуске, обе версии `continuitySig`, включая общие со шлюзом векторы из `testvectors/continuity/` |
| `DenialsTest` | обработку кодов отказа шлюза, в том числе из WebView |
| `StoreAndCoreTest`, `TrustClockTest` | файл состояния, вычисление состояния, время |
| `GatewayErrorTest` | разбор отказа шлюза |
| `MtlsTest`, `DeviceHttpTest` | TLS с клиентским сертификатом, смену сертификата, повтор запроса со старым сертификатом. `DeviceHttpTest` лежит в `src/sharedTest` и выполняется и на JVM, и на устройстве: кэши TLS-сессий у JDK и у Conscrypt ведут себя по-разному |
| `RaspTest`, `RaspSummaryTest` | проверки, сравнение Kotlin и C, политику, пробный режим, второй проход, реакцию BLOCK, сводку |
| `ListsInSyncTest` | совпадение списков в `rasp/Checks.kt`, `devicetrust-native/strings.txt` и манифесте библиотеки |
| `AlertsTest` | сообщения шлюзу, очередь, ограничение частоты, доставку |
| `VaultTest` | Vault: обе половины, перенос прежнего хранилища, ошибки, `IntegrityGate` |

Запуск одного класса или одного теста:

```bash
./gradlew :devicetrust:testDebugUnitTest --tests 'org.wolpmessenger.devicetrust.RaspTest'
./gradlew :devicetrust:testDebugUnitTest --tests '*VaultTest*'
```

Отчёт — `devicetrust/build/reports/tests/testDebugUnitTest/index.html`.

### 3.2 Тесты на устройстве

Они работают с настоящим Android Keystore и настоящей `libwolpdt.so`, поэтому требуют реального устройства; на эмуляторе Keystore программный.

| Файл | Что проверяет |
|---|---|
| `KeystoreDeviceTest` | ключ создаётся в аппаратном хранилище и аттестуется |
| `KeystoreMtlsDeviceTest` | полное TLS-рукопожатие ключом Keystore через клиент библиотеки, TLS 1.3 и 1.2. На устройстве без аппаратного Keystore пропускается |
| `VaultDeviceTest` | Vault поверх настоящего ключа Keystore |
| `RaspDeviceTest` | C-библиотека загружается, её ответ проходит проверку, двойные проверки согласуются; на исправном телефоне единственная блокирующая находка — `APP_DEBUGGABLE`, потому что тестовый APK отладочный |
| `DeviceHttpTest` | тот же тест, что на JVM, но с Conscrypt |
| `LockBindingProbeDeviceTest` | не тест, а зонд: печатает, как ведут себя ключи Keystore, привязанные к блокировке экрана, и что видят проверки RASP на этом устройстве. Без аргумента `dtProbe` пропускается |

```bash
./gradlew :devicetrust:connectedDebugAndroidTest
```

Запуск зонда вручную (фазы `env`, `create`, `use`, `cleanup`; `create` выполняется при разблокированном экране, `use` — в каждом интересующем состоянии экрана):

```bash
./gradlew :devicetrust:assembleDebugAndroidTest
adb install -r -t devicetrust/build/outputs/apk/androidTest/debug/devicetrust-debug-androidTest.apk
adb shell am instrument -w -e class org.wolpmessenger.devicetrust.LockBindingProbeDeviceTest \
  -e dtProbe env org.wolpmessenger.devicetrust.test/androidx.test.runner.AndroidJUnitRunner
adb logcat -d -s System.out:I | grep DT-PROBE
```

Результаты запусков на устройствах записываются в [`specs/001-rasp-hardening/device-matrix.md`](../specs/001-rasp-hardening/device-matrix.md).

### 3.3 Тесты native-части на сборочной машине

```bash
./gradlew :sample:assembleDebug
devicetrust-native/test/run.sh sample/build/outputs/apk/debug/sample-debug.apk
```

Скрипт компилирует `devicetrust-native/test/apksig_test.c` вместе с `apksig.c` и `sha256.c` компилятором сборочной машины с AddressSanitizer и UndefinedBehaviorSanitizer и проверяет:

1. что таблица зашифрованных строк расшифровывается в значения из `strings.txt`;
2. что чтение блока подписи APK возвращает правильный сертификат для файлов, которые скрипт сам подписывает утилитой `apksigner`: только схема v2, только v3, только v1 (ожидается «блока нет»), смена ключа со схемой v3.1 для разных версий Android;
3. что обрезанные и искажённые файлы не приводят к падению.

Переданный APK используется только как содержимое для переподписи. Если заголовка со строками ещё нет, скрипт сам запускает `:devicetrust:generateNativeStrings`. Если на машине AddressSanitizer не запускается, скрипт сообщает об этом и продолжает только с UndefinedBehaviorSanitizer.

Сами проверки RASP на C (`rasp.c`) на сборочной машине не выполняются: им нужна система Android. Их проверяет `RaspDeviceTest`.

### 3.4 Проверки сборки

```bash
./gradlew checkForbiddenDependencies          # в зависимостях библиотеки нет Firebase и Google Play Services
./gradlew :devicetrust:checkNativeStrings     # ни одна строка из strings.txt не читается в libwolpdt.so
```

`checkNativeStrings` собирает выпускаемый AAR и ищет в каждой `libwolpdt.so` значения из `strings.txt` длиной от 4 байтов.

## 4. Непрерывная интеграция

Файл `.github/workflows/ci.yml` запускается при каждой отправке в ветку `main` и для каждого запроса на слияние. Шаги, по порядку:

| Шаг | Команда |
|---|---|
| Тесты на JVM | `./gradlew :devicetrust:testDebugUnitTest` |
| Проверка зависимостей | `./gradlew checkForbiddenDependencies` |
| Сборка AAR, `sample` и тестовых APK | `./gradlew :devicetrust:assembleRelease :devicetrust:assembleDebugAndroidTest :sample:assembleDebug :sample:assembleDebugAndroidTest` |
| Проверка шифрования строк | `./gradlew :devicetrust:checkNativeStrings` |
| Тесты native-части | `devicetrust-native/test/run.sh sample/build/outputs/apk/debug/sample-debug.apk` |
| Сборка `pilot` одноразовым ключом | обе release-сборки; затем проверка, что продуктовая сборка с пилотным `versionCode` отклоняется и что `libwolpdt.so` в APK не содержит символов |
| Публикация APK `sample` | артефакт `sample-debug-apk`, хранится 30 суток |

Тесты на устройстве, замеры и экспорт векторов в непрерывной интеграции не выполняются: им нужно реальное устройство.

Перед отправкой изменений выполните локально как минимум тесты на JVM; если менялась native-часть или `strings.txt` — также `checkNativeStrings`, тесты native-части и тесты на устройстве.

## 5. Модуль `sample`

Приложение на Compose, которому не нужен шлюз. Оно обращается к внутренним частям библиотеки напрямую (с opt-in `@InternalDeviceTrustApi`) и не вызывает `DeviceTrust.init`.

```bash
./gradlew :sample:assembleDebug
adb install -r sample/build/outputs/apk/debug/sample-debug.apk
```

Экран содержит карточки: сведения об устройстве, предпроверка, аттестация ключа, замеры и **Share report** — отправка одного файла JSON со всеми результатами и свежими тестовыми векторами.

В debug-сборке есть ещё два экрана для стенда шлюза (он находится в репозитории приложения): `StandEnrollActivity` выполняет настоящую регистрацию, `StandRenewActivity` — продление через публичный API. Их запускают скрипты стенда командой `am start` с параметрами `url`, `appUrl`, `pins`, `cookie`, `password`; точный вид команд приведён в комментариях к этим классам. Результат выводится на экран и в logcat с тегом `WOLP_STAND`. Конфигурация стенда (`StandConfig.kt`) понижает реакции на `APP_DEBUGGABLE` и `DEBUGGER` до REPORT — иначе отладочная сборка заблокировала бы себя.

## 6. Модуль `pilot`

Образец того, как приложение должно собираться вокруг библиотеки. Два варианта (`productFlavors`) одного `applicationId`:

| Вариант | `buildKind` | `versionCode` по умолчанию | Пробный режим RASP |
|---|---|---|---|
| `product` | `RELEASE` | 10300 | выключен |
| `pilot` | `PILOT` | 10290 | включён |

Свойства Gradle:

| Свойство | Назначение |
|---|---|
| `wolp.signing.storeFile`, `wolp.signing.storePassword`, `wolp.signing.keyAlias`, `wolp.signing.keyPassword` | ключ release-подписи; без всех четырёх release-сборка не проходит проверку |
| `wolp.expectedSigningDigests` | ожидаемые SHA-256 сертификата подписи через запятую. Если не задано, берётся из хранилища ключей подписи — удобно здесь, но в приложении значение должно быть зафиксировано |
| `wolp.productVersionCode`, `wolp.pilotVersionCode` | номера версий вариантов |
| `wolp.pilot.wrongDigest=true` | демонстрация: в сборку записывается заведомо неверный отпечаток, поэтому продуктовая сборка блокируется с находкой `APK_SIGNATURE`, а пилотная отправляет REPORT с пометкой `dryRun` |

Сборка с одноразовым ключом:

```bash
keytool -genkeypair -keystore /tmp/release.p12 -storetype PKCS12 -storepass pass123 -keypass pass123 \
  -alias wolp -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA -dname "CN=test" -validity 30
SIGN="-Pwolp.signing.storeFile=/tmp/release.p12 -Pwolp.signing.storePassword=pass123 -Pwolp.signing.keyAlias=wolp -Pwolp.signing.keyPassword=pass123"
./gradlew $SIGN :pilot:assembleProductRelease :pilot:assemblePilotRelease
```

Перед каждой release-сборкой выполняется задача `verifyProductReleaseBuildKind` или `verifyPilotReleaseBuildKind`. Она завершает сборку ошибкой, если тип сборки не соответствует варианту, `versionCode` не в своём диапазоне, пробный режим включён в продуктовом варианте, release-сборка отладочная, подпись не настроена, сертификата подписи нет среди ожидаемых или список ожидаемых пуст.

Приложение показывает параметры сборки и состояние, а по кнопке выполняет `DeviceTrust.checkIntegrity()`. Всё дублируется в logcat с тегом `DT-PILOT`. Адреса шлюза в нём — заглушки: модуль проверяет только RASP и политику. Проход можно запустить без нажатия кнопки:

```bash
adb shell am start -n org.wolpmessenger.devicetrust.pilot/.PilotActivity --ez scan true
adb logcat -s DT-PILOT
```

## 7. Типовые задачи

### 7.1 Добавить проверку RASP

1. **Идентификатор и реакция.** В `api/RaspPolicy.kt` добавьте константу в `RaspCheck` и запись в `RaspCheck.DEFAULTS`. Выбирайте BLOCK, только если проверка не даёт ложных срабатываний на исправных устройствах: блокировка необратима.
2. **Реализация на Kotlin.** Если проверке нужны данные платформы, добавьте метод в интерфейс `RaspEnv` (`rasp/RaspEnv.kt`), реализуйте его в `AndroidRaspEnv` и в поддельной среде `Env` в `RaspTest.kt`. Саму проверку добавьте в `KotlinChecks` (`rasp/Checks.kt`): в `single()` — если реализация только на Kotlin, в `dual()` — если будет парная реализация на C.
3. **Реализация на C** (если нужна). Добавьте идентификатор `ID_<ИМЯ>` и все строки проверки в `devicetrust-native/strings.txt` — строковых литералов в коде на C быть не должно. Напишите функцию `check_<имя>` в `devicetrust-native/src/rasp.c`, которая выводит строку результата через `out_line`, и вызовите её из функции `scan`. Запрет доступа (`EACCES`, `EPERM`) возвращайте исходом `D`, а не `F`.
4. **Двойная проверка.** Kotlin- и C-реализации должны использовать одни и те же пути, свойства и системные вызовы и давать одинаковую подробность находки: любое расхождение превращается в `HOOK_TAMPER` на каждом устройстве. Общие списки добавьте в сравнение в `ListsInSyncTest`.
5. **Второй проход.** Если проверка эвристическая и её реакция BLOCK, добавьте идентификатор в `RaspEngine.SECOND_PASS`.
6. **Видимость пакетов.** Если проверка ищет установленное приложение, добавьте пакет и в `KotlinChecks.ROOT_MANAGERS`, и в блок `<queries>` файла `devicetrust/src/main/AndroidManifest.xml`.
7. **Тесты.** Добавьте случаи в `RaspTest`: чистое устройство, находка, запрет доступа, расхождение реализаций. Тест `ListsInSyncTest` сам проверит, что у каждого идентификатора из `strings.txt` есть реакция по умолчанию.
8. **Проверка на устройстве.** Выполните `./gradlew :devicetrust:checkNativeStrings`, тесты native-части и `./gradlew :devicetrust:connectedDebugAndroidTest`: `RaspDeviceTest` должен показать, что на исправном телефоне новая проверка не срабатывает, а двойные проверки согласуются.
9. **Документация.** Добавьте проверку в обе таблицы [`RASP.md`, раздел 3](RASP.md#3-проверки).

### 7.2 Изменить строку или список в native-части

1. Измените `devicetrust-native/strings.txt`. Формат: `ИМЯ значение` — одна строка; `ИМЯ[] значение` — очередной элемент массива. Значение — остаток строки после первой группы пробелов; допустимы последовательности `\0`, `\r`, `\n`, `\t`, `\\`.
2. Если список общий с Kotlin (`SU_PATHS`, `EMU_PATHS`, `EMU_HARDWARE` и признаки эмулятора в отпечатке сборки), внесите то же изменение в `rasp/Checks.kt`.
3. Выполните `./gradlew :devicetrust:testDebugUnitTest --tests '*ListsInSyncTest*'`, затем `./gradlew :devicetrust:checkNativeStrings` и тесты native-части.

В коде на C строка `ИМЯ` доступна как `OBF_ИМЯ`, массив — как `OBF_ИМЯ` с числом элементов `OBF_ИМЯ_N`; расшифровывает их макрос `DEC(переменная, OBF_ИМЯ)`.

### 7.3 Добавить тестовые векторы аттестации с нового устройства

Векторы — цепочки аттестации с реальных устройств, по которым тестируется проверка аттестации на шлюзе. Формат описан в [`testvectors/README.md`](../testvectors/README.md).

1. Подключите устройство и разрешите отладку по USB.
2. Выполните:

   ```bash
   tools/export-testvectors.sh            # или: tools/export-testvectors.sh -s <серийный номер>
   ```

   Скрипт собирает и устанавливает `sample` и его тестовый APK, запускает на устройстве `DeviceExportTest#exportTestVectors`, забирает файлы в `testvectors/<производитель>-<модель>-api<версия SDK>/` и удаляет тестовый пакет. Приложение `sample` остаётся установленным.
3. Добавьте строку об устройстве и ожидаемом вердикте шлюза в таблицу `testvectors/README.md`.

Повторный экспорт с того же устройства перезаписывает файлы: вызовы аттестации в векторах постоянные (`SHA-256("wolp-testvector/<случай>")`), но ключи и время экспорта каждый раз новые.

### 7.4 Векторы `continuitySig`

Файлы `testvectors/continuity/continuity-v1.json` и `continuity-v2.json` — общий контракт библиотеки и шлюза: один и тот же файл должны проходить подписывающий код на Kotlin (`CertManagerTest`) и проверяющий код шлюза. Они созданы независимой реализацией на Python; сценария их создания в этом репозитории нет. Менять их нужно только вместе с изменением формата подписи (`cert/ContinuitySig.kt`, S3 §5.4 и §5.4a) и одновременно в тестах шлюза.

### 7.5 Обновить замеры

```bash
tools/bench.sh                           # или: tools/bench.sh -s <серийный номер>
```

Скрипт запускает на устройстве `DeviceExportTest#measure` и сохраняет результат в `bench/<производитель>-<модель>-api<версия SDK>.json`: скорость создания ключа и подписи в Keystore (TEE и, если есть, StrongBox) и скорость Vault. Сводную строку добавьте в таблицу [`bench/README.md`](../bench/README.md). Те же числа показывает карточка замеров в приложении `sample`.

### 7.6 Изменить публичный API

1. Публичные типы живут только в пакете `api/` и в объекте `DeviceTrust`.
2. Новый вариант в `sealed`-типе (`TrustEvent`, `TrustState`, `EnrollResult` и другие) ломает компиляцию приложения там, где `when` перечисляет варианты без `else`. Опишите изменение в [`API.md`, раздел 13](API.md#13-переход-с-предыдущей-версии).
3. Обновите соответствующий раздел [`API.md`](API.md), а при изменении поведения — [`ARCHITECTURE.md`](ARCHITECTURE.md).
4. Если меняется обмен со шлюзом, изменение должно быть согласовано со спецификацией S3 и вводиться так, чтобы прежние версии шлюза и библиотеки продолжали работать вместе. Пример — сводка RASP: библиотека отправляет новое поле только шлюзу, который объявил его поддержку.

## 8. Правила для документации

- Справочные документы описывают текущее поведение. История изменений остаётся в git и в `specs/`; в [`API.md`](API.md) ей отведён только раздел о переходе с предыдущей версии.
- Каждое утверждение проверяется по коду. Если документ и код расходятся, исправляется документ.
- Идентификаторы, команды и пути пишутся в обратных кавычках и без изменений.

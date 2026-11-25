// Texts of the init wizard in its 7 languages (11-REQ-05): questions, lessons, the summary and the
// manual instructions. Every language has the same keys and the same {placeholders}. Codes
// (INIT_*), file and option names, the written files and the other commands stay English. Pure.

export const LANGUAGES = ['en', 'es', 'fr', 'pl', 'it', 'uk', 'ru'] as const;
export type WizardLanguage = (typeof LANGUAGES)[number];

/** Names of the languages in themselves, shown in step 0. */
export const LANGUAGE_NAMES: Record<WizardLanguage, string> = {
  en: 'English',
  es: 'Español',
  fr: 'Français',
  pl: 'Polski',
  it: 'Italiano',
  uk: 'Українська',
  ru: 'Русский',
};

export function isWizardLanguage(value: string): value is WizardLanguage {
  return (LANGUAGES as readonly string[]).includes(value);
}

const en = {
  declinedInstalled: '{pkg} is installed; no file was changed.',
  declinedSteps: 'To set it up by hand:',
  declinedConfig:
    'Wrap the exported config in playwright.config with withSecurity() from {config}.',
  declinedTest:
    'Wrap your test object with withSecurityFixtures() from {fixture}, or import test from {test} instead of @playwright/test.',
  declinedRun: 'Accept the current state, review and commit the baseline, then scan: {example}',
  declinedDocs: 'Guide: {url}',
  declinedLater: 'Run {init} any time for the guided setup.',
  noTerminal:
    'no terminal: the default answers are used and nothing is written. Run the setup again in a terminal to write the changes.',
  dryRun: 'dry run: the planned changes are shown and nothing is written.',
  interrupted: 'interrupted.',
  answerAgain: 'Please answer again: that value is not valid here.',
  pressEnter: 'Press Enter to continue.',
  yes: 'yes',
  no: 'no',
  yesShort: 'y',
  noShort: 'n',
  stepProject: 'The package and how to use it',
  about1:
    '{pkg} scans the HTTP traffic your existing Playwright tests already produce (pages and API calls) for security issues: headers, cookies, CORS, tokens, secrets, information disclosure.',
  about2:
    'You accept the current state into a baseline file that you commit; from then on a run fails only when a new issue appears.',
  about3:
    'It is passive: it never sends a request of its own, so it does not attack your app and does not replace a penetration test.',
  usageTitle: 'How you will use it:',
  usageCheck: 'a dry run: does the scan see your traffic?',
  usageBaseline: 'accept the current state into security-baseline.json',
  usageReview: 'review the file and the report, add a note to each accepted entry, commit it',
  usageScan: 'in CI and locally: fails only on new findings',
  usageCommand:
    'Use the command you already run your tests with; the variable goes in front of it. On Windows put npx cross-env in front.',
  usageCommandPlaceholder: '<your test command>',
  variablesTitle: 'Other variables:',
  varEnv: 'one baseline per environment: security-baseline.<label>.json',
  varMaxTests: 'tests run by a check (default 10)',
  filesTitle: 'Files:',
  fileConfig: 'the package config (commit it)',
  fileBaseline: 'the baseline (commit it)',
  fileReport: 'reports (do not commit; added to .gitignore)',
  noConfigMessage: 'No playwright.config.* in {dir}.',
  noConfigHint: 'Run {command} in the directory of your Playwright config.',
  noConfigFound: 'Playwright configs found in subdirectories; run the setup there:',
  tooOldMessage:
    '@playwright/test {version} is older than {min}, the lowest version {pkg} supports.',
  tooOldHint: 'Update @playwright/test to {min} or later, then run {command} again.',
  stepRules: 'Rules',
  rulesLesson: 'The rules come in presets:',
  presetRecommended:
    'recommended: every rule except two strict-only header rules; the place to start.',
  presetStrict:
    'strict: every rule, and low-severity findings with high confidence count as medium.',
  presetMinimal: 'minimal: only rules with high confidence, for a quiet start.',
  presetQuestion: 'Rule preset? [recommended/strict/minimal]',
  stepGate: 'Gate',
  gateLesson:
    'Only new findings fail the scan, and only from this severity up; lower ones are reported as non-blocking. Findings in the baseline never fail it.',
  gateQuestion: 'Lowest severity of a new finding that fails the scan? [low/medium/high/critical]',
  stepOrigins: 'Origins of your app',
  originsLesson:
    'The scan analyses only responses of the origins in scope: the origin of use.baseURL and the ones you add. Analytics, fonts and CDNs are not your app: leave them out.',
  originsBase: 'From use.baseURL: {origin}',
  originsNoBase:
    "No baseURL literal found in playwright.config; add your app's origin here if the tests do not set one.",
  originsFound: 'Other origins found in your sources:',
  originsQuestion: 'Other origins of your app or API to scan (comma-separated, Enter for none)?',
  originsInvalid: '"{value}" is not an origin such as https://api.example.com.',
  stepEnvs: 'Environments',
  envsLesson:
    'If the same tests run against several environments (qa, staging…), each one gets its own baseline file with PW_SEC_ENV=<label>, because headers and cookies differ between them.',
  envsQuestion: 'Do you run these tests against several environments?',
  envsLabels: 'Environment labels (comma-separated, e.g. qa, staging)?',
  envsInvalid:
    '"{value}" is not a label: use lowercase letters, digits and -, at most 32 characters.',
  stepCommand: 'Test command',
  commandLesson1:
    'Type the command you usually run your tests with, e.g. npm run e2e:qa. The wizard does not change anything in it: it uses it in the commands at the end and for the check.',
  commandLesson2:
    'Enter keeps the suggested command; "skip" keeps it too and skips the check at the end.',
  commandQuestion: 'Which command do you usually run your tests with?',
  commandVariable:
    'Type the command without PW_SEC_ variables: the wizard adds PW_SEC_MODE itself.',
  commandChain:
    'This command chains several commands: PW_SEC_MODE=... in front of it only reaches the first one. Put the chain in a package.json script and type npm run <script>.',
  commandReporter:
    'This command or its script sets --reporter: a scan with it stops with RUN_REPORTER_FLAG. Add playwright-security-scan/reporter to the flag, or drop it.',
  stepChanges: 'Changes',
  changesLesson: 'Each change is shown as a diff before it is applied.',
  nothingToChange: 'Nothing to change: the project is already set up.',
  perfOrder:
    'withSecurity() must be outside withPerf(): in perf mode withPerf() keeps only the reporters it knows, so the scan would never run.',
  newFile: 'new file',
  modifiedFile: 'change',
  overwriteQuestion: '{path} exists. Overwrite it?',
  kept: '{path} exists and is kept.',
  applyQuestion: 'Apply this change?',
  fileWritten: 'Written: {path}',
  writeFailedMessage: 'Could not write {detail}',
  writeFailedHint: 'Check the permissions of the file and its directory, then run the setup again.',
  manualSecConfigKept: '{file} exists and was not changed.',
  manualSecConfigHint: 'Set these options in it if you want them:',
  manualConfigJson: '{config} was not changed: the package config is {file}.',
  manualConfigPattern:
    '{config} was not changed: its export is not a plain defineConfig({...}), withPerf(...) or object (for example another wrapper).',
  configHintIntro:
    'Wrap the exported config in withSecurity() as the outermost call (also around other wrappers):',
  configHintCjs: 'In {path} with module.exports: {call}.',
  manualDirectImports:
    'Test files that import test straight from @playwright/test are not scanned ({count}): {files}.',
  manualDirectImportsHint: 'Change the import in each of them:',
  manualDirectImportsModuleHint:
    'Import test from {module} in them, or change the import in each of them:',
  manualNewContext:
    'Calls of contexts made with request.newContext() are not scanned until each context is tracked ({count}): {files}.',
  manualNewContextHint: 'Track each context right after it is created:',
  boxTitle: 'Action needed: nothing is scanned yet',
  boxWhy: 'Without the security fixture the package sees no traffic. Add one of these by hand:',
  boxFixtures: 'If you have a fixtures file that exports test:',
  boxFixturesFiles: 'Files with .extend() and the number of test files that import each:',
  boxImports:
    'If your tests import test from @playwright/test (files: {count}), change the import in each of them:',
  boxDocs: 'Other layouts (mergeTests, several test objects, playwright-bdd): {url}',
  boxWrapThis: 'Wrap the one your tests import: {file}',
  boxWorkspace:
    '{file} is in the workspace package {pkg}: install {self} in the workspace root (e.g. pnpm add -Dw) or in that package too.',
  skipped: 'Skipped.',
  stepSummary: 'Summary',
  changedFiles: 'Changed files:',
  plannedChanges: 'Planned changes (not written):',
  noFilesChanged: 'No file was changed.',
  formatNote: 'Format the changed files with your formatter (e.g. prettier --write).',
  manualSteps: 'Manual steps: {count} (see the warnings above).',
  docs: 'Docs: {links}',
  finished: 'Setup finished.',
};

export type MessageKey = keyof typeof en;
export type Messages = Record<MessageKey, string>;

const pl: Messages = {
  declinedInstalled: '{pkg} jest zainstalowana; żaden plik nie został zmieniony.',
  declinedSteps: 'Aby skonfigurować ręcznie:',
  declinedConfig: 'Owiń eksportowany config w playwright.config funkcją withSecurity() z {config}.',
  declinedTest:
    'Owiń swój obiekt test funkcją withSecurityFixtures() z {fixture} albo importuj test z {test} zamiast z @playwright/test.',
  declinedRun: 'Przyjmij obecny stan, przejrzyj i zacommituj bazę, potem skanuj: {example}',
  declinedDocs: 'Przewodnik: {url}',
  declinedLater: 'Uruchom {init} w dowolnej chwili, aby przejść konfigurację z przewodnikiem.',
  noTerminal:
    'brak terminala: używane są odpowiedzi domyślne i nic nie jest zapisywane. Uruchom konfigurację ponownie w terminalu, aby zapisać zmiany.',
  dryRun: 'próba: planowane zmiany są pokazywane, nic nie jest zapisywane.',
  interrupted: 'przerwano.',
  answerAgain: 'Odpowiedz jeszcze raz: ta wartość nie jest tu dozwolona.',
  pressEnter: 'Naciśnij Enter, aby kontynuować.',
  yes: 'tak',
  no: 'nie',
  yesShort: 't',
  noShort: 'n',
  stepProject: 'Paczka i jak jej używać',
  about1:
    '{pkg} sprawdza pod kątem bezpieczeństwa ruch HTTP, który już generują Twoje testy Playwright (strony i wywołania API): nagłówki, ciasteczka, CORS, tokeny, sekrety, ujawnianie informacji.',
  about2:
    'Obecny stan przyjmujesz do pliku bazy, który commitujesz; od tej chwili run kończy się błędem tylko wtedy, gdy pojawi się nowy problem.',
  about3:
    'Skan jest pasywny: nigdy nie wysyła własnych żądań, więc nie atakuje aplikacji i nie zastępuje testu penetracyjnego.',
  usageTitle: 'Jak będziesz jej używać:',
  usageCheck: 'próbny przebieg: czy skan widzi Twój ruch?',
  usageBaseline: 'przyjęcie obecnego stanu do security-baseline.json',
  usageReview: 'przejrzyj plik i raport, dodaj notatkę do każdego przyjętego wpisu, zacommituj',
  usageScan: 'w CI i lokalnie: błąd tylko przy nowych znaleziskach',
  usageCommand:
    'Użyj polecenia, którym już uruchamiasz testy; zmienna idzie przed nim. Na Windowsie dodaj na początku npx cross-env.',
  usageCommandPlaceholder: '<twoje polecenie testów>',
  variablesTitle: 'Inne zmienne:',
  varEnv: 'osobna baza na środowisko: security-baseline.<etykieta>.json',
  varMaxTests: 'liczba testów w próbnym przebiegu (domyślnie 10)',
  filesTitle: 'Pliki:',
  fileConfig: 'konfiguracja paczki (commituj)',
  fileBaseline: 'baza (commituj)',
  fileReport: 'raporty (nie commituj; dopisane do .gitignore)',
  noConfigMessage: 'Brak playwright.config.* w {dir}.',
  noConfigHint: 'Uruchom {command} w katalogu z configiem Playwrighta.',
  noConfigFound: 'Znaleziono configi Playwrighta w podkatalogach; uruchom konfigurację tam:',
  tooOldMessage:
    '@playwright/test {version} jest starszy niż {min}, najniższa wersja obsługiwana przez {pkg}.',
  tooOldHint:
    'Zaktualizuj @playwright/test do {min} lub nowszej, potem uruchom {command} ponownie.',
  stepRules: 'Reguły',
  rulesLesson: 'Reguły są zebrane w presety:',
  presetRecommended:
    'recommended: wszystkie reguły poza dwiema regułami nagłówków tylko dla strict; dobry start.',
  presetStrict:
    'strict: wszystkie reguły, a znaleziska o niskiej ważności i wysokiej pewności liczą się jak medium.',
  presetMinimal: 'minimal: tylko reguły o wysokiej pewności, na spokojny start.',
  presetQuestion: 'Preset reguł? [recommended/strict/minimal]',
  stepGate: 'Próg',
  gateLesson:
    'Run oblewają tylko nowe znaleziska i tylko od tej ważności w górę; niższe są raportowane jako nieblokujące. Znaleziska z bazy nigdy go nie oblewają.',
  gateQuestion:
    'Najniższa ważność nowego znaleziska, które oblewa skan? [low/medium/high/critical]',
  stepOrigins: 'Originy aplikacji',
  originsLesson:
    'Skan analizuje tylko odpowiedzi originów w zakresie: originu use.baseURL i tych, które dodasz. Analityka, fonty i CDN to nie Twoja aplikacja: pomiń je.',
  originsBase: 'Z use.baseURL: {origin}',
  originsNoBase:
    'W playwright.config nie ma baseURL jako tekstu; dodaj tu origin aplikacji, jeśli testy go nie ustawiają.',
  originsFound: 'Inne originy znalezione w Twoich plikach:',
  originsQuestion:
    'Inne originy aplikacji albo API do skanowania (po przecinku, Enter, jeśli brak)?',
  originsInvalid: '"{value}" nie jest originem w rodzaju https://api.example.com.',
  stepEnvs: 'Środowiska',
  envsLesson:
    'Jeśli te same testy działają na kilku środowiskach (qa, staging…), każde dostaje własny plik bazy przez PW_SEC_ENV=<etykieta>, bo nagłówki i ciasteczka się między nimi różnią.',
  envsQuestion: 'Czy uruchamiasz te testy na kilku środowiskach?',
  envsLabels: 'Etykiety środowisk (po przecinku, np. qa, staging)?',
  envsInvalid: '"{value}" nie jest etykietą: użyj małych liter, cyfr i -, najwyżej 32 znaki.',
  stepCommand: 'Polecenie testów',
  commandLesson1:
    'Wpisz polecenie, którym zwykle uruchamiasz testy, np. npm run e2e:qa. Kreator niczego w nim nie zmienia: używa go w poleceniach na końcu i do sprawdzenia.',
  commandLesson2:
    'Enter zostawia proponowane polecenie; "skip" też je zostawia i pomija sprawdzenie na końcu.',
  commandQuestion: 'Jakim poleceniem zwykle uruchamiasz testy?',
  commandVariable: 'Wpisz polecenie bez zmiennych PW_SEC_: kreator sam dodaje PW_SEC_MODE.',
  commandChain:
    'To polecenie łączy kilka poleceń: PW_SEC_MODE=... przed nim dociera tylko do pierwszego. Umieść łańcuch w skrypcie package.json i wpisz npm run <skrypt>.',
  commandReporter:
    'To polecenie albo jego skrypt ustawia --reporter: skan z nim kończy się błędem RUN_REPORTER_FLAG. Dodaj playwright-security-scan/reporter do flagi albo ją usuń.',
  stepChanges: 'Zmiany',
  changesLesson: 'Każda zmiana jest pokazywana jako diff przed zastosowaniem.',
  nothingToChange: 'Nic do zmiany: projekt jest już skonfigurowany.',
  perfOrder:
    'withSecurity() musi być na zewnątrz withPerf(): w trybie perf withPerf() zostawia tylko znane sobie reportery, więc skan nigdy by się nie uruchomił.',
  newFile: 'nowy plik',
  modifiedFile: 'zmiana',
  overwriteQuestion: '{path} istnieje. Nadpisać?',
  kept: '{path} istnieje i zostaje bez zmian.',
  applyQuestion: 'Zastosować tę zmianę?',
  fileWritten: 'Zapisano: {path}',
  writeFailedMessage: 'Nie udało się zapisać {detail}',
  writeFailedHint:
    'Sprawdź uprawnienia pliku i jego katalogu, potem uruchom konfigurację ponownie.',
  manualSecConfigKept: '{file} istnieje i nie został zmieniony.',
  manualSecConfigHint: 'Ustaw w nim te opcje, jeśli ich chcesz:',
  manualConfigJson: '{config} nie został zmieniony: konfiguracja paczki to {file}.',
  manualConfigPattern:
    '{config} nie został zmieniony: jego eksport to nie zwykłe defineConfig({...}), withPerf(...) ani obiekt (np. inna nakładka).',
  configHintIntro:
    'Owiń eksportowany config w withSecurity() jako zewnętrzne wywołanie (także wokół innych nakładek):',
  configHintCjs: 'W {path} z module.exports: {call}.',
  manualDirectImports:
    'Pliki testów importujące test prosto z @playwright/test nie są skanowane ({count}): {files}.',
  manualDirectImportsHint: 'Zmień import w każdym z nich:',
  manualDirectImportsModuleHint:
    'Importuj w nich test z {module} albo zmień import w każdym z nich:',
  manualNewContext:
    'Wywołania kontekstów z request.newContext() nie są skanowane, dopóki każdy kontekst nie jest śledzony ({count}): {files}.',
  manualNewContextHint: 'Śledź każdy kontekst zaraz po utworzeniu:',
  boxTitle: 'Wymagana akcja: nic nie jest jeszcze skanowane',
  boxWhy: "Bez fixture'a paczki skan nie widzi żadnego ruchu. Dodaj ręcznie jedno z poniższych:",
  boxFixtures: "Jeśli masz plik fixture'ów eksportujący test:",
  boxFixturesFiles: 'Pliki z .extend() i liczba plików testów, które z każdego importują:',
  boxImports:
    'Jeśli testy importują test z @playwright/test (pliki: {count}), zmień import w każdym z nich:',
  boxDocs: 'Inne układy (mergeTests, kilka obiektów test, playwright-bdd): {url}',
  boxWrapThis: 'Owiń ten, który importują testy: {file}',
  boxWorkspace:
    '{file} jest w pakiecie workspace {pkg}: zainstaluj {self} w korzeniu workspace (np. pnpm add -Dw) albo także w tym pakiecie.',
  skipped: 'Pominięto.',
  stepSummary: 'Podsumowanie',
  changedFiles: 'Zmienione pliki:',
  plannedChanges: 'Planowane zmiany (niezapisane):',
  noFilesChanged: 'Żaden plik nie został zmieniony.',
  formatNote: 'Sformatuj zmienione pliki swoim formaterem (np. prettier --write).',
  manualSteps: 'Kroki ręczne: {count} (zobacz ostrzeżenia wyżej).',
  docs: 'Dokumentacja: {links}',
  finished: 'Konfiguracja zakończona.',
};

const es: Messages = {
  declinedInstalled: '{pkg} está instalado; no se cambió ningún archivo.',
  declinedSteps: 'Para configurarlo a mano:',
  declinedConfig:
    'Envuelve la configuración exportada en playwright.config con withSecurity() de {config}.',
  declinedTest:
    'Envuelve tu objeto test con withSecurityFixtures() de {fixture}, o importa test de {test} en lugar de @playwright/test.',
  declinedRun:
    'Acepta el estado actual, revisa y haz commit de la línea base y luego escanea: {example}',
  declinedDocs: 'Guía: {url}',
  declinedLater: 'Ejecuta {init} en cualquier momento para la configuración guiada.',
  noTerminal:
    'sin terminal: se usan las respuestas por defecto y no se escribe nada. Vuelve a ejecutar la configuración en un terminal para escribir los cambios.',
  dryRun: 'simulación: se muestran los cambios previstos y no se escribe nada.',
  interrupted: 'interrumpido.',
  answerAgain: 'Responde de nuevo: ese valor no es válido aquí.',
  pressEnter: 'Pulsa Intro para continuar.',
  yes: 'sí',
  no: 'no',
  yesShort: 's',
  noShort: 'n',
  stepProject: 'El paquete y cómo usarlo',
  about1:
    '{pkg} analiza en busca de problemas de seguridad el tráfico HTTP que ya generan tus tests de Playwright (páginas y llamadas a la API): cabeceras, cookies, CORS, tokens, secretos, divulgación de información.',
  about2:
    'Aceptas el estado actual en un archivo de línea base que guardas en el repositorio; desde entonces una ejecución falla solo cuando aparece un problema nuevo.',
  about3:
    'Es pasivo: nunca envía peticiones propias, así que no ataca tu aplicación y no sustituye una prueba de penetración.',
  usageTitle: 'Cómo lo usarás:',
  usageCheck: 'una prueba en seco: ¿ve el escaneo tu tráfico?',
  usageBaseline: 'aceptar el estado actual en security-baseline.json',
  usageReview: 'revisa el archivo y el informe, añade una nota a cada entrada aceptada, haz commit',
  usageScan: 'en CI y en local: falla solo con hallazgos nuevos',
  usageCommand:
    'Usa el comando con el que ya ejecutas tus tests; la variable va delante. En Windows antepón npx cross-env.',
  usageCommandPlaceholder: '<tu comando de tests>',
  variablesTitle: 'Otras variables:',
  varEnv: 'una línea base por entorno: security-baseline.<etiqueta>.json',
  varMaxTests: 'tests de una prueba en seco (por defecto 10)',
  filesTitle: 'Archivos:',
  fileConfig: 'la configuración del paquete (haz commit)',
  fileBaseline: 'la línea base (haz commit)',
  fileReport: 'informes (sin commit; añadidos a .gitignore)',
  noConfigMessage: 'No hay playwright.config.* en {dir}.',
  noConfigHint: 'Ejecuta {command} en el directorio de tu configuración de Playwright.',
  noConfigFound:
    'Hay configuraciones de Playwright en subdirectorios; ejecuta la configuración allí:',
  tooOldMessage:
    '@playwright/test {version} es anterior a {min}, la versión más baja que admite {pkg}.',
  tooOldHint: 'Actualiza @playwright/test a {min} o posterior y vuelve a ejecutar {command}.',
  stepRules: 'Reglas',
  rulesLesson: 'Las reglas vienen en presets:',
  presetRecommended:
    'recommended: todas las reglas salvo dos reglas de cabeceras solo de strict; el punto de partida.',
  presetStrict:
    'strict: todas las reglas, y los hallazgos de severidad baja con confianza alta cuentan como medium.',
  presetMinimal: 'minimal: solo reglas con confianza alta, para un comienzo tranquilo.',
  presetQuestion: '¿Preset de reglas? [recommended/strict/minimal]',
  stepGate: 'Umbral',
  gateLesson:
    'Solo los hallazgos nuevos hacen fallar el escaneo, y solo desde esta severidad; los inferiores se informan como no bloqueantes. Los hallazgos de la línea base nunca lo hacen fallar.',
  gateQuestion:
    '¿Severidad mínima de un hallazgo nuevo que hace fallar el escaneo? [low/medium/high/critical]',
  stepOrigins: 'Orígenes de tu aplicación',
  originsLesson:
    'El escaneo analiza solo respuestas de los orígenes en alcance: el origen de use.baseURL y los que añadas. Analítica, fuentes y CDN no son tu aplicación: déjalos fuera.',
  originsBase: 'De use.baseURL: {origin}',
  originsNoBase:
    'No hay un baseURL literal en playwright.config; añade aquí el origen de tu aplicación si los tests no lo definen.',
  originsFound: 'Otros orígenes encontrados en tus fuentes:',
  originsQuestion:
    '¿Otros orígenes de tu aplicación o API a escanear (separados por comas, Intro si ninguno)?',
  originsInvalid: '"{value}" no es un origen como https://api.example.com.',
  stepEnvs: 'Entornos',
  envsLesson:
    'Si los mismos tests se ejecutan en varios entornos (qa, staging…), cada uno tiene su propio archivo de línea base con PW_SEC_ENV=<etiqueta>, porque las cabeceras y cookies difieren entre ellos.',
  envsQuestion: '¿Ejecutas estos tests en varios entornos?',
  envsLabels: '¿Etiquetas de los entornos (separadas por comas, p. ej. qa, staging)?',
  envsInvalid:
    '"{value}" no es una etiqueta: usa minúsculas, dígitos y -, como máximo 32 caracteres.',
  stepCommand: 'Comando de tests',
  commandLesson1:
    'Escribe el comando con el que sueles ejecutar tus tests, p. ej. npm run e2e:qa. El asistente no cambia nada en él: lo usa en los comandos del final y para la comprobación.',
  commandLesson2:
    'Intro mantiene el comando sugerido; "skip" también lo mantiene y omite la comprobación final.',
  commandQuestion: '¿Con qué comando sueles ejecutar tus tests?',
  commandVariable:
    'Escribe el comando sin variables PW_SEC_: el asistente añade PW_SEC_MODE por sí mismo.',
  commandChain:
    'Este comando encadena varios comandos: PW_SEC_MODE=... delante solo llega al primero. Pon la cadena en un script de package.json y escribe npm run <script>.',
  commandReporter:
    'Este comando o su script define --reporter: un escaneo con él termina con RUN_REPORTER_FLAG. Añade playwright-security-scan/reporter a la opción o quítala.',
  stepChanges: 'Cambios',
  changesLesson: 'Cada cambio se muestra como un diff antes de aplicarlo.',
  nothingToChange: 'Nada que cambiar: el proyecto ya está configurado.',
  perfOrder:
    'withSecurity() debe estar fuera de withPerf(): en modo perf withPerf() conserva solo los reporters que conoce, así que el escaneo nunca se ejecutaría.',
  newFile: 'archivo nuevo',
  modifiedFile: 'cambio',
  overwriteQuestion: '{path} existe. ¿Sobrescribirlo?',
  kept: '{path} existe y se mantiene.',
  applyQuestion: '¿Aplicar este cambio?',
  fileWritten: 'Escrito: {path}',
  writeFailedMessage: 'No se pudo escribir {detail}',
  writeFailedHint:
    'Comprueba los permisos del archivo y de su directorio y vuelve a ejecutar la configuración.',
  manualSecConfigKept: '{file} existe y no se modificó.',
  manualSecConfigHint: 'Define en él estas opciones si las quieres:',
  manualConfigJson: '{config} no se modificó: la configuración del paquete es {file}.',
  manualConfigPattern:
    '{config} no se modificó: su export no es un simple defineConfig({...}), withPerf(...) ni un objeto (por ejemplo, otro envoltorio).',
  configHintIntro:
    'Envuelve la configuración exportada en withSecurity() como llamada exterior (también alrededor de otros envoltorios):',
  configHintCjs: 'En {path} con module.exports: {call}.',
  manualDirectImports:
    'Los archivos de tests que importan test directamente de @playwright/test no se escanean ({count}): {files}.',
  manualDirectImportsHint: 'Cambia la importación en cada uno:',
  manualDirectImportsModuleHint:
    'Importa test de {module} en ellos, o cambia la importación en cada uno:',
  manualNewContext:
    'Las llamadas de contextos creados con request.newContext() no se escanean hasta que cada contexto se rastrea ({count}): {files}.',
  manualNewContextHint: 'Rastrea cada contexto justo después de crearlo:',
  boxTitle: 'Acción necesaria: todavía no se escanea nada',
  boxWhy:
    'Sin el fixture del paquete el escaneo no ve tráfico. Añade a mano una de estas opciones:',
  boxFixtures: 'Si tienes un archivo de fixtures que exporta test:',
  boxFixturesFiles:
    'Archivos con .extend() y el número de archivos de tests que importan cada uno:',
  boxImports:
    'Si tus tests importan test de @playwright/test (archivos: {count}), cambia la importación en cada uno:',
  boxDocs: 'Otras estructuras (mergeTests, varios objetos test, playwright-bdd): {url}',
  boxWrapThis: 'Envuelve el que importan tus tests: {file}',
  boxWorkspace:
    '{file} está en el paquete del workspace {pkg}: instala {self} en la raíz del workspace (p. ej. pnpm add -Dw) o también en ese paquete.',
  skipped: 'Omitido.',
  stepSummary: 'Resumen',
  changedFiles: 'Archivos cambiados:',
  plannedChanges: 'Cambios previstos (no escritos):',
  noFilesChanged: 'No se cambió ningún archivo.',
  formatNote: 'Formatea los archivos cambiados con tu formateador (p. ej. prettier --write).',
  manualSteps: 'Pasos manuales: {count} (ver los avisos de arriba).',
  docs: 'Documentación: {links}',
  finished: 'Configuración terminada.',
};

const fr: Messages = {
  declinedInstalled: '{pkg} est installé ; aucun fichier n’a été modifié.',
  declinedSteps: 'Pour le configurer à la main :',
  declinedConfig:
    'Enveloppez la configuration exportée de playwright.config avec withSecurity() de {config}.',
  declinedTest:
    'Enveloppez votre objet test avec withSecurityFixtures() de {fixture}, ou importez test depuis {test} au lieu de @playwright/test.',
  declinedRun: 'Acceptez l’état actuel, relisez et commitez la référence, puis scannez : {example}',
  declinedDocs: 'Guide : {url}',
  declinedLater: 'Lancez {init} à tout moment pour la configuration guidée.',
  noTerminal:
    'pas de terminal : les réponses par défaut sont utilisées et rien n’est écrit. Relancez la configuration dans un terminal pour écrire les modifications.',
  dryRun: 'simulation : les modifications prévues sont affichées et rien n’est écrit.',
  interrupted: 'interrompu.',
  answerAgain: 'Répondez à nouveau : cette valeur n’est pas valide ici.',
  pressEnter: 'Appuyez sur Entrée pour continuer.',
  yes: 'oui',
  no: 'non',
  yesShort: 'o',
  noShort: 'n',
  stepProject: 'Le paquet et comment l’utiliser',
  about1:
    '{pkg} analyse sous l’angle de la sécurité le trafic HTTP que vos tests Playwright produisent déjà (pages et appels d’API) : en-têtes, cookies, CORS, jetons, secrets, divulgation d’informations.',
  about2:
    'Vous acceptez l’état actuel dans un fichier de référence que vous commitez ; ensuite, une exécution échoue seulement quand un nouveau problème apparaît.',
  about3:
    'Il est passif : il n’envoie jamais de requête à lui, donc il n’attaque pas votre application et ne remplace pas un test d’intrusion.',
  usageTitle: 'Comment vous l’utiliserez :',
  usageCheck: 'un essai à blanc : le scan voit-il votre trafic ?',
  usageBaseline: 'accepter l’état actuel dans security-baseline.json',
  usageReview:
    'relisez le fichier et le rapport, ajoutez une note à chaque entrée acceptée, commitez',
  usageScan: 'en CI et en local : échoue seulement sur de nouveaux résultats',
  usageCommand:
    'Utilisez la commande avec laquelle vous lancez déjà vos tests ; la variable se place devant. Sous Windows, ajoutez npx cross-env devant.',
  usageCommandPlaceholder: '<votre commande de tests>',
  variablesTitle: 'Autres variables :',
  varEnv: 'une référence par environnement : security-baseline.<label>.json',
  varMaxTests: 'tests d’un essai à blanc (10 par défaut)',
  filesTitle: 'Fichiers :',
  fileConfig: 'la configuration du paquet (à commiter)',
  fileBaseline: 'la référence (à commiter)',
  fileReport: 'rapports (à ne pas commiter ; ajoutés à .gitignore)',
  noConfigMessage: 'Aucun playwright.config.* dans {dir}.',
  noConfigHint: 'Lancez {command} dans le dossier de votre configuration Playwright.',
  noConfigFound:
    'Des configurations Playwright existent dans des sous-dossiers ; lancez la configuration là :',
  tooOldMessage:
    '@playwright/test {version} est antérieur à {min}, la plus ancienne version prise en charge par {pkg}.',
  tooOldHint: 'Mettez @playwright/test à jour vers {min} ou plus, puis relancez {command}.',
  stepRules: 'Règles',
  rulesLesson: 'Les règles sont regroupées en presets :',
  presetRecommended:
    'recommended : toutes les règles sauf deux règles d’en-têtes réservées à strict ; le point de départ.',
  presetStrict:
    'strict : toutes les règles, et les résultats de faible gravité à confiance élevée comptent comme medium.',
  presetMinimal: 'minimal : seulement les règles à confiance élevée, pour un démarrage calme.',
  presetQuestion: 'Preset de règles ? [recommended/strict/minimal]',
  stepGate: 'Seuil',
  gateLesson:
    'Seuls les nouveaux résultats font échouer le scan, et seulement à partir de cette gravité ; les autres sont signalés comme non bloquants. Les résultats de la référence ne le font jamais échouer.',
  gateQuestion:
    'Gravité minimale d’un nouveau résultat qui fait échouer le scan ? [low/medium/high/critical]',
  stepOrigins: 'Origines de votre application',
  originsLesson:
    'Le scan n’analyse que les réponses des origines dans le périmètre : l’origine de use.baseURL et celles que vous ajoutez. Statistiques, polices et CDN ne sont pas votre application : laissez-les de côté.',
  originsBase: 'Depuis use.baseURL : {origin}',
  originsNoBase:
    'Aucun baseURL littéral dans playwright.config ; ajoutez ici l’origine de votre application si les tests ne la définissent pas.',
  originsFound: 'Autres origines trouvées dans vos sources :',
  originsQuestion:
    'Autres origines de votre application ou API à scanner (séparées par des virgules, Entrée si aucune) ?',
  originsInvalid: '« {value} » n’est pas une origine comme https://api.example.com.',
  stepEnvs: 'Environnements',
  envsLesson:
    'Si les mêmes tests tournent sur plusieurs environnements (qa, staging…), chacun a son propre fichier de référence avec PW_SEC_ENV=<label>, car les en-têtes et les cookies diffèrent.',
  envsQuestion: 'Lancez-vous ces tests sur plusieurs environnements ?',
  envsLabels: 'Labels des environnements (séparés par des virgules, ex. qa, staging) ?',
  envsInvalid:
    '« {value} » n’est pas un label : utilisez des minuscules, des chiffres et -, 32 caractères au plus.',
  stepCommand: 'Commande de tests',
  commandLesson1:
    'Saisissez la commande avec laquelle vous lancez habituellement vos tests, ex. npm run e2e:qa. L’assistant n’y change rien : il l’utilise dans les commandes de la fin et pour la vérification.',
  commandLesson2:
    'Entrée garde la commande proposée ; « skip » la garde aussi et saute la vérification finale.',
  commandQuestion: 'Avec quelle commande lancez-vous habituellement vos tests ?',
  commandVariable:
    'Saisissez la commande sans variables PW_SEC_ : l’assistant ajoute PW_SEC_MODE lui-même.',
  commandChain:
    'Cette commande enchaîne plusieurs commandes : PW_SEC_MODE=... devant n’atteint que la première. Mettez la chaîne dans un script de package.json et saisissez npm run <script>.',
  commandReporter:
    'Cette commande ou son script définit --reporter : un scan avec elle s’arrête sur RUN_REPORTER_FLAG. Ajoutez playwright-security-scan/reporter à l’option, ou retirez-la.',
  stepChanges: 'Modifications',
  changesLesson: 'Chaque modification est affichée sous forme de diff avant d’être appliquée.',
  nothingToChange: 'Rien à modifier : le projet est déjà configuré.',
  perfOrder:
    'withSecurity() doit être à l’extérieur de withPerf() : en mode perf, withPerf() ne garde que les reporters qu’il connaît, donc le scan ne s’exécuterait jamais.',
  newFile: 'nouveau fichier',
  modifiedFile: 'modification',
  overwriteQuestion: '{path} existe. L’écraser ?',
  kept: '{path} existe et est conservé.',
  applyQuestion: 'Appliquer cette modification ?',
  fileWritten: 'Écrit : {path}',
  writeFailedMessage: 'Impossible d’écrire {detail}',
  writeFailedHint:
    'Vérifiez les droits du fichier et de son dossier, puis relancez la configuration.',
  manualSecConfigKept: '{file} existe et n’a pas été modifié.',
  manualSecConfigHint: 'Définissez-y ces options si vous les voulez :',
  manualConfigJson: '{config} n’a pas été modifié : la configuration du paquet est {file}.',
  manualConfigPattern:
    '{config} n’a pas été modifié : son export n’est pas un simple defineConfig({...}), withPerf(...) ou objet (par exemple une autre enveloppe).',
  configHintIntro:
    'Enveloppez la configuration exportée dans withSecurity() comme appel le plus extérieur (aussi autour d’autres enveloppes) :',
  configHintCjs: 'Dans {path} avec module.exports : {call}.',
  manualDirectImports:
    'Les fichiers de tests qui importent test directement depuis @playwright/test ne sont pas scannés ({count}) : {files}.',
  manualDirectImportsHint: 'Changez l’import dans chacun d’eux :',
  manualDirectImportsModuleHint:
    'Importez test depuis {module} dans ces fichiers, ou changez l’import dans chacun d’eux :',
  manualNewContext:
    'Les appels des contextes créés avec request.newContext() ne sont pas scannés tant que chaque contexte n’est pas suivi ({count}) : {files}.',
  manualNewContextHint: 'Suivez chaque contexte juste après sa création :',
  boxTitle: 'Action requise : rien n’est encore scanné',
  boxWhy:
    'Sans la fixture du paquet, le scan ne voit aucun trafic. Ajoutez l’une de ces options à la main :',
  boxFixtures: 'Si vous avez un fichier de fixtures qui exporte test :',
  boxFixturesFiles:
    'Fichiers avec .extend() et le nombre de fichiers de tests qui importent chacun :',
  boxImports:
    'Si vos tests importent test depuis @playwright/test (fichiers : {count}), changez l’import dans chacun d’eux :',
  boxDocs: 'Autres structures (mergeTests, plusieurs objets test, playwright-bdd) : {url}',
  boxWrapThis: 'Enveloppez celui que vos tests importent : {file}',
  boxWorkspace:
    '{file} est dans le paquet du workspace {pkg} : installez {self} à la racine du workspace (ex. pnpm add -Dw) ou aussi dans ce paquet.',
  skipped: 'Ignoré.',
  stepSummary: 'Résumé',
  changedFiles: 'Fichiers modifiés :',
  plannedChanges: 'Modifications prévues (non écrites) :',
  noFilesChanged: 'Aucun fichier n’a été modifié.',
  formatNote: 'Formatez les fichiers modifiés avec votre formateur (ex. prettier --write).',
  manualSteps: 'Étapes manuelles : {count} (voir les avertissements ci-dessus).',
  docs: 'Documentation : {links}',
  finished: 'Configuration terminée.',
};

const it: Messages = {
  declinedInstalled: '{pkg} è installato; nessun file è stato modificato.',
  declinedSteps: 'Per configurarlo a mano:',
  declinedConfig:
    'Avvolgi la configurazione esportata in playwright.config con withSecurity() da {config}.',
  declinedTest:
    'Avvolgi il tuo oggetto test con withSecurityFixtures() da {fixture}, oppure importa test da {test} invece che da @playwright/test.',
  declinedRun:
    'Accetta lo stato attuale, rivedi e fai commit della baseline, poi esegui la scansione: {example}',
  declinedDocs: 'Guida: {url}',
  declinedLater: 'Esegui {init} in qualsiasi momento per la configurazione guidata.',
  noTerminal:
    'nessun terminale: si usano le risposte predefinite e non si scrive nulla. Riesegui la configurazione in un terminale per scrivere le modifiche.',
  dryRun: 'prova: le modifiche previste vengono mostrate e non si scrive nulla.',
  interrupted: 'interrotto.',
  answerAgain: 'Rispondi di nuovo: quel valore qui non è valido.',
  pressEnter: 'Premi Invio per continuare.',
  yes: 'sì',
  no: 'no',
  yesShort: 's',
  noShort: 'n',
  stepProject: 'Il pacchetto e come usarlo',
  about1:
    '{pkg} analizza dal punto di vista della sicurezza il traffico HTTP che i tuoi test Playwright producono già (pagine e chiamate API): header, cookie, CORS, token, segreti, divulgazione di informazioni.',
  about2:
    'Accetti lo stato attuale in un file di baseline che metti in commit; da allora un’esecuzione fallisce solo quando compare un problema nuovo.',
  about3:
    'È passivo: non invia mai richieste proprie, quindi non attacca la tua applicazione e non sostituisce un penetration test.',
  usageTitle: 'Come lo userai:',
  usageCheck: 'una prova a secco: la scansione vede il tuo traffico?',
  usageBaseline: 'accettare lo stato attuale in security-baseline.json',
  usageReview: 'rivedi il file e il report, aggiungi una nota a ogni voce accettata, fai commit',
  usageScan: 'in CI e in locale: fallisce solo con risultati nuovi',
  usageCommand:
    'Usa il comando con cui esegui già i test; la variabile va davanti. Su Windows anteponi npx cross-env.',
  usageCommandPlaceholder: '<il tuo comando di test>',
  variablesTitle: 'Altre variabili:',
  varEnv: 'una baseline per ambiente: security-baseline.<etichetta>.json',
  varMaxTests: 'test di una prova a secco (predefinito 10)',
  filesTitle: 'File:',
  fileConfig: 'la configurazione del pacchetto (in commit)',
  fileBaseline: 'la baseline (in commit)',
  fileReport: 'report (non in commit; aggiunti a .gitignore)',
  noConfigMessage: 'Nessun playwright.config.* in {dir}.',
  noConfigHint: 'Esegui {command} nella cartella della configurazione di Playwright.',
  noConfigFound: 'Trovate configurazioni Playwright in sottocartelle; esegui lì la configurazione:',
  tooOldMessage:
    '@playwright/test {version} è precedente a {min}, la versione minima supportata da {pkg}.',
  tooOldHint: 'Aggiorna @playwright/test a {min} o successiva, poi riesegui {command}.',
  stepRules: 'Regole',
  rulesLesson: 'Le regole sono raccolte in preset:',
  presetRecommended:
    'recommended: tutte le regole tranne due regole sugli header riservate a strict; il punto di partenza.',
  presetStrict:
    'strict: tutte le regole, e i risultati di gravità bassa con confidenza alta contano come medium.',
  presetMinimal: 'minimal: solo regole con confidenza alta, per un inizio tranquillo.',
  presetQuestion: 'Preset delle regole? [recommended/strict/minimal]',
  stepGate: 'Soglia',
  gateLesson:
    'Solo i risultati nuovi fanno fallire la scansione, e solo da questa gravità in su; quelli inferiori sono segnalati come non bloccanti. I risultati nella baseline non la fanno mai fallire.',
  gateQuestion:
    'Gravità minima di un nuovo risultato che fa fallire la scansione? [low/medium/high/critical]',
  stepOrigins: 'Origini della tua applicazione',
  originsLesson:
    'La scansione analizza solo le risposte delle origini nel perimetro: l’origine di use.baseURL e quelle che aggiungi. Statistiche, font e CDN non sono la tua applicazione: lasciali fuori.',
  originsBase: 'Da use.baseURL: {origin}',
  originsNoBase:
    'Nessun baseURL letterale in playwright.config; aggiungi qui l’origine dell’applicazione se i test non la impostano.',
  originsFound: 'Altre origini trovate nei tuoi sorgenti:',
  originsQuestion:
    'Altre origini della tua applicazione o API da scansionare (separate da virgole, Invio se nessuna)?',
  originsInvalid: '"{value}" non è un’origine come https://api.example.com.',
  stepEnvs: 'Ambienti',
  envsLesson:
    'Se gli stessi test girano su più ambienti (qa, staging…), ognuno ha il proprio file di baseline con PW_SEC_ENV=<etichetta>, perché header e cookie cambiano tra loro.',
  envsQuestion: 'Esegui questi test su più ambienti?',
  envsLabels: 'Etichette degli ambienti (separate da virgole, es. qa, staging)?',
  envsInvalid:
    '"{value}" non è un’etichetta: usa lettere minuscole, cifre e -, al massimo 32 caratteri.',
  stepCommand: 'Comando dei test',
  commandLesson1:
    'Scrivi il comando con cui esegui di solito i test, es. npm run e2e:qa. La procedura non cambia nulla: lo usa nei comandi finali e per la verifica.',
  commandLesson2:
    'Invio mantiene il comando proposto; "skip" lo mantiene e salta la verifica finale.',
  commandQuestion: 'Con quale comando esegui di solito i test?',
  commandVariable:
    'Scrivi il comando senza variabili PW_SEC_: la procedura aggiunge PW_SEC_MODE da sola.',
  commandChain:
    'Questo comando concatena più comandi: PW_SEC_MODE=... davanti raggiunge solo il primo. Metti la catena in uno script di package.json e scrivi npm run <script>.',
  commandReporter:
    'Questo comando o il suo script imposta --reporter: una scansione con esso si ferma con RUN_REPORTER_FLAG. Aggiungi playwright-security-scan/reporter all’opzione, oppure toglila.',
  stepChanges: 'Modifiche',
  changesLesson: 'Ogni modifica viene mostrata come diff prima di essere applicata.',
  nothingToChange: 'Niente da cambiare: il progetto è già configurato.',
  perfOrder:
    'withSecurity() deve stare fuori da withPerf(): in modalità perf withPerf() tiene solo i reporter che conosce, quindi la scansione non partirebbe mai.',
  newFile: 'nuovo file',
  modifiedFile: 'modifica',
  overwriteQuestion: '{path} esiste. Sovrascriverlo?',
  kept: '{path} esiste e viene mantenuto.',
  applyQuestion: 'Applicare questa modifica?',
  fileWritten: 'Scritto: {path}',
  writeFailedMessage: 'Impossibile scrivere {detail}',
  writeFailedHint:
    'Controlla i permessi del file e della sua cartella, poi riesegui la configurazione.',
  manualSecConfigKept: '{file} esiste e non è stato modificato.',
  manualSecConfigHint: 'Imposta in esso queste opzioni se le vuoi:',
  manualConfigJson: '{config} non è stato modificato: la configurazione del pacchetto è {file}.',
  manualConfigPattern:
    '{config} non è stato modificato: il suo export non è un semplice defineConfig({...}), withPerf(...) o oggetto (per esempio un altro wrapper).',
  configHintIntro:
    'Avvolgi la configurazione esportata in withSecurity() come chiamata più esterna (anche attorno ad altri wrapper):',
  configHintCjs: 'In {path} con module.exports: {call}.',
  manualDirectImports:
    'I file di test che importano test direttamente da @playwright/test non sono scansionati ({count}): {files}.',
  manualDirectImportsHint: 'Cambia l’import in ciascuno:',
  manualDirectImportsModuleHint:
    'Importa test da {module} in essi, oppure cambia l’import in ciascuno:',
  manualNewContext:
    'Le chiamate dei contesti creati con request.newContext() non sono scansionate finché ogni contesto non è tracciato ({count}): {files}.',
  manualNewContextHint: 'Traccia ogni contesto subito dopo averlo creato:',
  boxTitle: 'Azione necessaria: non si scansiona ancora nulla',
  boxWhy:
    'Senza la fixture del pacchetto la scansione non vede traffico. Aggiungi a mano una di queste opzioni:',
  boxFixtures: 'Se hai un file di fixture che esporta test:',
  boxFixturesFiles: 'File con .extend() e il numero di file di test che importano ciascuno:',
  boxImports:
    'Se i test importano test da @playwright/test (file: {count}), cambia l’import in ciascuno:',
  boxDocs: 'Altre strutture (mergeTests, più oggetti test, playwright-bdd): {url}',
  boxWrapThis: 'Avvolgi quello che importano i test: {file}',
  boxWorkspace:
    '{file} è nel pacchetto workspace {pkg}: installa {self} nella radice del workspace (es. pnpm add -Dw) o anche in quel pacchetto.',
  skipped: 'Saltato.',
  stepSummary: 'Riepilogo',
  changedFiles: 'File modificati:',
  plannedChanges: 'Modifiche previste (non scritte):',
  noFilesChanged: 'Nessun file è stato modificato.',
  formatNote: 'Formatta i file modificati con il tuo formattatore (es. prettier --write).',
  manualSteps: 'Passi manuali: {count} (vedi gli avvisi sopra).',
  docs: 'Documentazione: {links}',
  finished: 'Configurazione completata.',
};

const uk: Messages = {
  declinedInstalled: '{pkg} встановлено; жоден файл не змінено.',
  declinedSteps: 'Щоб налаштувати вручну:',
  declinedConfig:
    'Обгорніть експортований конфіг у playwright.config функцією withSecurity() з {config}.',
  declinedTest:
    'Обгорніть свій об’єкт test функцією withSecurityFixtures() з {fixture} або імпортуйте test з {test} замість @playwright/test.',
  declinedRun: 'Прийміть поточний стан, перегляньте й закомітьте базу, потім скануйте: {example}',
  declinedDocs: 'Посібник: {url}',
  declinedLater: 'Запустіть {init} будь-коли для налаштування з посібником.',
  noTerminal:
    'немає термінала: використано відповіді за замовчуванням, нічого не записано. Запустіть налаштування в терміналі, щоб записати зміни.',
  dryRun: 'пробний запуск: показано заплановані зміни, нічого не записано.',
  interrupted: 'перервано.',
  answerAgain: 'Дайте відповідь ще раз: це значення тут неприпустиме.',
  pressEnter: 'Натисніть Enter, щоб продовжити.',
  yes: 'так',
  no: 'ні',
  yesShort: 'т',
  noShort: 'н',
  stepProject: 'Пакет і як ним користуватися',
  about1:
    '{pkg} перевіряє на проблеми безпеки HTTP-трафік, який уже створюють ваші тести Playwright (сторінки й виклики API): заголовки, cookie, CORS, токени, секрети, розкриття інформації.',
  about2:
    'Поточний стан ви приймаєте у файл бази, який комітите; відтоді запуск падає лише тоді, коли з’являється нова проблема.',
  about3:
    'Сканування пасивне: воно ніколи не надсилає власних запитів, тож не атакує застосунок і не замінює тест на проникнення.',
  usageTitle: 'Як ви ним користуватиметеся:',
  usageCheck: 'пробний запуск: чи бачить сканування ваш трафік?',
  usageBaseline: 'прийняти поточний стан у security-baseline.json',
  usageReview: 'перегляньте файл і звіт, додайте нотатку до кожного прийнятого запису, закомітьте',
  usageScan: 'у CI та локально: падає лише на нових знахідках',
  usageCommand:
    'Використовуйте команду, якою вже запускаєте тести; змінна ставиться перед нею. У Windows додайте на початку npx cross-env.',
  usageCommandPlaceholder: '<ваша команда тестів>',
  variablesTitle: 'Інші змінні:',
  varEnv: 'окрема база для кожного середовища: security-baseline.<мітка>.json',
  varMaxTests: 'кількість тестів пробного запуску (за замовчуванням 10)',
  filesTitle: 'Файли:',
  fileConfig: 'конфігурація пакета (комітити)',
  fileBaseline: 'база (комітити)',
  fileReport: 'звіти (не комітити; додано до .gitignore)',
  noConfigMessage: 'У {dir} немає playwright.config.*.',
  noConfigHint: 'Запустіть {command} у каталозі з конфігом Playwright.',
  noConfigFound: 'Знайдено конфіги Playwright у підкаталогах; запустіть налаштування там:',
  tooOldMessage:
    '@playwright/test {version} старіший за {min}, найнижчу версію, яку підтримує {pkg}.',
  tooOldHint: 'Оновіть @playwright/test до {min} або новішої, потім знову запустіть {command}.',
  stepRules: 'Правила',
  rulesLesson: 'Правила зібрано в пресети:',
  presetRecommended:
    'recommended: усі правила, крім двох правил заголовків лише для strict; з цього варто почати.',
  presetStrict:
    'strict: усі правила, а знахідки низької важливості з високою впевненістю рахуються як medium.',
  presetMinimal: 'minimal: лише правила з високою впевненістю, для спокійного старту.',
  presetQuestion: 'Пресет правил? [recommended/strict/minimal]',
  stepGate: 'Поріг',
  gateLesson:
    'Сканування валять лише нові знахідки і лише від цієї важливості; нижчі показуються як неблокувальні. Знахідки з бази ніколи його не валять.',
  gateQuestion:
    'Найнижча важливість нової знахідки, що валить сканування? [low/medium/high/critical]',
  stepOrigins: 'Origin вашого застосунку',
  originsLesson:
    'Сканування аналізує лише відповіді origin у межах: origin з use.baseURL і ті, що ви додасте. Аналітика, шрифти й CDN — не ваш застосунок: не додавайте їх.',
  originsBase: 'З use.baseURL: {origin}',
  originsNoBase:
    'У playwright.config немає baseURL як тексту; додайте тут origin застосунку, якщо тести його не задають.',
  originsFound: 'Інші origin, знайдені у ваших файлах:',
  originsQuestion: 'Інші origin застосунку або API для сканування (через кому, Enter, якщо немає)?',
  originsInvalid: '"{value}" не є origin на кшталт https://api.example.com.',
  stepEnvs: 'Середовища',
  envsLesson:
    'Якщо ті самі тести запускаються на кількох середовищах (qa, staging…), кожне отримує власний файл бази через PW_SEC_ENV=<мітка>, бо заголовки й cookie між ними різняться.',
  envsQuestion: 'Чи запускаєте ви ці тести на кількох середовищах?',
  envsLabels: 'Мітки середовищ (через кому, напр. qa, staging)?',
  envsInvalid:
    '"{value}" не є міткою: використовуйте малі літери, цифри та -, щонайбільше 32 символи.',
  stepCommand: 'Команда тестів',
  commandLesson1:
    'Введіть команду, якою зазвичай запускаєте тести, напр. npm run e2e:qa. Майстер нічого в ній не змінює: використовує її в командах наприкінці та для перевірки.',
  commandLesson2:
    'Enter залишає запропоновану команду; "skip" теж її залишає й пропускає перевірку наприкінці.',
  commandQuestion: 'Якою командою ви зазвичай запускаєте тести?',
  commandVariable: 'Введіть команду без змінних PW_SEC_: майстер сам додає PW_SEC_MODE.',
  commandChain:
    'Ця команда поєднує кілька команд: PW_SEC_MODE=... перед нею дістається лише першої. Винесіть ланцюжок у скрипт package.json і введіть npm run <скрипт>.',
  commandReporter:
    'Ця команда або її скрипт задає --reporter: сканування з нею зупиняється з RUN_REPORTER_FLAG. Додайте playwright-security-scan/reporter до прапорця або приберіть його.',
  stepChanges: 'Зміни',
  changesLesson: 'Кожна зміна показується як diff перед застосуванням.',
  nothingToChange: 'Нічого змінювати: проєкт уже налаштовано.',
  perfOrder:
    'withSecurity() має бути зовні withPerf(): у режимі perf withPerf() залишає лише відомі йому репортери, тож сканування ніколи б не запустилося.',
  newFile: 'новий файл',
  modifiedFile: 'зміна',
  overwriteQuestion: '{path} існує. Перезаписати?',
  kept: '{path} існує й залишається без змін.',
  applyQuestion: 'Застосувати цю зміну?',
  fileWritten: 'Записано: {path}',
  writeFailedMessage: 'Не вдалося записати {detail}',
  writeFailedHint: 'Перевірте права файлу та його каталогу, потім знову запустіть налаштування.',
  manualSecConfigKept: '{file} існує і не змінений.',
  manualSecConfigHint: 'Задайте в ньому ці параметри, якщо вони потрібні:',
  manualConfigJson: '{config} не змінено: конфігурація пакета — {file}.',
  manualConfigPattern:
    '{config} не змінено: його експорт — не простий defineConfig({...}), withPerf(...) чи об’єкт (наприклад, інша обгортка).',
  configHintIntro:
    'Обгорніть експортований конфіг у withSecurity() як зовнішній виклик (також навколо інших обгорток):',
  configHintCjs: 'У {path} з module.exports: {call}.',
  manualDirectImports:
    'Файли тестів, що імпортують test напряму з @playwright/test, не скануються ({count}): {files}.',
  manualDirectImportsHint: 'Змініть імпорт у кожному з них:',
  manualDirectImportsModuleHint:
    'Імпортуйте в них test з {module} або змініть імпорт у кожному з них:',
  manualNewContext:
    'Виклики контекстів, створених через request.newContext(), не скануються, доки кожен контекст не відстежується ({count}): {files}.',
  manualNewContextHint: 'Відстежуйте кожен контекст одразу після створення:',
  boxTitle: 'Потрібна дія: поки нічого не сканується',
  boxWhy: 'Без фікстури пакета сканування не бачить трафіку. Додайте вручну один із варіантів:',
  boxFixtures: 'Якщо у вас є файл фікстур, що експортує test:',
  boxFixturesFiles: 'Файли з .extend() і кількість файлів тестів, що імпортують кожен:',
  boxImports:
    'Якщо тести імпортують test з @playwright/test (файлів: {count}), змініть імпорт у кожному з них:',
  boxDocs: 'Інші структури (mergeTests, кілька об’єктів test, playwright-bdd): {url}',
  boxWrapThis: 'Обгорніть той, який імпортують тести: {file}',
  boxWorkspace:
    '{file} лежить у пакеті workspace {pkg}: встановіть {self} у корені workspace (напр. pnpm add -Dw) або також у цьому пакеті.',
  skipped: 'Пропущено.',
  stepSummary: 'Підсумок',
  changedFiles: 'Змінені файли:',
  plannedChanges: 'Заплановані зміни (не записані):',
  noFilesChanged: 'Жоден файл не змінено.',
  formatNote: 'Відформатуйте змінені файли своїм форматером (напр. prettier --write).',
  manualSteps: 'Ручні кроки: {count} (див. попередження вище).',
  docs: 'Документація: {links}',
  finished: 'Налаштування завершено.',
};

const ru: Messages = {
  declinedInstalled: '{pkg} установлен; ни один файл не изменён.',
  declinedSteps: 'Чтобы настроить вручную:',
  declinedConfig:
    'Оберните экспортируемый конфиг в playwright.config функцией withSecurity() из {config}.',
  declinedTest:
    'Оберните свой объект test функцией withSecurityFixtures() из {fixture} или импортируйте test из {test} вместо @playwright/test.',
  declinedRun:
    'Примите текущее состояние, просмотрите и закоммитьте базу, затем сканируйте: {example}',
  declinedDocs: 'Руководство: {url}',
  declinedLater: 'Запустите {init} в любой момент для пошаговой настройки.',
  noTerminal:
    'нет терминала: используются ответы по умолчанию, ничего не записывается. Запустите настройку в терминале, чтобы записать изменения.',
  dryRun: 'пробный запуск: показаны запланированные изменения, ничего не записано.',
  interrupted: 'прервано.',
  answerAgain: 'Ответьте ещё раз: это значение здесь недопустимо.',
  pressEnter: 'Нажмите Enter, чтобы продолжить.',
  yes: 'да',
  no: 'нет',
  yesShort: 'д',
  noShort: 'н',
  stepProject: 'Пакет и как им пользоваться',
  about1:
    '{pkg} проверяет на проблемы безопасности HTTP-трафик, который уже создают ваши тесты Playwright (страницы и вызовы API): заголовки, cookie, CORS, токены, секреты, раскрытие информации.',
  about2:
    'Текущее состояние вы принимаете в файл базы, который коммитите; с этого момента запуск падает только при появлении новой проблемы.',
  about3:
    'Сканирование пассивное: оно никогда не отправляет собственных запросов, поэтому не атакует приложение и не заменяет тест на проникновение.',
  usageTitle: 'Как вы будете им пользоваться:',
  usageCheck: 'пробный запуск: видит ли сканирование ваш трафик?',
  usageBaseline: 'принять текущее состояние в security-baseline.json',
  usageReview: 'просмотрите файл и отчёт, добавьте заметку к каждой принятой записи, закоммитьте',
  usageScan: 'в CI и локально: падает только на новых находках',
  usageCommand:
    'Используйте команду, которой уже запускаете тесты; переменная ставится перед ней. В Windows добавьте в начале npx cross-env.',
  usageCommandPlaceholder: '<ваша команда тестов>',
  variablesTitle: 'Другие переменные:',
  varEnv: 'отдельная база для каждого окружения: security-baseline.<метка>.json',
  varMaxTests: 'число тестов пробного запуска (по умолчанию 10)',
  filesTitle: 'Файлы:',
  fileConfig: 'конфигурация пакета (коммитить)',
  fileBaseline: 'база (коммитить)',
  fileReport: 'отчёты (не коммитить; добавлено в .gitignore)',
  noConfigMessage: 'В {dir} нет playwright.config.*.',
  noConfigHint: 'Запустите {command} в каталоге с конфигом Playwright.',
  noConfigFound: 'Найдены конфиги Playwright в подкаталогах; запустите настройку там:',
  tooOldMessage:
    '@playwright/test {version} старше {min}, самой ранней версии, которую поддерживает {pkg}.',
  tooOldHint: 'Обновите @playwright/test до {min} или новее, затем снова запустите {command}.',
  stepRules: 'Правила',
  rulesLesson: 'Правила собраны в пресеты:',
  presetRecommended:
    'recommended: все правила, кроме двух правил заголовков только для strict; с него стоит начать.',
  presetStrict:
    'strict: все правила, а находки низкой важности с высокой уверенностью считаются medium.',
  presetMinimal: 'minimal: только правила с высокой уверенностью, для спокойного старта.',
  presetQuestion: 'Пресет правил? [recommended/strict/minimal]',
  stepGate: 'Порог',
  gateLesson:
    'Сканирование валят только новые находки и только начиная с этой важности; более низкие показываются как неблокирующие. Находки из базы никогда его не валят.',
  gateQuestion:
    'Наименьшая важность новой находки, которая валит сканирование? [low/medium/high/critical]',
  stepOrigins: 'Origin вашего приложения',
  originsLesson:
    'Сканирование анализирует только ответы origin в области: origin из use.baseURL и те, что вы добавите. Аналитика, шрифты и CDN — не ваше приложение: не добавляйте их.',
  originsBase: 'Из use.baseURL: {origin}',
  originsNoBase:
    'В playwright.config нет baseURL в виде текста; добавьте здесь origin приложения, если тесты его не задают.',
  originsFound: 'Другие origin, найденные в ваших файлах:',
  originsQuestion:
    'Другие origin приложения или API для сканирования (через запятую, Enter, если нет)?',
  originsInvalid: '"{value}" не является origin вроде https://api.example.com.',
  stepEnvs: 'Окружения',
  envsLesson:
    'Если одни и те же тесты запускаются на нескольких окружениях (qa, staging…), каждое получает свой файл базы через PW_SEC_ENV=<метка>, потому что заголовки и cookie в них различаются.',
  envsQuestion: 'Запускаете ли вы эти тесты на нескольких окружениях?',
  envsLabels: 'Метки окружений (через запятую, напр. qa, staging)?',
  envsInvalid:
    '"{value}" не является меткой: используйте строчные буквы, цифры и -, не более 32 символов.',
  stepCommand: 'Команда тестов',
  commandLesson1:
    'Введите команду, которой обычно запускаете тесты, напр. npm run e2e:qa. Мастер ничего в ней не меняет: использует её в командах в конце и для проверки.',
  commandLesson2:
    'Enter оставляет предложенную команду; "skip" тоже её оставляет и пропускает проверку в конце.',
  commandQuestion: 'Какой командой вы обычно запускаете тесты?',
  commandVariable: 'Введите команду без переменных PW_SEC_: мастер сам добавляет PW_SEC_MODE.',
  commandChain:
    'Эта команда объединяет несколько команд: PW_SEC_MODE=... перед ней доходит только до первой. Вынесите цепочку в скрипт package.json и введите npm run <скрипт>.',
  commandReporter:
    'Эта команда или её скрипт задаёт --reporter: сканирование с ней останавливается с RUN_REPORTER_FLAG. Добавьте playwright-security-scan/reporter к флагу или уберите его.',
  stepChanges: 'Изменения',
  changesLesson: 'Каждое изменение показывается как diff перед применением.',
  nothingToChange: 'Менять нечего: проект уже настроен.',
  perfOrder:
    'withSecurity() должен быть снаружи withPerf(): в режиме perf withPerf() оставляет только известные ему репортеры, поэтому сканирование никогда бы не запустилось.',
  newFile: 'новый файл',
  modifiedFile: 'изменение',
  overwriteQuestion: '{path} существует. Перезаписать?',
  kept: '{path} существует и остаётся без изменений.',
  applyQuestion: 'Применить это изменение?',
  fileWritten: 'Записано: {path}',
  writeFailedMessage: 'Не удалось записать {detail}',
  writeFailedHint: 'Проверьте права файла и его каталога, затем снова запустите настройку.',
  manualSecConfigKept: '{file} существует и не изменён.',
  manualSecConfigHint: 'Задайте в нём эти параметры, если они нужны:',
  manualConfigJson: '{config} не изменён: конфигурация пакета — {file}.',
  manualConfigPattern:
    '{config} не изменён: его экспорт — не простой defineConfig({...}), withPerf(...) или объект (например, другая обёртка).',
  configHintIntro:
    'Оберните экспортируемый конфиг в withSecurity() как внешний вызов (также вокруг других обёрток):',
  configHintCjs: 'В {path} с module.exports: {call}.',
  manualDirectImports:
    'Файлы тестов, импортирующие test напрямую из @playwright/test, не сканируются ({count}): {files}.',
  manualDirectImportsHint: 'Измените импорт в каждом из них:',
  manualDirectImportsModuleHint:
    'Импортируйте в них test из {module} или измените импорт в каждом из них:',
  manualNewContext:
    'Вызовы контекстов, созданных через request.newContext(), не сканируются, пока каждый контекст не отслеживается ({count}): {files}.',
  manualNewContextHint: 'Отслеживайте каждый контекст сразу после создания:',
  boxTitle: 'Нужно действие: пока ничего не сканируется',
  boxWhy: 'Без фикстуры пакета сканирование не видит трафика. Добавьте вручную один из вариантов:',
  boxFixtures: 'Если у вас есть файл фикстур, экспортирующий test:',
  boxFixturesFiles: 'Файлы с .extend() и число файлов тестов, которые импортируют каждый:',
  boxImports:
    'Если тесты импортируют test из @playwright/test (файлов: {count}), измените импорт в каждом из них:',
  boxDocs: 'Другие структуры (mergeTests, несколько объектов test, playwright-bdd): {url}',
  boxWrapThis: 'Оберните тот, который импортируют тесты: {file}',
  boxWorkspace:
    '{file} находится в пакете workspace {pkg}: установите {self} в корне workspace (напр. pnpm add -Dw) или также в этом пакете.',
  skipped: 'Пропущено.',
  stepSummary: 'Итог',
  changedFiles: 'Изменённые файлы:',
  plannedChanges: 'Запланированные изменения (не записаны):',
  noFilesChanged: 'Ни один файл не изменён.',
  formatNote: 'Отформатируйте изменённые файлы своим форматтером (напр. prettier --write).',
  manualSteps: 'Ручные шаги: {count} (см. предупреждения выше).',
  docs: 'Документация: {links}',
  finished: 'Настройка завершена.',
};

export const MESSAGES: Record<WizardLanguage, Messages> = { en, es, fr, pl, it, uk, ru };

const PLACEHOLDER = /\{(\w+)\}/gu;

/** The {name} placeholders of a text, sorted and without duplicates. */
export function placeholders(text: string): string[] {
  return [...new Set([...text.matchAll(PLACEHOLDER)].map((m) => m[1] as string))].sort();
}

export type MessageValues = Readonly<Record<string, string | number>>;

/** The text with each {name} replaced by its value; unknown names stay as they are. */
export function format(text: string, values: MessageValues = {}): string {
  return text.replace(PLACEHOLDER, (whole, name: string) =>
    values[name] === undefined ? whole : String(values[name]),
  );
}

export type Translate = (key: MessageKey, values?: MessageValues) => string;

export function translator(lang: WizardLanguage): Translate {
  return (key, values) => format(MESSAGES[lang][key], values);
}

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

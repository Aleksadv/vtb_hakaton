### Структура проекта

```
api-security-scanner/
├── pom.xml
├── .gitignore
├── README.md
├── target/                         # собираемые артефакты (jar + отчёты)
│   └── reports/
│       ├── VirtualBankAPI-YYYYMMDD-HHMMSS.json
│       └── VirtualBankAPI-YYYYMMDD-HHMMSS.pdf
└── src/
    ├── main/
    │   └── java/
    │       └── securityscanner/
    │           ├── auditor/
    │           │   └── APISecurityAuditor.java
    │           ├── core/
    │           │   ├── ExecutionContext.java
    │           │   ├── PluginRegistry.java
    │           │   ├── SecurityPlugin.java
    │           │   └── model/
    │           │       └── Finding.java
    │           ├── generator/
    │           │   └── ScenarioGenerator.java
    │           ├── http/
    │           │   └── RequestExecutor.java
    │           ├── parser/
    │           │   └── OpenAPIParserSimple.java
    │           ├── plugins/
    │           │   ├── BolaPlugin.java
    │           │   ├── MassAssignmentPlugin.java
    │           │   └── RateLimitPlugin.java
    │           ├── report/
    │           │   ├── ReportWriter.java
    │           │   └── ResponseValidator.java
    │           └── runner/
    │               └── BankingAPIScanner.java
    └── test/
        └── java/                   

```
parser/ — парсинг и резолв схем (OpenAPI 3.1)

generator/ — генерация сценариев (positive/negative)

auditor/ — главный координирующий класс, использует всё остальное

core/ — инфраструктура и контекст (ExecutionContext, модель Finding)

plugins/ — OWASP API Top-10 проверки (BOLA, Mass Assignment, RateLimit)

report/ — валидация + JSON/PDF отчёты

http/ — унифицированные сетевые запросы

runner/ — точка входа (main), CLI-параметры
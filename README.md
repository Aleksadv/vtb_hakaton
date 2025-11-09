## **СТРУКТУРА ПРОЕКТА API SECURITY SCANNER**

```
api-security-scanner/
├── pom.xml
├── README.md
├── run_scan.ps1
├── .gitignore
├── target/
│   └── reports/
│       ├── VirtualBankAPI-YYYYMMDD-HHMMSS.json
│       └── VirtualBankAPI-YYYYMMDD-HHMMSS.pdf
└── src/
    └── main/
        └── java/
            └── securityscanner/
                ├── auditor/
                │   └── APISecurityAuditor.java
                ├── core/
                │   ├── ExecutionContext.java
                │   ├── PluginRegistry.java
                │   ├── SecurityPlugin.java
                │   ├── BaseSecurityPlugin.java
                │   ├── ResponseValidator.java
                │   └── model/
                │       └── Finding.java
                ├── generator/
                │   └── ScenarioGenerator.java
                ├── http/
                │   └── RequestExecutor.java
                ├── parser/
                │   └── OpenAPIParserSimple.java
                ├── plugins/
                │   ├── APIHealthPlugin.java
                │   ├── AuthenticationPlugin.java
                │   ├── BolaPlugin.java
                │   ├── BrokenFunctionAuthPlugin.java
                │   ├── BusinessFlowPlugin.java
                │   ├── InjectionPlugin.java
                │   ├── InventoryManagementPlugin.java
                │   ├── ObjectPropertyAuthPlugin.java
                │   ├── ResourceConsumptionPlugin.java
                │   ├── SecurityHeadersPlugin.java
                │   ├── SecurityMisconfigPlugin.java
                │   ├── SSRFPlugin.java
                │   └── UnsafeConsumptionPlugin.java
                ├── report/
                │   └── ReportWriter.java
                └── runner/
                    └── BankingAPIScanner.java
```

---

# API Security Scanner

Автоматизированный сканер безопасности API для банковских систем.

## Быстрый запуск

```powershell
.\run_scan.ps1
```

Скрипт `run_scan.ps1` содержит все необходимые параметры для подключения к тестовому стенду Virtual Bank API.

## Описание

Сканер выполняет комплексную проверку безопасности API согласно OWASP API Security Top 10 :

- **API1:** - Broken Object Level Authorization (BOLA)
- **API2:** - Broken Authentication  
- **API3:** - Broken Object Property Level Authorization
- **API4:** - Unrestricted Resource Consumption
- **API5:** - Broken Function Level Authorization
- **API6:** - Unrestricted Access to Sensitive Business Flows
- **API7:** - Server Side Request Forgery (SSRF)
- **API8:** - Security Misconfiguration
- **API9:** - Improper Inventory Management
- **API10:** - Unsafe Consumption of APIs

## Форматы отчетов

После выполнения сканирования генерируются отчеты в форматах:
- **JSON** - для автоматической обработки и интеграции
- **PDF** - для ручного анализа и презентаций

Отчеты сохраняются в папку `target/reports/` с timestamp в имени файла.

## Технические требования

- Java 17 или выше
- Maven 3.6+
- Доступ к API Virtual Bank (https://vbank.open.bankingapi.ru)
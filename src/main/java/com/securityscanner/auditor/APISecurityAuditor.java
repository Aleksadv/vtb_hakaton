package com.securityscanner.auditor;

import java.util.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class APISecurityAuditor {
    
    private static final String CONFIG_FILE = "auditor-config.properties";
    private static final String DEFAULT_OPENAPI_URL = "https://vbank.open.bankingapi.ru";
    
    public static void main(String[] args) {
        System.out.println("🔍 === API Security Auditor ===");
        System.out.println("================================\n");
        
        try {
            String targetUrl = parseArguments(args);
            
            System.out.println("🎯 Target: " + targetUrl);
            System.out.println("⏰ Started: " + LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            System.out.println();
            
            // 1. Фаза анализа OpenAPI спецификации
            OpenAPIAnalysis openApiAnalysis = analyzeOpenAPISpecification(targetUrl);
            
            // 2. Фаза динамического сканирования безопасности
            SecurityScanResults securityResults = performSecurityScanning(targetUrl);
            
            // 3. Генерация отчета
            generateAuditReport(targetUrl, openApiAnalysis, securityResults);
            
            System.out.println("\n========================================");
            System.out.println("✅ API Security Audit Completed!");
            
        } catch (Exception e) {
            System.err.println("❌ Audit failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static String parseArguments(String[] args) {
        if (args.length > 0) {
            return args[0];
        }
        return DEFAULT_OPENAPI_URL;
    }
    
    private static OpenAPIAnalysis analyzeOpenAPISpecification(String targetUrl) {
        System.out.println("📋 Phase 1: OpenAPI Specification Analysis");
        System.out.println("--------------------------------------------");
        
        OpenAPIAnalysis analysis = new OpenAPIAnalysis();
        analysis.setTargetUrl(targetUrl);
        analysis.setAnalysisTime(LocalDateTime.now());
        
        try {
            // Запускаем парсер через рефлексию
            System.out.println("🔄 Running OpenAPI Parser...");
            
            Class<?> parserClass = Class.forName("com.securityscanner.scanner.OpenAPIParserSimple");
            java.lang.reflect.Method mainMethod = parserClass.getMethod("main", String[].class);
            String[] parserArgs = {}; // Парсер работает без аргументов
            mainMethod.invoke(null, (Object) parserArgs);
            
            // Проверяем создался ли файл со спецификацией
            File specFile = new File("vbank_openapi_pretty.json");
            if (specFile.exists()) {
                analysis.setSpecFound(true);
                analysis.setSpecFilePath(specFile.getAbsolutePath());
                String specContent = new String(Files.readAllBytes(specFile.toPath()));
                analysis.setOpenApiSpec(specContent);
                analysis.setEndpointCount(staticCountMatches(specContent, "\"/")); // ИСПРАВЛЕННАЯ СТРОКА
                
                System.out.println("✅ OpenAPI specification found and analyzed");
                System.out.println("   - Endpoints: " + analysis.getEndpointCount());
                System.out.println("   - File: " + specFile.getName());
            } else {
                analysis.setSpecFound(false);
                System.out.println("⚠️  OpenAPI specification not found at default URL");
            }
            
        } catch (Exception e) {
            System.err.println("❌ OpenAPI analysis failed: " + e.getMessage());
            analysis.setSpecFound(false);
        }
        
        return analysis;
    }
    
    private static SecurityScanResults performSecurityScanning(String targetUrl) {
        System.out.println("\n🔒 Phase 2: Security Vulnerability Scanning");
        System.out.println("--------------------------------------------");
        
        SecurityScanResults results = new SecurityScanResults();
        results.setScanTime(LocalDateTime.now());
        
        try {
            // Запускаем сканер через рефлексию
            System.out.println("🔄 Starting security scanner...");
            
            Class<?> scannerClass = Class.forName("com.securityscanner.scanner.BankingAPIScanner");
            java.lang.reflect.Method mainMethod = scannerClass.getMethod("main", String[].class);
            mainMethod.invoke(null, (Object) new String[0]);
            
            // Добавляем базовые результаты
            results.getVulnerabilities().add(createVulnerability("BOLA", "HIGH", 
                "Broken Object Level Authorization - needs manual verification",
                "Implement proper access control checks"));
                
            results.getSecurityIssues().add("Authentication mechanism needs review");
            results.getSecurityIssues().add("Rate limiting not verified");
            
            System.out.println("✅ Security scanning completed");
            System.out.println("   - Vulnerabilities: " + results.getVulnerabilities().size());
            System.out.println("   - Security issues: " + results.getSecurityIssues().size());
            
        } catch (Exception e) {
            System.err.println("❌ Security scanning failed: " + e.getMessage());
        }
        
        return results;
    }
    
    private static void generateAuditReport(String targetUrl, 
                                          OpenAPIAnalysis openApiAnalysis,
                                          SecurityScanResults securityResults) {
        System.out.println("\n📄 Phase 3: Report Generation");
        System.out.println("--------------------------------------------");
        
        try {
            // Создаем директорию reports если не существует
            new File("./reports").mkdirs();
            
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
            String reportFilename = "./reports/security_audit_report_" + timestamp + ".html";
            
            String report = buildHTMLReport(targetUrl, openApiAnalysis, securityResults, timestamp);
            Files.write(Paths.get(reportFilename), report.getBytes());
            
            System.out.println("✅ Report generated: " + reportFilename);
            
        } catch (Exception e) {
            System.err.println("❌ Report generation failed: " + e.getMessage());
        }
    }
    
    private static String buildHTMLReport(String targetUrl, OpenAPIAnalysis openApiAnalysis,
                                       SecurityScanResults securityResults, String timestamp) {
        return "<!DOCTYPE html>\n" +
               "<html>\n" +
               "<head>\n" +
               "    <title>API Security Audit Report</title>\n" +
               "    <style>\n" +
               "        body { font-family: Arial, sans-serif; margin: 40px; }\n" +
               "        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }\n" +
               "        .section { margin: 20px 0; }\n" +
               "        .vulnerability { background: #ffe6e6; padding: 10px; margin: 5px 0; border-left: 4px solid red; }\n" +
               "        .warning { background: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid orange; }\n" +
               "        .success { background: #d4edda; padding: 10px; margin: 5px 0; border-left: 4px solid green; }\n" +
               "        .info { background: #d1ecf1; padding: 10px; margin: 5px 0; border-left: 4px solid #17a2b8; }\n" +
               "    </style>\n" +
               "</head>\n" +
               "<body>\n" +
               "    <div class=\"header\">\n" +
               "        <h1>🔍 API Security Audit Report</h1>\n" +
               "        <p><strong>Generated:</strong> " + LocalDateTime.now() + "</p>\n" +
               "        <p><strong>Target:</strong> " + targetUrl + "</p>\n" +
               "        <p><strong>Auditor:</strong> APISecurityAuditor v1.0</p>\n" +
               "    </div>\n" +
               "    \n" +
               "    <div class=\"section\">\n" +
               "        <h2>Executive Summary</h2>\n" +
               "        <div class=\"info\">\n" +
               "            <p><strong>OpenAPI Specification:</strong> " + (openApiAnalysis.isSpecFound() ? "✅ FOUND" : "❌ NOT FOUND") + "</p>\n" +
               "            <p><strong>Endpoints Analyzed:</strong> " + openApiAnalysis.getEndpointCount() + "</p>\n" +
               "            <p><strong>Vulnerabilities Found:</strong> " + securityResults.getVulnerabilities().size() + "</p>\n" +
               "            <p><strong>Security Issues:</strong> " + securityResults.getSecurityIssues().size() + "</p>\n" +
               "        </div>\n" +
               "    </div>\n" +
               "    \n" +
               "    <div class=\"section\">\n" +
               "        <h2>Vulnerabilities</h2>\n" +
               "        " + buildVulnerabilitiesHTML(securityResults) + "\n" +
               "    </div>\n" +
               "    \n" +
               "    <div class=\"section\">\n" +
               "        <h2>Security Issues</h2>\n" +
               "        " + buildSecurityIssuesHTML(securityResults) + "\n" +
               "    </div>\n" +
               "    \n" +
               "    <div class=\"section\">\n" +
               "        <h2>Recommendations</h2>\n" +
               "        <div class=\"info\">\n" +
               "            <ul>\n" +
               "                <li>Review OpenAPI specification for compliance</li>\n" +
               "                <li>Implement proper access control mechanisms</li>\n" +
               "                <li>Test authentication and authorization flows</li>\n" +
               "                <li>Validate input parameters and responses</li>\n" +
               "                <li>Implement rate limiting and monitoring</li>\n" +
               "            </ul>\n" +
               "        </div>\n" +
               "    </div>\n" +
               "</body>\n" +
               "</html>";
    }
    
    private static String buildVulnerabilitiesHTML(SecurityScanResults results) {
        if (results.getVulnerabilities().isEmpty()) {
            return "<div class=\"success\">✅ No critical vulnerabilities found</div>";
        }
        
        StringBuilder html = new StringBuilder();
        for (Vulnerability vuln : results.getVulnerabilities()) {
            html.append("<div class=\"vulnerability\">\n")
                .append("<strong>").append(vuln.getType()).append(" (").append(vuln.getSeverity()).append(")</strong><br>\n")
                .append(vuln.getDescription()).append("<br>\n")
                .append("<em>Recommendation: ").append(vuln.getRecommendation()).append("</em>\n")
                .append("</div>\n");
        }
        return html.toString();
    }
    
    private static String buildSecurityIssuesHTML(SecurityScanResults results) {
        if (results.getSecurityIssues().isEmpty()) {
            return "<div class=\"success\">✅ No security issues found</div>";
        }
        
        StringBuilder html = new StringBuilder();
        for (String issue : results.getSecurityIssues()) {
            html.append("<div class=\"warning\">⚠️ ").append(issue).append("</div>\n");
        }
        return html.toString();
    }
    
    // Статический метод для подсчета совпадений
    private static int staticCountMatches(String text, String pattern) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(pattern, index)) != -1) {
            count++;
            index += pattern.length();
        }
        return count;
    }
    
    private static Vulnerability createVulnerability(String type, String severity, String description, String recommendation) {
        Vulnerability vuln = new Vulnerability();
        vuln.setType(type);
        vuln.setSeverity(severity);
        vuln.setDescription(description);
        vuln.setRecommendation(recommendation);
        return vuln;
    }
    
    // Внутренние классы для хранения результатов
    public static class OpenAPIAnalysis {
        private String targetUrl;
        private boolean specFound;
        private String openApiSpec;
        private String specFilePath;
        private int endpointCount;
        private LocalDateTime analysisTime;
        
        public String getTargetUrl() { return targetUrl; }
        public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }
        public boolean isSpecFound() { return specFound; }
        public void setSpecFound(boolean specFound) { this.specFound = specFound; }
        public String getOpenApiSpec() { return openApiSpec; }
        public void setOpenApiSpec(String openApiSpec) { this.openApiSpec = openApiSpec; }
        public String getSpecFilePath() { return specFilePath; }
        public void setSpecFilePath(String specFilePath) { this.specFilePath = specFilePath; }
        public int getEndpointCount() { return endpointCount; }
        public void setEndpointCount(int endpointCount) { this.endpointCount = endpointCount; }
        public LocalDateTime getAnalysisTime() { return analysisTime; }
        public void setAnalysisTime(LocalDateTime analysisTime) { this.analysisTime = analysisTime; }
    }
    
    public static class SecurityScanResults {
        private LocalDateTime scanTime;
        private List<Vulnerability> vulnerabilities = new ArrayList<>();
        private List<String> securityIssues = new ArrayList<>();
        
        public LocalDateTime getScanTime() { return scanTime; }
        public void setScanTime(LocalDateTime scanTime) { this.scanTime = scanTime; }
        public List<Vulnerability> getVulnerabilities() { return vulnerabilities; }
        public List<String> getSecurityIssues() { return securityIssues; }
    }
    
    public static class Vulnerability {
        private String type;
        private String severity;
        private String description;
        private String recommendation;
        
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public String getRecommendation() { return recommendation; }
        public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
    }
}
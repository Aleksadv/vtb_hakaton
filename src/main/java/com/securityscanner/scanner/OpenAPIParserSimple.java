package com.securityscanner.scanner;

import java.net.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

public class OpenAPIParserSimple {
    
    private static final String BASE_URL = "https://vbank.open.bankingapi.ru";
    
    public static void main(String[] args) {
        System.out.println("Starting OpenAPI Parser...");
        
        try {
            String openApiSpec = getOpenAPISpecification();
            
            if (openApiSpec != null) {
                System.out.println("Success! Specification length: " + openApiSpec.length() + " chars");
                
                // Сохраним красиво отформатированный JSON
                savePrettyJson(openApiSpec, "vbank_openapi_pretty.json");
                System.out.println("Saved as formatted JSON to: vbank_openapi_pretty.json");
                
                // Быстрый анализ
                quickAnalysis(openApiSpec);
            } else {
                System.out.println("No OpenAPI spec found");
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static String getOpenAPISpecification() {
        String[] paths = {
            "/openapi.json",
            "/swagger.json",
            "/v3/api-docs", 
            "/api-docs",
            "/docs/swagger.json",
            "/swagger/v1/swagger.json",
            "/.well-known/openapi.json"
        };
        
        for (String path : paths) {
            System.out.println("Trying: " + path);
            String spec = fetchURL(BASE_URL + path);
            if (spec != null && spec.contains("openapi") && spec.contains("paths")) {
                System.out.println("Found at: " + path);
                return spec;
            }
        }
        return null;
    }
    
    private static String fetchURL(String urlString) {
        try {
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            
            if (conn.getResponseCode() == 200) {
                StringBuilder response = new StringBuilder();
                try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        response.append(line);
                    }
                }
                return response.toString();
            }
        } catch (Exception e) {
            // Ignore and try next
        }
        return null;
    }
    
    private static void savePrettyJson(String json, String filename) {
        try {
            // Простое форматирование JSON с отступами
            String prettyJson = formatJson(json);
            
            try (FileWriter writer = new FileWriter(filename)) {
                writer.write(prettyJson);
            }
            System.out.println("File saved: " + new File(filename).getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Could not save file: " + e.getMessage());
            // Сохраним как есть если форматирование не удалось
            try (FileWriter writer = new FileWriter(filename)) {
                writer.write(json);
            } catch (Exception ex) {
                System.err.println("Could not save at all: " + ex.getMessage());
            }
        }
    }
    
    private static String formatJson(String json) {
        StringBuilder pretty = new StringBuilder();
        int indentLevel = 0;
        boolean inQuotes = false;
        
        for (char c : json.toCharArray()) {
            switch (c) {
                case '{':
                case '[':
                    pretty.append(c);
                    if (!inQuotes) {
                        pretty.append("\n");
                        indentLevel++;
                        appendIndent(pretty, indentLevel);
                    }
                    break;
                    
                case '}':
                case ']':
                    if (!inQuotes) {
                        pretty.append("\n");
                        indentLevel--;
                        appendIndent(pretty, indentLevel);
                    }
                    pretty.append(c);
                    break;
                    
                case ',':
                    pretty.append(c);
                    if (!inQuotes) {
                        pretty.append("\n");
                        appendIndent(pretty, indentLevel);
                    }
                    break;
                    
                case ':':
                    pretty.append(c);
                    if (!inQuotes) {
                        pretty.append(" ");
                    }
                    break;
                    
                case '"':
                    pretty.append(c);
                    inQuotes = !inQuotes;
                    break;
                    
                default:
                    pretty.append(c);
                    break;
            }
        }
        
        return pretty.toString();
    }
    
    private static void appendIndent(StringBuilder sb, int level) {
        for (int i = 0; i < level; i++) {
            sb.append("  "); // 2 пробела на уровень
        }
    }
    
    private static void quickAnalysis(String spec) {
        System.out.println("\nQuick Analysis:");
        
        // OpenAPI version
        if (spec.contains("\"openapi\"")) {
            int start = spec.indexOf("\"openapi\":") + 10;
            int end = spec.indexOf("\"", start);
            System.out.println("OpenAPI Version: " + spec.substring(start, end));
        }
        
        // Count endpoints
        int endpointCount = countMatches(spec, "\"/");
        System.out.println("Estimated endpoints: " + endpointCount);
        
        // Count methods
        System.out.println("Methods:");
        System.out.println("   GET: " + countMatches(spec, "\"get\""));
        System.out.println("   POST: " + countMatches(spec, "\"post\""));
        System.out.println("   PUT: " + countMatches(spec, "\"put\""));
        System.out.println("   DELETE: " + countMatches(spec, "\"delete\""));
        
        // Check for security
        if (spec.contains("securitySchemes")) {
            System.out.println("Security schemes defined");
        }
        
        // Show some endpoints
        System.out.println("\nSample endpoints:");
        showSampleEndpoints(spec);
    }
    
    private static void showSampleEndpoints(String spec) {
        // Найдем первые 5 эндпоинтов
        int count = 0;
        int index = 0;
        
        while (count < 5 && (index = spec.indexOf("\"/", index)) != -1) {
            int end = spec.indexOf("\"", index + 2);
            if (end != -1) {
                String endpoint = spec.substring(index + 1, end);
                System.out.println("   " + endpoint);
                count++;
            }
            index = end;
        }
    }
    
    private static int countMatches(String text, String pattern) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(pattern, index)) != -1) {
            count++;
            index += pattern.length();
        }
        return count;
    }
}
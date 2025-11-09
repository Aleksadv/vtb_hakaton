package securityscanner.plugins;

import com.fasterxml.jackson.databind.JsonNode;
import securityscanner.core.ExecutionContext;
import securityscanner.core.SecurityPlugin;
import securityscanner.core.model.Finding;

import java.util.*;

/**
 * Плагин для проверки Improper Inventory Management - OWASP API9 
 * Проверяет устаревшие версии API, документацию и управление инвентарем
 */
public class InventoryManagementPlugin implements SecurityPlugin {
    @Override public String id() { return "API9: InventoryManagement"; }
    @Override public String title() { return "Improper Inventory Management"; }
    @Override public String description() { return "Проверка устаревших версий API и документации"; }

    @Override
    public List<Finding> run(ExecutionContext ctx) throws Exception {
        List<Finding> out = new ArrayList<>();

        // Проверка доступности OpenAPI спецификации
        if (ctx.openapiRoot == null) {
            out.add(Finding.of("N/A", "N/A", 0, id(),
                    Finding.Severity.LOW, "OpenAPI спецификация не доступна для анализа", ""));
            return out;
        }

        // Проверка информации о версии API из OpenAPI спецификации
        JsonNode info = ctx.openapiRoot.path("info");
        String version = info.path("version").asText();
        String title = info.path("title").asText();

        if (version != null && !version.isBlank()) {
            out.add(Finding.of("/info", "N/A", 0, id(),
                    Finding.Severity.INFO, "API версия: " + version + " (" + title + ")", ""));
        }

        // Проверка устаревших версий в путях API
        JsonNode paths = ctx.openapiRoot.path("paths");
        if (paths.isObject()) {
            Iterator<String> pathNames = paths.fieldNames();
            while (pathNames.hasNext()) {
                String path = pathNames.next();
                // Обнаружение путей с указанием версий (устаревшая практика)
                if (path.contains("/v1/") || path.contains("/v2/")) {
                    out.add(Finding.of(path, "N/A", 0, id(),
                            Finding.Severity.LOW, "Эндпоинт содержит указание версии в пути", path));
                }
            }
        }

        // Проверка серверов из OpenAPI спецификации
        JsonNode servers = ctx.openapiRoot.path("servers");
        if (servers.isArray()) {
            for (JsonNode server : servers) {
                String url = server.path("url").asText();
                if (url != null && !url.isBlank()) {
                    // Обнаружение тестовых/staging серверов в продакшн спецификации
                    if (url.contains("staging") || url.contains("test") || url.contains("dev")) {
                        out.add(Finding.of(url, "N/A", 0, id(),
                                Finding.Severity.MEDIUM, "Сервер может быть тестовым/staging", url));
                    }
                }
            }
        }

        return out;
    }
}
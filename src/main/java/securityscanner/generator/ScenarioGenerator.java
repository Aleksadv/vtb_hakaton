package securityscanner.generator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;

/**
 * Генератор тестовых сценариев на основе OpenAPI спецификации.
 * Создает позитивные и негативные сценарии для тестирования API.
 */
public class ScenarioGenerator {

    private final ObjectMapper om = new ObjectMapper();

    /**
     * Модель тестового сценария.
     * Содержит всю информацию для выполнения HTTP запроса.
     */
    public static class Scenario {
        public String path;                    // Путь эндпоинта
        public String method;                  // HTTP метод (GET/POST/PUT/DELETE)
        public Map<String,String> query = new LinkedHashMap<>(); // Query параметры
        public Map<String,String> headers = new LinkedHashMap<>(); // HTTP заголовки
        public JsonNode body;                  // Тело запроса (для POST/PUT)
        public String label;                   // Тип сценария: "positive" / "negative"

        /**
         * Создает копию сценария
         */
        public Scenario copy() {
            Scenario s = new Scenario();
            s.path = path;
            s.method = method;
            s.query = new LinkedHashMap<>(query);
            s.headers = new LinkedHashMap<>(headers);
            s.body = body;
            s.label = label;
            return s;
        }
    }

    /**
     * Генерирует список тестовых сценариев на основе OpenAPI спецификации
     * @param openapiRoot корневой узел OpenAPI спецификации
     * @param requestingBank идентификатор банка для межбанковских запросов
     * @param interbankClientId client_id для межбанковских операций
     * @return список тестовых сценариев
     */
    public List<Scenario> generate(JsonNode openapiRoot, String requestingBank, String interbankClient) {
        List<Scenario> out = new ArrayList<>();
        JsonNode paths = openapiRoot.path("paths");
        if (!paths.isObject()) return out;

        // Список эндпоинтов которые нужно пропустить из-за проблем со схемой
        Set<String> skipEndpoints = Set.of(
            "/account-consents/request",
            "/auth/bank-token", 
            "/product-agreement-consents/request",
            "/product-agreements"
        );

        Iterator<String> it = paths.fieldNames();
        while (it.hasNext()) {
            String p = it.next();
            
            // Пропускаем проблемные эндпоинты
            if (skipEndpoints.stream().anyMatch(p::contains)) {
                continue;
            }

            JsonNode node = paths.path(p);

            // Обрабатываем все HTTP методы для данного эндпоинта
            for (String m : List.of("get","post","put","delete")) {
                JsonNode op = node.path(m);
                if (!op.isObject()) continue;

                Scenario s = new Scenario();
                s.path = p;
                s.method = m.toUpperCase(Locale.ROOT);
                s.label = "positive";
                
                // Для межбанковских запросов к /accounts добавляем client_id и заголовки
                if ("/accounts".equals(p) && interbankClient != null && !interbankClient.isBlank()) {
                    s.query.put("client_id", interbankClient);
                    if (requestingBank != null && !requestingBank.isBlank())
                        s.headers.put("X-Requesting-Bank", requestingBank);
                }
                
                // Генерируем тело запроса для POST/PUT методов если есть схема
                if (!p.contains("/consents") && !p.contains("/agreements")) {
                    JsonNode reqBody = op.path("requestBody").path("content").path("application/json").path("schema");
                    if (reqBody.isObject()) {
                        s.body = minimalValidJson(reqBody);
                    }
                }
                out.add(s);

                // Создаем негативные сценарии только для безопасных эндпоинтов
                if (!p.contains("/auth") && !p.contains("/consents")) {
                    Scenario neg = s.copy();
                    neg.label = "negative";
                    if (neg.query.containsKey("client_id")) {
                        neg.query.put("client_id", "other-9999"); // Подмена client_id
                    } else if (neg.body != null && neg.body.isObject()) {
                        // Добавляем неожиданное поле для проверки валидации
                        ((com.fasterxml.jackson.databind.node.ObjectNode) neg.body).put("_unexpected", "boom");
                    }
                    out.add(neg);
                }
            }
        }
        return out;
    }

    /**
     * Генерирует минимальный валидный JSON объект на основе JSON Schema
     * @param schema JSON Schema из OpenAPI спецификации
     * @return минимальный валидный JSON объект
     */
    private JsonNode minimalValidJson(JsonNode schema) {
        var obj = om.createObjectNode();
        if (!schema.isObject()) return obj;
        if ("object".equals(schema.path("type").asText())) {
            JsonNode props = schema.path("properties");
            JsonNode req = schema.path("required");
            Set<String> required = new HashSet<>();
            if (req.isArray()) req.forEach(n -> required.add(n.asText()));
            if (props.isObject()) {
                Iterator<String> names = props.fieldNames();
                while (names.hasNext()) {
                    String name = names.next();
                    JsonNode ps = props.path(name);
                    if (required.isEmpty() || required.contains(name)) {
                        obj.set(name, defaultFor(ps));
                    }
                }
            }
            return obj;
        }
        return defaultFor(schema);
    }

    /**
     * Генерирует значение по умолчанию для типа данных из JSON Schema
     * @param s JSON Schema для свойства
     * @return значение по умолчанию соответствующего типа
     */
    private JsonNode defaultFor(JsonNode s) {
        String t = s.path("type").asText();
        switch (t) {
            case "string":
                if (s.has("enum") && s.get("enum").isArray() && s.get("enum").size() > 0)
                    return s.get("enum").get(0);
                return new ObjectMapper().getNodeFactory().textNode("sample");
            case "integer":
            case "number":
                return new ObjectMapper().getNodeFactory().numberNode(1);
            case "boolean":
                return new ObjectMapper().getNodeFactory().booleanNode(true);
            case "array":
                var arr = new ObjectMapper().createArrayNode();
                JsonNode items = s.path("items");
                if (!items.isMissingNode()) arr.add(defaultFor(items));
                return arr;
            case "object":
                return minimalValidJson(s);
            default:
                return new ObjectMapper().getNodeFactory().textNode("sample");
        }
    }
}
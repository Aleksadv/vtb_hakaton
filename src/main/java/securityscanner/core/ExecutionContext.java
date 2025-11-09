package securityscanner.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.OkHttpClient;
import securityscanner.core.model.Finding;
import securityscanner.parser.OpenAPIParser;

import java.util.List;

/**
 * Контекст выполнения, передаваемый во все плагины безопасности.
 * Содержит все необходимые зависимости и данные для работы плагинов.
 */
public class ExecutionContext {
    public final String baseUrl;              // Базовый URL API
    public final String accessToken;          // Токен аутентификации
    public final String requestingBank;       // Идентификатор банка для межбанковских запросов
    public final String interbankClientId;    // client_id для межбанковских операций
    public final String consentId;            // ID созданного согласия (consent)
    public final boolean verbose;             // Режим подробного логирования

    // Зависимости для работы плагинов
    public final OkHttpClient http;           // HTTP клиент для запросов
    public final ObjectMapper om;             // JSON парсер
    public final OpenAPIParser parser;  // Парсер OpenAPI спецификаций
    public final JsonNode openapiRoot;        // Корневой узел OpenAPI спецификации

    // Коллекция для накопления результатов проверок
    public final List<Finding> findings;

    public ExecutionContext(String baseUrl,
                            String accessToken,
                            String requestingBank,
                            String interbankClientId,
                            String consentId,
                            boolean verbose,
                            OkHttpClient http,
                            ObjectMapper om,
                            OpenAPIParser parser,
                            JsonNode openapiRoot,
                            List<Finding> findings) {
        this.baseUrl = baseUrl;
        this.accessToken = accessToken;
        this.requestingBank = requestingBank;
        this.interbankClientId = interbankClientId;
        this.consentId = consentId;
        this.verbose = verbose;
        this.http = http;
        this.om = om;
        this.parser = parser;
        this.openapiRoot = openapiRoot;
        this.findings = findings;
    }
}
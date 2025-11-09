package securityscanner.http;

import okhttp3.*;
import java.time.Duration;
import java.util.Map;

/**
 * HTTP клиент для выполнения запросов к API.
 * Обеспечивает централизованное управление таймаутами и логированием.
 */
public class RequestExecutor {

    private final OkHttpClient http;
    private final boolean verbose;

    /**
     * Создает экземпляр RequestExecutor с настройками таймаутов
     * @param http базовый HTTP клиент
     * @param verbose режим подробного логирования
     */
    public RequestExecutor(OkHttpClient http, boolean verbose) {
        this.http = http.newBuilder()
                .callTimeout(Duration.ofSeconds(30))
                .readTimeout(Duration.ofSeconds(30))
                .build();
        this.verbose = verbose;
    }

    /**
     * Выполняет GET запрос
     * @param url целевой URL
     * @param headers HTTP заголовки
     * @return HTTP ответ
     */
    public Response get(String url, Map<String, String> headers) throws Exception {
        Request.Builder rb = new Request.Builder().url(url).get();
        headers.forEach(rb::addHeader);
        if (verbose) System.out.println("GET " + url + " " + headers);
        return http.newCall(rb.build()).execute();
    }

    /**
     * Выполняет POST запрос с JSON телом
     * @param url целевой URL
     * @param json JSON тело запроса
     * @param headers HTTP заголовки
     * @return HTTP ответ
     */
    public Response postJson(String url, String json, Map<String, String> headers) throws Exception {
        RequestBody body = RequestBody.create(json, MediaType.parse("application/json"));
        Request.Builder rb = new Request.Builder().url(url).post(body);
        headers.forEach(rb::addHeader);
        if (verbose) {
            System.out.println("POST " + url + " " + headers);
            System.out.println("Body: " + (json.length() > 1000 ? json.substring(0, 1000) + "...(truncated)" : json));
        }
        return http.newCall(rb.build()).execute();
    }
}
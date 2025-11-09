package securityscanner.core.model;

/**
 * Модель для представления найденной уязвимости или проблемы безопасности.
 * Содержит всю информацию о finding: эндпоинт, метод, статус, серьезность, рекомендации.
 */
public class Finding {
    public enum Severity { INFO, LOW, MEDIUM, HIGH }

    public String endpoint;      // Эндпоинт API где найдена проблема
    public String method;        // HTTP метод (GET, POST, PUT, DELETE)
    public int status;           // HTTP статус код ответа
    public String owasp;         // OWASP категория (например "API1:BOLA")
    public Severity severity;    // Уровень серьезности проблемы
    public String message;       // Описание проблемы
    public String evidence;      // Доказательства (кусок ответа, заголовки)
    public String recommendation; // Рекомендации по исправлению

    public Finding() {}

    /**
     * Создает finding с рекомендацией по умолчанию
     */
    public static Finding of(String endpoint, String method, int status,
                             String owasp, Severity sev, String msg, String ev) {
        return of(endpoint, method, status, owasp, sev, msg, ev, "");
    }

    /**
     * Создает finding с полной информацией
     */
    public static Finding of(String endpoint, String method, int status,
                             String owasp, Severity sev, String msg, String ev, String recommendation) {
        Finding f = new Finding();
        f.endpoint = endpoint;
        f.method = method;
        f.status = status;
        f.owasp = owasp;
        f.severity = sev;
        f.message = msg;
        f.evidence = ev;
        f.recommendation = recommendation;
        return f;
    }
}
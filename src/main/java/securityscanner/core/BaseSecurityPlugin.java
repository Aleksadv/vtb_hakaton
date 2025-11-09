package securityscanner.core;

import securityscanner.core.model.Finding;

/**
 * Абстрактный базовый класс для всех плагинов безопасности.
 * Предоставляет общую функциональность для создания findings и очистки сообщений.
 * Упрощает разработку новых плагинов за счет устранения boilerplate кода.
 */
public abstract class BaseSecurityPlugin implements SecurityPlugin {
    
    /**
     * Создает объект Finding с предварительной очисткой текстовых сообщений.
     * Автоматически подставляет идентификатор плагина и обрабатывает специальные символы.
     * 
     * @param endpoint эндпоинт API где обнаружена проблема
     * @param method HTTP метод запроса
     * @param status HTTP статус код ответа
     * @param severity уровень серьезности проблемы
     * @param message описание проблемы
     * @param recommendation рекомендация по исправлению
     * @return объект Finding с очищенными текстовыми полями
     */
    protected Finding createFinding(String endpoint, String method, int status, 
                                  Finding.Severity severity, String message, String recommendation) {
        return Finding.of(endpoint, method, status, id(), severity, 
                         cleanMessage(message), "", cleanMessage(recommendation));
    }
    
    /**
     * Очищает текстовые сообщения от специальных символов и лишних пробелов.
     * Убирает символы новой строки, возврата каретки и табуляции для корректного
     * отображения в отчетах и предотвращения проблем с форматированием.
     * 
     * @param message исходное текстовое сообщение
     * @return очищенное сообщение без специальных символов
     */
    private String cleanMessage(String message) {
        if (message == null) return "";
        // Замена специальных символов на пробелы и обрезка лишних пробелов
        return message.replace("\n", " ")
                     .replace("\r", " ")
                     .replace("\t", " ")
                     .trim();
    }
}
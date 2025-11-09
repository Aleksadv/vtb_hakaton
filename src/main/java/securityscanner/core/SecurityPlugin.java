package securityscanner.core;

import securityscanner.core.model.Finding;
import java.util.List;

/**
 * Интерфейс для всех плагинов безопасности.
 * Каждый плагин должен реализовать методы идентификации и выполнения проверок.
 */
public interface SecurityPlugin {
    /**
     * Возвращает уникальный идентификатор плагина (например "API1:BOLA")
     */
    String id();

    /**
     * Возвращает краткое название плагина для отображения
     */
    String title();

    /**
     * Возвращает описание функциональности плагина
     */
    String description();

    /**
     * Выполняет проверки безопасности и возвращает список найденных проблем
     * @param ctx контекст выполнения с данными и зависимостями
     * @return список findings или пустой список если проблем не найдено
     */
    List<Finding> run(ExecutionContext ctx) throws Exception;
}
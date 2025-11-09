package securityscanner.runner;

import securityscanner.auditor.APISecurityAuditor;

import java.util.*;

/**
 * Главный класс запуска сканера безопасности API
 * Обрабатывает аргументы командной строки и инициализирует аудитор
 */
public class BankingAPIScanner {

    /**
     * Парсит аргументы командной строки в Map
     * @param args аргументы командной строки
     * @return Map с параметрами и их значениями
     */
    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> map = new LinkedHashMap<>();
        List<String> multi = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.startsWith("--")) {
                String key = a.substring(2);
                String val = (i + 1 < args.length && !args[i + 1].startsWith("--")) ? args[++i] : "true";
                map.put(key, val);
            } else {
                multi.add(a);
            }
        }
        return map;
    }

    /**
     * Точка входа в приложение
     * @param args аргументы командной строки
     */
    public static void main(String[] args) throws Exception {
        Map<String, String> p = parseArgs(args);

        // Парсинг параметров командной строки
        String openapi = p.getOrDefault("openapi", "");
        String baseUrl = p.getOrDefault("base-url", "");
        String authArg = p.getOrDefault("auth", ""); // формат: bearer:XXXXX
        String clientId = p.getOrDefault("client-id", System.getenv("CLIENT_ID"));
        String clientSecret = p.getOrDefault("client-secret", System.getenv("CLIENT_SECRET"));
        String requestingBank = p.getOrDefault("requesting-bank", clientId); // по умолчанию = teamID
        String interbankClient = p.getOrDefault("client", "");               // client_id клиента для межбанка
        boolean createConsent = Boolean.parseBoolean(p.getOrDefault("create-consent", "false"));
        boolean verbose = Boolean.parseBoolean(p.getOrDefault("verbose", "false"));

        // Доп. заголовки: --add-header "X-Requesting-Bank:team184" (можно указать несколько раз)
        List<String> extraHeaders = new ArrayList<>();
        for (Map.Entry<String, String> e : p.entrySet()) {
            if (e.getKey().equals("add-header")) extraHeaders.add(e.getValue());
        }

        // Вывод информации о конфигурации
        System.out.println("Starting Banking API Security Scanner...");
        System.out.println("openapi=" + openapi);
        System.out.println("base-url=" + (baseUrl.isBlank() ? "(auto from OpenAPI)" : baseUrl));
        System.out.println("auth=" + (authArg.isBlank() ? "(will resolve)" : authArg.substring(0, Math.min(authArg.length(), 16)) + "..."));
        System.out.println("client-id=" + (clientId == null ? "" : clientId));
        System.out.println("requesting-bank=" + (requestingBank == null ? "" : requestingBank));
        System.out.println("create-consent=" + createConsent);
        if (!extraHeaders.isEmpty()) System.out.println("extra headers: " + extraHeaders);
        if (verbose) System.out.println("verbose=ON");

        // Инициализация и запуск аудитора безопасности
        APISecurityAuditor auditor = new APISecurityAuditor(verbose);
        auditor.setOpenapiLocation(openapi);
        auditor.setBaseUrl(baseUrl);
        auditor.setAuthArg(authArg);
        auditor.setClientId(clientId);
        auditor.setClientSecret(clientSecret);
        auditor.setRequestingBank(requestingBank);
        auditor.setInterbankClientId(interbankClient);
        auditor.setCreateConsent(createConsent);
        auditor.setExtraHeaders(extraHeaders);

        auditor.run();
    }
}
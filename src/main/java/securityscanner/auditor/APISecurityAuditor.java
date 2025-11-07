package securityscanner.auditor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import securityscanner.core.ResponseValidator;
import securityscanner.core.model.Finding;
import securityscanner.parser.OpenAPIParserSimple;
import securityscanner.report.ReportWriter;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

public class APISecurityAuditor {

    private final boolean verbose;
    private final ObjectMapper om = new ObjectMapper();
    private final OkHttpClient http = new OkHttpClient.Builder()
            .callTimeout(Duration.ofSeconds(30))
            .readTimeout(Duration.ofSeconds(30))
            .build();

    private final List<Finding> findings = new ArrayList<>();
    private final ResponseValidator validator = new ResponseValidator();
    private final ReportWriter reportWriter = new ReportWriter();

    private String openapiLocation;
    private String baseUrl;
    private String authArg; // "bearer:XXXX"
    private String clientId;
    private String clientSecret;
    private String requestingBank;
    private String interbankClientId;
    private boolean createConsent;
    private List<String> extraHeaders = List.of();

    public APISecurityAuditor(boolean verbose) { this.verbose = verbose; }

    public void setOpenapiLocation(String openapiLocation) { this.openapiLocation = openapiLocation; }
    public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
    public void setAuthArg(String authArg) { this.authArg = authArg; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    public void setRequestingBank(String requestingBank) { this.requestingBank = requestingBank; }
    public void setInterbankClientId(String interbankClientId) { this.interbankClientId = interbankClientId; }
    public void setCreateConsent(boolean createConsent) { this.createConsent = createConsent; }
    public void setExtraHeaders(List<String> extraHeaders) { this.extraHeaders = extraHeaders != null ? extraHeaders : List.of(); }

    private void log(String s) { if (verbose) System.out.println(s); }

    private String ensureBaseUrlFromOpenAPI(String current) throws Exception {
        if (current != null && !current.isBlank()) return current.replaceAll("/+$", "");
        if (openapiLocation == null || openapiLocation.isBlank()) return "";
        OpenAPIParserSimple parser = new OpenAPIParserSimple();
        String fromSpec = parser.extractFirstServerUrl(openapiLocation);
        if (fromSpec == null || fromSpec.isBlank()) return "";
        return fromSpec.replaceAll("/+$", "");
    }

    private String resolveAccessToken() throws Exception {
        if (authArg != null && authArg.toLowerCase(Locale.ROOT).startsWith("bearer:")) {
            String t = authArg.substring("bearer:".length());
            System.out.println("Access token (from --auth) detected.");
            return t;
        }
        String env = System.getenv("BANK_TOKEN");
        if (env != null && !env.isBlank()) {
            System.out.println("Access token (from env BANK_TOKEN) detected.");
            return env;
        }
        if (clientId == null || clientSecret == null || clientId.isBlank() || clientSecret.isBlank())
            throw new IllegalStateException("No token and no CLIENT_ID/CLIENT_SECRET provided to fetch /auth/bank-token");

        String url = baseUrl + "/auth/bank-token?client_id=" + encode(clientId) + "&client_secret=" + encode(clientSecret);
        Request req = new Request.Builder().url(url).post(RequestBody.create(new byte[0])).build();
        log("POST " + url);
        try (Response r = http.newCall(req).execute()) {
            String body = r.body() != null ? r.body().string() : "";
            System.out.println("Auth response status: " + r.code());
            log("? Auth response body: " + body);
            if (!r.isSuccessful()) throw new IllegalStateException("Auth failed: " + r.code());
            JsonNode node = om.readTree(body);
            String token = node.path("access_token").asText();
            if (token == null || token.isBlank())
                throw new IllegalStateException("Auth response has no access_token");
            System.out.println("Access Token received: " + token.substring(0, Math.min(token.length(), 16)) + "...");
            return token;
        }
    }

    private static String encode(String v) { return java.net.URLEncoder.encode(v, StandardCharsets.UTF_8); }

    private void applyExtraHeaders(Request.Builder b) {
        for (String h : extraHeaders) {
            int idx = h.indexOf(':');
            if (idx > 0) {
                String name = h.substring(0, idx).trim();
                String val = h.substring(idx + 1).trim();
                if (!name.isBlank() && !val.isBlank()) b.addHeader(name, val);
            }
        }
    }

    private String createConsentIfNeeded(String token) throws Exception {
        if (!createConsent) return null;
        if (requestingBank == null || requestingBank.isBlank())
            throw new IllegalStateException("--create-consent requires --requesting-bank (usually your team id)");
        if (interbankClientId == null || interbankClientId.isBlank())
            throw new IllegalStateException("--create-consent requires --client <client_id_of_user> (e.g., team200-1)");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("client_id", interbankClientId);
        body.put("permissions", List.of("ReadAccountsDetail", "ReadBalances"));
        body.put("reason", "HackAPI scan");
        body.put("requesting_bank", requestingBank);
        body.put("requesting_bank_name", "Team " + requestingBank);

        String json = om.writeValueAsString(body);
        String url = baseUrl + "/account-consents/request";
        Request.Builder rb = new Request.Builder()
                .url(url)
                .post(RequestBody.create(json, MediaType.parse("application/json")));
        rb.addHeader("Authorization", "Bearer " + token);
        rb.addHeader("X-Requesting-Bank", requestingBank);
        applyExtraHeaders(rb);

        log("POST " + url + " (create consent)");
        log("Body: " + json);
        try (Response r = http.newCall(rb.build()).execute()) {
            String resp = r.body() != null ? r.body().string() : "";
            System.out.println("Create consent status: " + r.code());
            log("Create consent response: " + resp);
            if (!r.isSuccessful()) throw new IllegalStateException("Create consent failed: " + r.code());
            JsonNode node = om.readTree(resp);
            String consentId = node.path("consent_id").asText();
            if (consentId == null || consentId.isBlank()) {
                JsonNode alt = node.path("data").path("consentId");
                consentId = alt.isMissingNode() ? null : alt.asText();
            }
            if (consentId == null || consentId.isBlank()) throw new IllegalStateException("No consent_id in response");
            System.out.println("Consent created: " + consentId);

            findings.add(Finding.of("/account-consents/request", "POST", r.code(),
                    "ContractCheck", Finding.Severity.INFO, "Consent created: " + consentId, resp));
            return consentId;
        }
    }

    private void validateAndRecord(String endpoint, String method, Response r, JsonNode expectedSchema) {
        List<Finding> vf = validator.validateContract(endpoint, method, r, expectedSchema);
        findings.addAll(vf);
    }

    private void tryGetAccounts(String token, String consentId) throws Exception {
        HttpUrl.Builder urlb = Objects.requireNonNull(HttpUrl.parse(baseUrl + "/accounts")).newBuilder();
        if (interbankClientId != null && !interbankClientId.isBlank()) {
            urlb.addQueryParameter("client_id", interbankClientId);
        }
        HttpUrl url = urlb.build();

        Request.Builder rb = new Request.Builder().url(url).get();
        rb.addHeader("Authorization", "Bearer " + token);
        if (interbankClientId != null && !interbankClientId.isBlank()) {
            if (requestingBank != null && !requestingBank.isBlank())
                rb.addHeader("X-Requesting-Bank", requestingBank);
            if (consentId != null && !consentId.isBlank())
                rb.addHeader("X-Consent-Id", consentId);
        }
        applyExtraHeaders(rb);

        log("GET " + url);
        try (Response r = http.newCall(rb.build()).execute()) {
            String body = r.body() != null ? r.body().string() : "";
            System.out.println("/accounts -> " + r.code());
            log(body);

            // верни body в Response для валидатора (сделаем второй Response из строки)
            Response re = r.newBuilder()
                    .body(ResponseBody.create(body, MediaType.parse(r.header("Content-Type", "application/json"))))
                    .build();

            // Схема 200 application/json для /accounts
            OpenAPIParserSimple parser = new OpenAPIParserSimple();
            JsonNode schema = parser.resolveResponseSchema(openapiLocation, "/accounts", 200, r.header("Content-Type", "application/json"));
            validateAndRecord("/accounts", "GET", re, schema);
        }
    }

    private void probeCommonPaths(String token, List<String> paths) throws Exception {
        for (String p : paths) {
            String url = baseUrl + p;
            Request.Builder rb = new Request.Builder().url(url).get();
            if (token != null && !token.isBlank()) rb.addHeader("Authorization", "Bearer " + token);
            applyExtraHeaders(rb);
            log("GET " + url);
            try (Response r = http.newCall(rb.build()).execute()) {
                System.out.println(p + " -> " + r.code());
                String body = r.body() != null ? r.body().string() : "";
                if (verbose) log(body);

                Response re = r.newBuilder()
                        .body(ResponseBody.create(body, MediaType.parse(r.header("Content-Type", "application/json"))))
                        .build();

                // попробуем валидацию, если есть схема (многие тех.эндпоинты без схем)
                OpenAPIParserSimple parser = new OpenAPIParserSimple();
                JsonNode schema = parser.resolveResponseSchema(openapiLocation, p, r.code(), r.header("Content-Type", "application/json"));
                validateAndRecord(p, "GET", re, schema);
            }
        }
    }

    public void run() throws Exception {
        this.baseUrl = ensureBaseUrlFromOpenAPI(this.baseUrl);
        if (baseUrl == null || baseUrl.isBlank())
            throw new IllegalStateException("Base URL is empty. Provide --base-url or a spec with servers[].url");
        System.out.println("Resolved base-url: " + baseUrl);

        String token = resolveAccessToken();

        String consentId = null;
        if (createConsent) {
            consentId = createConsentIfNeeded(token);
        }

        tryGetAccounts(token, consentId);
        probeCommonPaths(token, List.of("/health", "/", "/.well-known/jwks.json"));

        // === Отчёты ===
        var jsonFile = reportWriter.writeJson("Virtual Bank API Report", openapiLocation, baseUrl, findings);
        var pdfFile  = reportWriter.writePdf("Virtual Bank API Report", openapiLocation, baseUrl, findings);
        System.out.println("Reports:");
        System.out.println("  JSON: " + jsonFile.getAbsolutePath());
        System.out.println("  PDF : " + pdfFile.getAbsolutePath());
    }
}

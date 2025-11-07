package securityscanner.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.*;
import okhttp3.Response;
import securityscanner.core.model.Finding;

import java.util.*;

public class ResponseValidator {

    private final ObjectMapper om = new ObjectMapper();

    public List<Finding> validateContract(String endpoint, String method,
                                          Response httpResp,
                                          JsonNode expectedSchema) {
        List<Finding> out = new ArrayList<>();
        int code = httpResp.code();
        String body = "";
        try { body = httpResp.body() != null ? httpResp.body().string() : ""; } catch (Exception ignore){}

        // 1) content-type грубая проверка
        String ct = httpResp.header("Content-Type", "");
        if (expectedSchema != null && (ct == null || !ct.toLowerCase(Locale.ROOT).contains("application/json"))) {
            out.add(Finding.of(endpoint, method, code, "ContractMismatch",
                    Finding.Severity.LOW, "Unexpected Content-Type: " + ct, bodySnippet(body)));
            // не выходим — возможно тело всё равно JSON
        }

        // 2) JSON Schema валидация, если есть схема и тело похоже на JSON
        if (expectedSchema != null && body != null && !body.isBlank() && looksLikeJson(body)) {
            try {
                JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
                JsonSchema schema = factory.getSchema(expectedSchema);
                JsonNode node = om.readTree(body);
                Set<ValidationMessage> errors = schema.validate(node);
                if (!errors.isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    for (ValidationMessage e : errors) sb.append(e.getMessage()).append("; ");
                    out.add(Finding.of(endpoint, method, code, "ContractMismatch",
                            Finding.Severity.MEDIUM, "Schema violations: " + sb, bodySnippet(body)));
                } else {
                    out.add(Finding.of(endpoint, method, code, "ContractMatch",
                            Finding.Severity.INFO, "Response matches schema", bodySnippet(body)));
                }
            } catch (Exception ex) {
                out.add(Finding.of(endpoint, method, code, "ContractValidationError",
                        Finding.Severity.LOW, "Validator error: " + ex.getMessage(), bodySnippet(body)));
            }
        } else {
            // если схемы нет — просто зафиксируем 200/код как инфо
            out.add(Finding.of(endpoint, method, code, "ContractCheck",
                    Finding.Severity.INFO, "No schema to validate or non-JSON body", bodySnippet(body)));
        }
        return out;
    }

    private static boolean looksLikeJson(String s) {
        String t = s.trim();
        return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
    }

    private static String bodySnippet(String body) {
        if (body == null) return "";
        return body.length() > 2000 ? body.substring(0, 2000) + "...(truncated)" : body;
    }
}

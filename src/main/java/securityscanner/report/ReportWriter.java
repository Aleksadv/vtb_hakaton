package securityscanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lowagie.text.*;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import securityscanner.core.model.Finding;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class ReportWriter {

    private final ObjectMapper om = new ObjectMapper();

    public static class Meta {
        public String title;
        public String openapi;
        public String baseUrl;
        public String generatedAt;
    }

    public static class Report {
        public Meta meta;
        public List<Finding> findings;
    }

    public File writeJson(String title, String openapi, String baseUrl, List<Finding> findings) throws Exception {
        ensureDir();
        Report r = new Report();
        r.meta = new Meta();
        r.meta.title = title;
        r.meta.openapi = openapi;
        r.meta.baseUrl = baseUrl;
        r.meta.generatedAt = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        r.findings = findings;

        String name = "VirtualBankAPI-" + timestamp() + ".json";
        File f = new File("target/reports/" + name);
        om.writerWithDefaultPrettyPrinter().writeValue(f, r);
        return f;
    }

    public File writePdf(String title, String openapi, String baseUrl, List<Finding> findings) throws Exception {
        ensureDir();
        String name = "VirtualBankAPI-" + timestamp() + ".pdf";
        File f = new File("target/reports/" + name);

        Document doc = new Document(PageSize.A4);
        PdfWriter.getInstance(doc, new FileOutputStream(f));
        doc.open();
        Font h1 = new Font(Font.HELVETICA, 16, Font.BOLD);
        Font txt = new Font(Font.HELVETICA, 10, Font.NORMAL);

        doc.add(new Paragraph(title, h1));
        doc.add(new Paragraph("OpenAPI: " + openapi, txt));
        doc.add(new Paragraph("Base URL: " + baseUrl, txt));
        doc.add(new Paragraph("Generated: " + LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME), txt));
        doc.add(new Paragraph(" ", txt));

        PdfPTable table = new PdfPTable(6);
        table.setWidthPercentage(100);
        table.setWidths(new float[]{18, 10, 10, 12, 25, 25});
        table.addCell("Endpoint");
        table.addCell("Method");
        table.addCell("Status");
        table.addCell("Type");
        table.addCell("Message");
        table.addCell("Evidence");

        for (Finding fnd : findings) {
            table.addCell(safe(fnd.endpoint));
            table.addCell(safe(fnd.method));
            table.addCell(String.valueOf(fnd.status));
            table.addCell(safe(fnd.owasp) + " / " + (fnd.severity != null ? fnd.severity : ""));
            table.addCell(safe(fnd.message));
            table.addCell(safe(trim(fnd.evidence, 600)));
        }
        doc.add(table);
        doc.close();
        return f;
    }

    private static String timestamp() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
    }
    private static void ensureDir() throws Exception {
        Files.createDirectories(new File("target/reports").toPath());
    }
    private static String trim(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "...(truncated)" : s;
    }
    private static String safe(String s) { return s == null ? "" : s; }
}

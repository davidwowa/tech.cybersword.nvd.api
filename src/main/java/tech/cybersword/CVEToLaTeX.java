package tech.cybersword;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class CVEToLaTeX {

    private static final Logger logger = LogManager.getLogger(CVEToLaTeX.class);

    private static Map<Integer, String> cweDescriptions = new HashMap<>();

    static {
        try (BufferedReader br = new BufferedReader(new FileReader("699.csv"))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] values = line.split(",");
                if (values.length >= 2) {
                    int cweId = Integer.parseInt(values[0].trim());
                    String description = values[1].trim();
                    cweDescriptions.put(cweId, description);
                }
            }
        } catch (IOException e) {
            logger.error("Error on read csv file: " + e.getMessage());
        }
    }

    private static String getCweDescription(int cweId) {
        return cweDescriptions.getOrDefault(cweId, "no CWE Description available");
    }

    public static void LaTeX(String jsonFilePath, String templateFilePath) {
        try {
            String jsonString = new String(Files.readAllBytes(Paths.get(jsonFilePath)));
            String latexTemplate = new String(Files.readAllBytes(Paths.get(templateFilePath)));

            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode rootNode = objectMapper.readTree(jsonString);
            JsonNode vulnerabilities = rootNode.get("vulnerabilities");

            if (vulnerabilities.isArray()) {
                for (JsonNode vulnerability : vulnerabilities) {
                    String cveId = vulnerability.get("id").asText();
                    String description = vulnerability.get("description").asText();
                    String score = vulnerability.get("ratings").get(0).get("score").asText();
                    String component = ""; // vulnerability.get("source").get("name").asText();

                    JsonNode affects = vulnerability.get("affects");
                    if (null != affects && affects.isArray()) {
                        Set<String> components = new HashSet<>();
                        int counter = 0;
                        for (JsonNode affect : affects) {
                            String af = affect.get("ref").asText();

                            if (counter < 19) {
                                String vendor = "";
                                String product = "";
                                String version = "";

                                String[] parts = af.split(":");
                                if (parts.length > 6) {
                                    vendor = vendor + " " + parts[3];// vendor
                                    product = product + " " + parts[4];// product
                                    version = version + " " + parts[5];// version
                                }

                                component = vendor + product + version;
                                if (!components.contains(component)) {
                                    components.add(component);
                                    counter++;
                                }

                                logger.info("Component: " + af);
                            } else {
                                component = component + "Other components affected in this context...";
                                logger.info("No in view, component: " + af);
                            }
                        }

                        component = String.join("\n", components);
                    }
                    component = component.replace("_", " ");
                    description = description.replace("_", "\\_");

                    try {
                        byte[] bytes = description.getBytes(StandardCharsets.UTF_8);
                        description = new String(bytes, StandardCharsets.UTF_8);
                    } catch (Exception e) {
                        logger.error("Fehler bei der UTF-8-Kodierung der Beschreibung: " + e.getMessage());
                        description = description.replaceAll("[^\\x00-\\x7F]", ""); // Entfernen ungültiger Zeichen
                    }

                    JsonNode cwes = vulnerability.get("cwes");
                    String cwess = "";
                    if (cwes.isArray()) {
                        for (JsonNode cwe : cwes) {
                            String cweId = cwe.asText();
                            int cweIdInt = Integer.parseInt(cweId);
                            String cweDesc = getCweDescription(cweIdInt);
                            cwess = cweId + " " + cweDesc + "\n";
                            logger.info("CWE: " + cwess);
                        }
                    }

                    String filledTemplate = latexTemplate.replace("{{CVEID}}", cveId)
                            .replace("{{Component}}", component).replace("{{Description}}", description)
                            .replace("{{Score}}", score).replace("{{CWES}}", cwess);

                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmm");
                    String currentDateTime = LocalDateTime.now().format(formatter);

                    Path outputDir = Paths.get(currentDateTime);
                    if (!Files.exists(outputDir)) {
                        Files.createDirectories(outputDir);
                    }

                    String outputFileName = outputDir.resolve(cveId.replace(":", "_") + ".tex").toString();
                    Files.write(Paths.get(outputFileName), filledTemplate.getBytes());

                    logger.info("LaTeX-file created: " + outputFileName);
                }
            }
        } catch (Exception e) {
            logger.error("create LaTeX-file failed ", e.getMessage());
            e.printStackTrace();
        }
    }
}

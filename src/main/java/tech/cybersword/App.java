package tech.cybersword;

import java.io.FileWriter;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cyclonedx.BomGeneratorFactory;
import org.cyclonedx.CycloneDxSchema.Version;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.vulnerability.Vulnerability;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class App {

    private static final Logger logger = LogManager.getLogger(App.class);

    private static final String NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static String API_KEY = "";

    private static int rceInDescCounter = 0;

    private static Bom rceBOM = new Bom();
    private static List<Vulnerability> rceVulnerabilities = new ArrayList<>();

    public static void main(String[] args) {

        // if (args.length == 0) {
        // System.out.println(
        // "Usage: java -jar tech.cybersword.nvd.api-*.jar <nvd api key> <start date in
        // ISO 8601 Format> <end date in ISO 8601 Format>");
        // System.exit(1);
        // }

        // Beispiel: Start- und Enddatum (ISO 8601 Format)
        String startDate = "2025-03-23T00:00:00.000Z";
        String endDate = "2025-03-29T23:59:59.999Z";

        // LocalDateTime now = LocalDateTime.now();
        // String startDate =
        // now.withHour(0).withMinute(0).withSecond(0).withNano(0).format(DateTimeFormatter.ISO_DATE_TIME)
        // + "Z";
        // String endDate =
        // now.withHour(23).withMinute(59).withSecond(59).withNano(999999999).format(DateTimeFormatter.ISO_DATE_TIME)
        // + "Z";

        // API_KEY = args[0];
        // String startDate = args[1];
        // String endDate = args[2];

        if (API_KEY == null || API_KEY.isEmpty()) {
            System.out.println("API Key is missing");
            System.exit(1);
        }

        try {
            DateTimeFormatter inputFormatter = DateTimeFormatter.ISO_DATE_TIME;
            DateTimeFormatter outputFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmm");

            LocalDateTime startDateTime = LocalDateTime.parse(startDate, inputFormatter);
            LocalDateTime endDateTime = LocalDateTime.parse(endDate, inputFormatter);

            String formattedStartDate = startDateTime.format(outputFormatter);
            String formattedEndDate = endDateTime.format(outputFormatter);

            String newFileName = String.format("new_cves_%s-%s.cdx.json", formattedStartDate, formattedEndDate);
            String modFileName = String.format("mod_cves_%s-%s.cdx.json", formattedStartDate, formattedEndDate);
            String newRceFileName = String.format("new_rce_cves_%s-%s.cdx.json", formattedStartDate, formattedEndDate);
            String modRceFileName = String.format("mod_rce_cves_%s-%s.cdx.json", formattedStartDate, formattedEndDate);

            JsonNode newCVEData = fetchCVEData(startDate, endDate, "pubStartDate", "pubEndDate");
            saveToCycloneDX(newCVEData, newFileName);

            rceBOM.setVulnerabilities(rceVulnerabilities);

            saveRCEs2BOM(newRceFileName);

            rceVulnerabilities = new ArrayList<>();

            JsonNode modifiedCVEData = fetchCVEData(startDate, endDate, "lastModStartDate", "lastModEndDate");
            saveToCycloneDX(modifiedCVEData, modFileName);

            new Thread(() -> {
                CVEToLaTeX.LaTeX(newRceFileName, "cve_rce.tex");
            }).start();

            rceBOM = new Bom();
            rceBOM.setVulnerabilities(rceVulnerabilities);

            saveRCEs2BOM(modRceFileName);

            new Thread(() -> {
                CVEToLaTeX.LaTeX(modRceFileName, "cve_rce.tex");
            }).start();

            logger.info("RCE Counter " + rceInDescCounter);
        } catch (IOException e) {
            logger.error("error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void saveRCEs2BOM(String rceFileName) throws IOException {
        BomJsonGenerator generator = BomGeneratorFactory.createJson(Version.VERSION_14, rceBOM);
        String bomJson = generator.toJsonString();
        try (FileWriter writer = new FileWriter(rceFileName)) {
            writer.write(bomJson);
        } catch (Exception e) {
            logger.error("error on save bom file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static JsonNode fetchCVEData(String startDate, String endDate, String startParam, String endParam)
            throws IOException {
        String requestUrl = String.format("%s?%s=%s&%s=%s", NVD_API_URL, startParam, startDate, endParam, endDate);

        logger.info("API-request: " + requestUrl);

        URL url = new URL(requestUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("apiKey", API_KEY);
        connection.setRequestProperty("Accept", "application/json");

        int responseCode = connection.getResponseCode();
        String message = connection.getResponseMessage();
        if (responseCode != 200) {
            logger.error("error by request: " + message);
            throw new IOException("Error by: HTTP " + responseCode + " " + message);
        }

        Scanner scanner = new Scanner(connection.getInputStream());
        StringBuilder response = new StringBuilder();
        while (scanner.hasNextLine()) {
            response.append(scanner.nextLine());
        }
        scanner.close();

        ObjectMapper mapper = new ObjectMapper();
        return mapper.readTree(response.toString());
    }

    public static void saveToCycloneDX(JsonNode cveData, String fileName) throws IOException {
        Bom bom = new Bom();
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (cveData.has("vulnerabilities")) {
            for (JsonNode cveNode : cveData.get("vulnerabilities")) {

                if (null == cveNode.get("cve").get("vulnStatus")) {
                    logger.warn("No vulnStatus found for CVE: " + cveNode.get("cve").get("id").asText());
                    continue;
                }

                String vulnStatus = cveNode.get("cve").get("vulnStatus").asText();

                if (!"Rejected".equals(vulnStatus) && !"Awaiting Analysis".equals(vulnStatus)) {

                    Vulnerability vulnerability = new Vulnerability();
                    vulnerability.setId(cveNode.get("cve").get("id").asText());

                    JsonNode descriptions = cveNode.get("cve").get("descriptions");
                    JsonNode description = null;

                    if (descriptions.isArray()) {
                        for (JsonNode node : descriptions) {
                            if (node.has("lang") && "en".equals(node.get("lang").asText())) {
                                description = node.get("value");
                                break;
                            }
                        }
                    }

                    if (null != description) {
                        String descriptionText = description.asText();
                        if (descriptionText.contains("remote code execution")
                                || descriptionText.contains("code execution") || descriptionText.contains("RCE")) {
                            if (vulnerability.getProperties() == null) {
                                vulnerability.setProperties(new ArrayList<>());
                            }
                            Property property = new Property();
                            property.setName("remoteCodeExecutionInDescription");
                            property.setValue("true");
                            vulnerability.getProperties().add(property);

                            rceVulnerabilities.add(vulnerability);

                            rceInDescCounter++;
                        }
                        vulnerability.setDescription(description.asText());
                    }

                    Vulnerability.Source source = new Vulnerability.Source();
                    source.setName("NVD");
                    source.setUrl("https://nvd.nist.gov/");

                    vulnerability.setSource(source);

                    JsonNode cvss = getCvssNode(cveNode);
                    JsonNode baseScore = getBaseScore(cveNode);
                    if (cvss != null) {
                        Vulnerability.Rating rating = new Vulnerability.Rating();
                        rating.setVector(cvss.asText());
                        if (null != baseScore) {
                            rating.setScore(baseScore.asDouble());
                        }
                        if (null == vulnerability.getRatings()) {
                            vulnerability.setRatings(new ArrayList<>());
                        }
                        vulnerability.getRatings().add(rating);
                    }

                    List<Vulnerability.Affect> affectedComponents = getAffectedComponents(cveNode);

                    vulnerability.setAffects(affectedComponents);

                    List<Integer> cwes = getCWEs(cveNode);

                    vulnerability.setCwes(cwes);

                    vulnerabilities.add(vulnerability);
                }
            }
        }

        bom.setVulnerabilities(vulnerabilities);

        BomJsonGenerator generator = BomGeneratorFactory.createJson(Version.VERSION_14, bom);

        String bomJson = generator.toJsonString();

        try (FileWriter writer = new FileWriter(fileName)) {
            writer.write(bomJson);
        }
    }

    private static List<Integer> getCWEs(JsonNode cveNode) {
        if (cveNode.get("cve").has("weaknesses")) {
            JsonNode problemtype = cveNode.get("cve").get("weaknesses");
            if (problemtype.isArray()) {
                for (JsonNode d : problemtype) {
                    if (d.has("description")) {
                        JsonNode description = d.get("description");
                        if (description.isArray()) {
                            List<Integer> cwes = new ArrayList<>();
                            for (JsonNode dd : description) {
                                if (dd.has("value")) {
                                    String value = dd.get("value").asText();
                                    String[] cwe = value.split("-");

                                    if (value.equals("NVD-CWE-noinfo") || value.equals("NVD-CWE-Other")) {
                                        cwes.add(Integer.valueOf(-1));
                                    } else {
                                        if (!cwe[1].equals("CWE")) {
                                            cwes.add(Integer.valueOf(cwe[1]));
                                        } else {
                                            logger.info("CWE Value " + value);
                                        }
                                    }
                                }
                            }
                            return cwes;
                        }
                    }
                }
            }
        }
        return null;
    }

    private static List<Vulnerability.Affect> getAffectedComponents(JsonNode cveNode) {
        if (cveNode.get("cve").has("configurations")) {
            JsonNode configurations = cveNode.get("cve").get("configurations");
            JsonNode nodes = configurations.get(0).get("nodes");
            List<Vulnerability.Affect> affected = new ArrayList<>();
            for (JsonNode node : nodes) {
                for (JsonNode cpeMatch : node) {
                    if (cpeMatch.isArray()) {
                        // return cpeMatch.toPrettyString();
                        for (JsonNode n : cpeMatch) {
                            Vulnerability.Affect affect = new Vulnerability.Affect();
                            if (n.has("criteria")) {
                                affect.setRef(n.get("criteria").asText());
                                affected.add(affect);
                            }
                        }
                    }
                }
            }
            return affected;
        }
        return null;
    }

    private static JsonNode getCvssNode(JsonNode cveNode) {
        JsonNode cvss = null;
        if (cveNode.get("cve").has("metrics")) {
            if (cveNode.get("cve").get("metrics").has("cvssMetricV31")) {
                cvss = cveNode.get("cve").get("metrics").get("cvssMetricV31").get(0).get("cvssData")
                        .get("vectorString");
            } else if (cveNode.get("cve").get("metrics").has("cvssMetricV30")) {
                cvss = cveNode.get("cve").get("metrics").get("cvssMetricV30").get(0).get("cvssData")
                        .get("vectorString");
            } else if (cveNode.get("cve").get("metrics").has("cvssMetricV2")) {
                cvss = cveNode.get("cve").get("metrics").get("cvssMetricV2").get(0).get("cvssData").get("vectorString");
            } else {
                logger.warn("No CVSS found for CVE: " + cveNode.get("cve").get("id").asText());
            }
        }
        return cvss;
    }

    private static JsonNode getBaseScore(JsonNode cveNode) {
        JsonNode cvss = null;
        if (cveNode.get("cve").has("metrics")) {
            if (cveNode.get("cve").get("metrics").has("cvssMetricV31")) {
                cvss = cveNode.get("cve").get("metrics").get("cvssMetricV31").get(0).get("cvssData").get("baseScore");
            } else if (cveNode.get("cve").get("metrics").has("cvssMetricV30")) {
                cvss = cveNode.get("cve").get("metrics").get("cvssMetricV30").get(0).get("cvssData").get("baseScore");
            } else if (cveNode.get("cve").get("metrics").has("cvssMetricV2")) {
                cvss = cveNode.get("cve").get("metrics").get("cvssMetricV2").get(0).get("cvssData").get("baseScore");
            } else {
                logger.warn("No baseScore found for CVE: " + cveNode.get("cve").get("id").asText());
            }
        }
        return cvss;
    }
}
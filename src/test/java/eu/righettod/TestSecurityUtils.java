package eu.righettod;


import org.apache.commons.lang3.StringUtils;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Collection of unit tests for the methods of the class "eu.righettod.SecurityUtils".<br>
 *
 * @see "https://junit.org/junit5/docs/current/user-guide/"
 * @see "https://www.baeldung.com/junit-5-migration"
 */
public class TestSecurityUtils {

    private static final String TEST_DATA_DIRECTORY = "src/test/resources";

    private static final String TEMPLATE_MESSAGE_FALSE_NEGATIVE_FOR_FILE = "File '%s' must be detected as NOT safe!";

    private static final String TEMPLATE_MESSAGE_FALSE_POSITIVE_FOR_FILE = "File '%s' must be detected as safe!";

    private String getTestFilePath(String testFileName) {
        return String.format("%s/%s", TEST_DATA_DIRECTORY, testFileName);
    }

    @Test
    public void isWeakPINCode() {
        List<String> pinCodes = Arrays.asList("0", "00", "111", "55555");
        pinCodes.forEach(pinCode -> {
            assertTrue(SecurityUtils.isWeakPINCode(pinCode), String.format("PIN '%s' with length < 6 must be detected as weak!", pinCode));
        });
        pinCodes = Arrays.asList("111111", "000000", "666666", "7777777");
        pinCodes.forEach(pinCode -> {
            assertTrue(SecurityUtils.isWeakPINCode(pinCode), String.format("PIN '%s' containing only the same number or only a sequence of zero must be detected as weak!", pinCode));
        });
        pinCodes = Arrays.asList("123456", "654321", "456789", "987654", "187973");
        pinCodes.forEach(pinCode -> {
            assertTrue(SecurityUtils.isWeakPINCode(pinCode), String.format("PIN '%s' containing sequence of following incremental or decremental numbers must be detected as weak!", pinCode));
        });
        pinCodes = Arrays.asList("185973", "246391");
        pinCodes.forEach(pinCode -> {
            assertFalse(SecurityUtils.isWeakPINCode(pinCode), String.format("PIN '%s' must not be detected as weak!", pinCode));
        });
    }

    @Test
    public void isWord972003DocumentSafe() {
        List<String> unsafeFileList = Arrays.asList("test-putty.exe.doc", "test-with-macro.doc", "test-with-macro.dot", "test-with-ole-object.doc", "test-with-ole-object.dot");
        unsafeFileList.forEach(f -> {
            String testFile = getTestFilePath(f);
            assertFalse(SecurityUtils.isWord972003DocumentSafe(testFile), String.format(TEMPLATE_MESSAGE_FALSE_NEGATIVE_FOR_FILE, testFile));
        });
        List<String> safeFileList = Arrays.asList("test-without-macro.doc", "test-without-macro.dot");
        safeFileList.forEach(f -> {
            String testFile = getTestFilePath(f);
            assertTrue(SecurityUtils.isWord972003DocumentSafe(testFile), String.format(TEMPLATE_MESSAGE_FALSE_POSITIVE_FOR_FILE, testFile));
        });
    }

    @Test
    public void isXMLSafe() {
        List<String> unsafeFileList = Arrays.asList("test-dtd.xml", "test-xxe.xml", "test-xinclude.xml");
        unsafeFileList.forEach(f -> {
            String testFile = getTestFilePath(f);
            assertFalse(SecurityUtils.isXMLSafe(testFile), String.format(TEMPLATE_MESSAGE_FALSE_NEGATIVE_FOR_FILE, testFile));
        });
        List<String> safeFileList = Arrays.asList("test-nodtd-noxxe-noxinclude.xml");
        safeFileList.forEach(f -> {
            String testFile = getTestFilePath(f);
            assertTrue(SecurityUtils.isXMLSafe(testFile), String.format(TEMPLATE_MESSAGE_FALSE_POSITIVE_FOR_FILE, testFile));
        });
    }

    @Test
    public void extractAllPDFLinks() throws Exception {
        String testFile = getTestFilePath("test-pdf-with-link-to-malicious-file.pdf");
        List<URL> links = SecurityUtils.extractAllPDFLinks(testFile);
        assertEquals(2, links.size());
        assertEquals("https://www.virustotal.com/gui/url/7206f3cac892dd5dcf5268d5a6642a26ab33976349a06e031dbf73adc4267f2b?nocache=1", links.get(0).toString());
        assertEquals("https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe", links.get(1).toString());
        testFile = getTestFilePath("test-pdf-nolink.pdf");
        links = SecurityUtils.extractAllPDFLinks(testFile);
        assertEquals(0, links.size());
    }

    @Test
    public void identifyMimeType() {
        Map<String, String> testFileList = new HashMap<>();
        testFileList.put("test-putty.exe.doc", "application/x-msdownload");
        testFileList.put("test-pdf-with-link-to-malicious-file.pdf", "application/pdf");
        testFileList.put("test-with-macro.doc", "application/x-tika-msoffice");
        testFileList.put("test-java-app.jar", "application/zip");
        testFileList.put("test-java-app.jar.zip", "application/zip");
        testFileList.put("test-java-app.jar.txt", "application/zip");
        testFileList.put("test-batch.txt", "application/x-bat");
        testFileList.forEach((testFileName, contentType) -> {
            String testFile = getTestFilePath(testFileName);
            try {
                String contentTypeIdentified = SecurityUtils.identifyMimeType(Files.readAllBytes(Paths.get(testFile)));
                assertEquals(contentType, contentTypeIdentified);
            } catch (IOException e) {
                fail(String.format("Error while testing file '%s': %s.", testFileName, e.getMessage()));
            }
        });

    }

    @Test
    public void isZIPSafe() {
        List<String> unsafeFileList = Arrays.asList("test-zipbomb.zip", "test-zipslip.zip");
        unsafeFileList.forEach(f -> {
            String testFile = getTestFilePath(f);
            assertFalse(SecurityUtils.isZIPSafe(testFile, 2, true), String.format(TEMPLATE_MESSAGE_FALSE_NEGATIVE_FOR_FILE, testFile));
        });
        String testFileSpecialCase = getTestFilePath("test-zipslip.zip");
        assertFalse(SecurityUtils.isZIPSafe(testFileSpecialCase, 1000, false), String.format(TEMPLATE_MESSAGE_FALSE_NEGATIVE_FOR_FILE, testFileSpecialCase));
        List<String> safeFileList = Arrays.asList("test-zipclean1.zip", "test-zipclean1.zip");
        safeFileList.forEach(f -> {
            String testFile = getTestFilePath(f);
            assertTrue(SecurityUtils.isZIPSafe(testFile, 5, false), String.format(TEMPLATE_MESSAGE_FALSE_POSITIVE_FOR_FILE, testFile));
        });
    }

    @Test
    public void isRelativeURL() {
        List<String> nonRelativeURLList = Arrays.asList("//righettod.eu", "http://righettod.eu", "https://righettod.eu", "ssh://righettod.eu", "http://login:pass@righettod.eu");
        nonRelativeURLList.forEach(u -> {
            assertFalse(SecurityUtils.isRelativeURL(u), String.format("URL '%s' must be detected as NOT relative!", u));
        });
        List<String> relativeURLList = Arrays.asList("/righettod.eu", "/test.jsp");
        relativeURLList.forEach(u -> {
            assertTrue(SecurityUtils.isRelativeURL(u), String.format("URL '%s' must be detected as relative!", u));
        });
    }

    @Test
    public void isPDFSafe() {
        List<String> unsafeFileList = Arrays.asList("test-putty.exe.pdf", "test-pdf-with-link-to-malicious-file.pdf", "test-dynamic-doc.pdf");
        unsafeFileList.forEach(f -> {
            String testFile = getTestFilePath(f);
            assertFalse(SecurityUtils.isPDFSafe(testFile), String.format(TEMPLATE_MESSAGE_FALSE_NEGATIVE_FOR_FILE, testFile));
        });
        List<String> safeFileList = Arrays.asList("test-pdf-nolink.pdf", "test-simplecleandoc.pdf");
        safeFileList.forEach(f -> {
            String testFile = getTestFilePath(f);
            assertTrue(SecurityUtils.isPDFSafe(testFile), String.format(TEMPLATE_MESSAGE_FALSE_POSITIVE_FOR_FILE, testFile));
        });
    }

    @Test
    public void clearPDFMetadata() throws Exception {
        String testFile = getTestFilePath("test-doc-with-metadata.pdf");
        try (PDDocument document = Loader.loadPDF(new File(testFile))) {
            //Ensure that the source PDF has the expected metadata
            assertEquals("PDFKit.NET 4.0.9.0", document.getDocumentInformation().getProducer());
            assertEquals("RIGHETTOD", document.getDocumentInformation().getAuthor());
            assertEquals("My Java API 12.5", document.getDocumentInformation().getCreator());
            assertEquals("holidays,internal", document.getDocumentInformation().getKeywords());
            assertEquals("MyValue", document.getDocumentInformation().getCustomMetadataValue("CustomMetadata"));
            //Clear the metadata
            SecurityUtils.clearPDFMetadata(document);
            //Ensure that the result PDF has not expected metadata anymore
            assertNull(document.getDocumentInformation().getProducer(), "The metadata PRODUCER was expected to be NULL!");
            assertNull(document.getDocumentInformation().getAuthor(), "The metadata AUTHOR was expected to be NULL!");
            assertNull(document.getDocumentInformation().getKeywords(), "The metadata KEYWORDS was expected to be NULL!");
            assertNull(document.getDocumentInformation().getCreator(), "The metadata CREATOR was expected to be NULL!");
            assertNull(document.getDocumentInformation().getCustomMetadataValue("CustomMetadata"), "The custom metadata 'CustomMetadata' was expected to be NULL!");
        }
    }

    @Test
    public void isPublicIPAddress() throws Exception {
        final String templateMsgIPFalseNegative = "IP address '%s' must be detected as NOT public!";
        final String templateMsgIPFalsePositive = "IP address '%s' must be detected as public!";
        //----Test IP V4
        //Standard private IPv4 addresses: https://www.arin.net/reference/research/statistics/address_filters/
        List<String> ipV4AddressesList = Arrays.asList("127.0.1.1", "10.10.10.10", "172.16.5.5", "192.168.178.5");
        ipV4AddressesList.forEach(ip -> {
            assertFalse(SecurityUtils.isPublicIPAddress(ip), String.format(templateMsgIPFalseNegative, ip));
        });
        //Encoded version of an private IPv4 address: https://www.vultr.com/resources/ipv4-converter/?ip_address=10.10.10.10
        //10.10.10.10 => 168430090  (Integer representation)
        //10.10.10.10 => 0x0A0A0A0A (Hex representation)
        ipV4AddressesList = Arrays.asList("168430090", "0x0A0A0A0A");
        ipV4AddressesList.forEach(ip -> {
            assertFalse(SecurityUtils.isPublicIPAddress(ip), String.format(templateMsgIPFalseNegative, ip));
        });
        //Multicast IPv4 addresses: https://en.wikipedia.org/wiki/Multicast_address
        ipV4AddressesList = Arrays.asList("224.0.0.0", "224.0.0.1", "224.0.0.2", "224.0.0.4", "224.0.0.5", "224.0.0.6", "224.0.0.9", "224.0.0.10", "224.0.0.13", "224.0.0.18", "224.0.0.19", "224.0.0.20", "224.0.0.21", "224.0.0.22", "224.0.0.102", "224.0.0.107", "224.0.0.251", "224.0.0.252", "224.0.0.253");
        ipV4AddressesList.forEach(ip -> {
            assertFalse(SecurityUtils.isPublicIPAddress(ip), String.format(templateMsgIPFalseNegative, ip));
        });
        //Valid public IPv4 addresses
        ipV4AddressesList = Arrays.asList("213.186.33.87", "172.217.23.110", "192.17.85.45");
        ipV4AddressesList.forEach(ip -> {
            assertTrue(SecurityUtils.isPublicIPAddress(ip), String.format(templateMsgIPFalsePositive, ip));
        });
        //----Test IP V6
        //Non public IPv6 addresses: https://www.ripe.net/media/documents/ipv6-address-types.pdf
        List<String> ipV6AddressesList = Arrays.asList("fdf8:f53b:82e4::53", "fe80::200:5aee:feaa:20a2", "fd38:5d06:4217:2ef7:ffff:ffff:ffff:ffff", "ff01:0:0:0:0:0:0:2", "0:0:0:0:0:0:0:1", "::1");
        ipV6AddressesList.forEach(ip -> {
            assertFalse(SecurityUtils.isPublicIPAddress(ip), String.format(templateMsgIPFalseNegative, ip));
        });
        //Public IPv6 addresses: https://www.lddgo.net/en/network/randomip
        String dataFile = getTestFilePath("test-public-ipv6.txt");
        ipV6AddressesList = Files.readAllLines(Paths.get(dataFile));
        ipV6AddressesList.forEach(ip -> {
            assertTrue(SecurityUtils.isPublicIPAddress(ip), String.format(templateMsgIPFalsePositive, ip));
        });
    }

    @Test
    public void computeHashNoProneToAbuseOnParts() throws Exception {
        final String msgError = "Hash are expected to be different!";
        final String exceptionMsg = "No part must be null!";
        //Test cases for valid input passed
        List<String> reference = Arrays.asList("Hello from", " my amazing country", " in europe!");
        List<String> abuse1 = Arrays.asList("Hello fro", "m my amazing count", "ry in europe!");
        List<String> abuse2 = Arrays.asList("", "Hello from my amazing country in europe!", "");
        //--Ensure that source string are the sames when parts are joined
        assertEquals(String.join("", reference), String.join("", abuse1));
        assertEquals(String.join("", reference), String.join("", abuse2));
        assertEquals(String.join("", abuse1), String.join("", abuse2));
        //--Compute and validate hashes
        byte[] hashReference = SecurityUtils.computeHashNoProneToAbuseOnParts(reference);
        byte[] hashAbuse1 = SecurityUtils.computeHashNoProneToAbuseOnParts(abuse1);
        byte[] hashAbuse2 = SecurityUtils.computeHashNoProneToAbuseOnParts(abuse2);
        assertFalse(Arrays.equals(hashReference, hashAbuse1), msgError);
        assertFalse(Arrays.equals(hashReference, hashAbuse2), msgError);
        assertFalse(Arrays.equals(hashAbuse1, hashAbuse2), msgError);
        //Test case for invalid input passed
        List<String> invalidInput = Arrays.asList("Hello from", " my amazing country", " in europe!", null);
        IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> SecurityUtils.computeHashNoProneToAbuseOnParts(invalidInput),
                "Expected IllegalArgumentException() to throw but invalid input was accepted!"
        );
        assertTrue(thrown.getMessage().contains(exceptionMsg));
    }

    @Test
    public void isXMLOnlyUseAllowedXSDorDTD() {
        final String msgErrorFalseNegative = "Reference to an invalid DTD/XSD must be detected!";
        final String msgErrorFalsePositive = "Reference to an invalid DTD/XSD must NOT be detected!";
        //Non allowed DTD
        String testFile = getTestFilePath("test-allowed-sid-in-dtd.xml");
        boolean isSafe = SecurityUtils.isXMLOnlyUseAllowedXSDorDTD(testFile, List.of("https://righettod.eu/official.dtd"));
        assertFalse(isSafe, msgErrorFalseNegative);
        //Non allowed XSD
        testFile = getTestFilePath("test-allowed-sid-in-xsd.xml");
        isSafe = SecurityUtils.isXMLOnlyUseAllowedXSDorDTD(testFile, List.of("https://righettod.eu/official.xsd"));
        assertFalse(isSafe, msgErrorFalseNegative);
        //Non allowed Public Identifier
        testFile = getTestFilePath("test-nonallowed-pid.xml");
        isSafe = SecurityUtils.isXMLOnlyUseAllowedXSDorDTD(testFile, List.of("https://righettod.eu/official.dtd"));
        assertFalse(isSafe, msgErrorFalseNegative);
        //Allowed DTD
        testFile = getTestFilePath("test-allowed-sid-in-dtd.xml");
        isSafe = SecurityUtils.isXMLOnlyUseAllowedXSDorDTD(testFile, List.of("https://company.com/test.dtd"));
        assertTrue(isSafe, msgErrorFalsePositive);
        //Allowed XSD
        testFile = getTestFilePath("test-allowed-sid-in-xsd.xml");
        isSafe = SecurityUtils.isXMLOnlyUseAllowedXSDorDTD(testFile, List.of("https://company.com/test.xsd"));
        assertTrue(isSafe, msgErrorFalsePositive);
    }

    @Test
    public void isExcelCSVSafe() throws IOException {
        String testFile;
        boolean isSafe;
        String caseIdentifier;

        //Test unsafe CSV cases
        int unsafeTestCaseCount = 5;
        for (int caseId = 0; caseId < unsafeTestCaseCount; caseId++) {
            caseIdentifier = StringUtils.leftPad(Integer.toString(caseId), 2, "0");
            testFile = getTestFilePath(String.format("test-excel-csv-unsafe%s.csv", caseIdentifier));
            isSafe = SecurityUtils.isExcelCSVSafe(testFile);
            assertFalse(isSafe, String.format(TEMPLATE_MESSAGE_FALSE_NEGATIVE_FOR_FILE, StringUtils.leftPad(Integer.toString(caseId), 2, "0")));
        }
        //Test safe CSV cases
        int safeTestCaseCount = 4;
        for (int caseId = 0; caseId < safeTestCaseCount; caseId++) {
            caseIdentifier = StringUtils.leftPad(Integer.toString(caseId), 2, "0");
            testFile = getTestFilePath(String.format("test-excel-csv-safe%s.csv", caseIdentifier));
            isSafe = SecurityUtils.isExcelCSVSafe(testFile);
            assertTrue(isSafe, String.format(TEMPLATE_MESSAGE_FALSE_POSITIVE_FOR_FILE, testFile));
        }

    }
}


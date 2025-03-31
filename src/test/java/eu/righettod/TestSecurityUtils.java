package eu.righettod;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.imaging.ImageInfo;
import org.apache.commons.imaging.Imaging;
import org.apache.commons.lang3.StringUtils;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

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

    private final SecureRandom secureRandom = new SecureRandom();

    private String getTestFilePath(String testFileName) {
        return String.format("%s/%s", TEST_DATA_DIRECTORY, testFileName);
    }

    private long getTestFileSize(String testFileName) {
        return new File(getTestFilePath(testFileName)).length();
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
        List<String> unsafeFileList = Arrays.asList("test-dtd.xml", "test-xxe.xml", "test-xinclude.xml", "test-xee.xml");
        unsafeFileList.forEach(f -> {
            String testFile = getTestFilePath(f);
            assertFalse(SecurityUtils.isXMLSafe(testFile), String.format(TEMPLATE_MESSAGE_FALSE_NEGATIVE_FOR_FILE, testFile));
        });
        List<String> safeFileList = Arrays.asList("test-nodtd-noxxe-noxee-noxinclude.xml");
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
        String exceptionMsg;
        String assertErrorMsg = "Expected IllegalArgumentException() to throw but invalid input was accepted!";
        //--Null string passed as a part
        exceptionMsg = "No part must be null!";
        final List<String> invalidInput1 = Arrays.asList("Hello from", " my amazing country", " in europe!", null);
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> SecurityUtils.computeHashNoProneToAbuseOnParts(invalidInput1), assertErrorMsg);
        assertTrue(thrown.getMessage().contains(exceptionMsg));
        //--A part contain the separator character
        exceptionMsg = "The character '|', used as parts separator, must be absent from every parts!";
        final List<String> invalidInput2 = Arrays.asList("Hello from", " my amazing | country");
        thrown = assertThrows(IllegalArgumentException.class, () -> SecurityUtils.computeHashNoProneToAbuseOnParts(invalidInput2), assertErrorMsg);
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

    @Test
    public void ensureSerializedObjectIntegrity() throws Exception {
        //Generate test material
        byte[] secret = new byte[32];
        secureRandom.nextBytes(secret);
        ByteArrayOutputStream testUserSerializedBytes = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(testUserSerializedBytes)) {
            oos.writeObject(new User(new Date(), "RIGHETTOD"));
            oos.flush();
        }
        Base64.Encoder b64Encoder = Base64.getEncoder();
        Base64.Decoder b64Decoder = Base64.getDecoder();
        String testUserSerializedBytesEncoded = b64Encoder.encodeToString(testUserSerializedBytes.toByteArray());
        //Test "protect" processing
        Map<String, Object> results = SecurityUtils.ensureSerializedObjectIntegrity(ProcessingMode.PROTECT, testUserSerializedBytesEncoded, secret);
        assertEquals(3, results.size());
        assertEquals(ProcessingMode.PROTECT.toString(), results.get("PROCESSING_MODE"));
        assertEquals(Boolean.TRUE, results.get("STATUS"));
        String protectedSerializedObject = (String) results.get("RESULT");
        String[] parts = protectedSerializedObject.split(":");
        assertEquals(2, parts.length);
        assertEquals(testUserSerializedBytesEncoded, parts[0]);
        assertNotEquals(0, b64Decoder.decode(parts[1]).length);
        //Test "validate" processing
        //--Case validation succeed (HMAC match)
        results = SecurityUtils.ensureSerializedObjectIntegrity(ProcessingMode.VALIDATE, protectedSerializedObject, secret);
        assertEquals(3, results.size());
        assertEquals(ProcessingMode.VALIDATE.toString(), results.get("PROCESSING_MODE"));
        assertEquals(Boolean.TRUE, results.get("STATUS"));
        assertEquals(protectedSerializedObject, results.get("RESULT"));
        //--Case validation failed due to malicious serialized object provided (HMAC not match)
        parts = protectedSerializedObject.split(":");
        String encodedSerializedObject = parts[0];
        String encodedHMAC = parts[1];
        byte[] alteredObject = b64Decoder.decode(encodedSerializedObject);
        alteredObject[0] += 1;
        encodedSerializedObject = b64Encoder.encodeToString(alteredObject);
        String alteredInput = encodedSerializedObject + ":" + encodedHMAC;
        results = SecurityUtils.ensureSerializedObjectIntegrity(ProcessingMode.VALIDATE, alteredInput, secret);
        assertEquals(ProcessingMode.VALIDATE.toString(), results.get("PROCESSING_MODE"));
        assertEquals(Boolean.FALSE, results.get("STATUS"));
        assertNotEquals(alteredInput, results.get("RESULT"));
    }

    @Test
    public void isJSONSafe() {
        final int maxItems = 10;
        //Test unsafe json files
        List<String> testUnsafeJsonFiles = List.of("test-json-100arrayitems.json", "test-json-100nestedobjects.json", "test-json-100nestedarrays.json", "test-json-50000nestedobjects.json");
        testUnsafeJsonFiles.forEach(f -> {
            try {
                String testFile = getTestFilePath(f);
                boolean isSafe = SecurityUtils.isJSONSafe(Files.readString(Paths.get(testFile)), maxItems, maxItems);
                assertFalse(isSafe, String.format(TEMPLATE_MESSAGE_FALSE_NEGATIVE_FOR_FILE, f));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        //Test safe but invalid json files
        List<String> testSafeButInvalidJsonFiles = List.of("test-json-safebutinvalid.json");
        testSafeButInvalidJsonFiles.forEach(f -> {
            try {
                String testFile = getTestFilePath(f);
                boolean isSafe = SecurityUtils.isJSONSafe(Files.readString(Paths.get(testFile)), maxItems, maxItems);
                assertFalse(isSafe, String.format(TEMPLATE_MESSAGE_FALSE_NEGATIVE_FOR_FILE, f));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        //Test safe json files
        List<String> testSafeJsonFiles = List.of("test-json-escapeddoublequotes.json", "test-json-safe00.json");
        testSafeJsonFiles.forEach(f -> {
            try {
                String testFile = getTestFilePath(f);
                boolean isSafe = SecurityUtils.isJSONSafe(Files.readString(Paths.get(testFile)), maxItems, maxItems);
                assertTrue(isSafe, String.format(TEMPLATE_MESSAGE_FALSE_POSITIVE_FOR_FILE, f));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    public void isImageSafe() {
        //Test safe image cases
        List<String> safeFileList = Arrays.asList("test-img-png-clean.png", "test-img-jpeg-clean.jpg", "test-img-gif-clean.gif");
        final List<String> imageAllowedMimeTypesCase1 = List.of("image/png", "image/jpeg", "image/gif");
        safeFileList.forEach(f -> {
            String testFile = getTestFilePath(f);
            assertTrue(SecurityUtils.isImageSafe(testFile, imageAllowedMimeTypesCase1), String.format(TEMPLATE_MESSAGE_FALSE_POSITIVE_FOR_FILE, testFile));
        });
        //Test safe image cases but with non allowed mime types
        final List<String> imageAllowedMimeTypesCase2 = List.of("image/emf");
        safeFileList.forEach(f -> {
            String testFile = getTestFilePath(f);
            assertFalse(SecurityUtils.isImageSafe(testFile, imageAllowedMimeTypesCase2), String.format(TEMPLATE_MESSAGE_FALSE_NEGATIVE_FOR_FILE, testFile));
        });
        //Test unsafe image cases
        List<String> unsafeFileList = Arrays.asList("test-img-png-phpcode-in-comments.png", "test-img-jpeg-cmd-in-artist.jpg", "test-img-jpeg-cmd-in-software.jpg", "test-img-exe-with-png-magicbytes.png", "test-img-gif-xsspayload-inserted-with-sighook-pixload.gif");
        final List<String> imageAllowedMimeTypesCase3 = List.of("image/png", "image/jpeg", "image/gif");
        unsafeFileList.forEach(f -> {
            String testFile = getTestFilePath(f);
            assertFalse(SecurityUtils.isImageSafe(testFile, imageAllowedMimeTypesCase3), String.format(TEMPLATE_MESSAGE_FALSE_NEGATIVE_FOR_FILE, testFile));
        });
    }

    @Test
    public void sanitizeFile() throws Exception {
        String errorMsg = "The sanitized file size must be different from the original file size (%s) !";
        String testFile;
        long testFileLength;
        byte[] sanitizedContent;
        //Test PDF files
        List<String> pdfFileList = List.of("test-sanitize-doc-pdf-with-malicious-files-concatenated.pdf");
        for (String pdfFile : pdfFileList) {
            testFile = getTestFilePath(pdfFile);
            testFileLength = getTestFileSize(pdfFile);
            sanitizedContent = SecurityUtils.sanitizeFile(testFile, InputFileType.PDF);
            assertNotEquals(testFileLength, sanitizedContent.length, String.format(errorMsg, pdfFile));
            //In addition: Test that the result is still a valid PDF file
            try (PDDocument document = Loader.loadPDF(sanitizedContent)) {
                assertTrue(document.getNumberOfPages() > 0);
            }
        }
        //Test image files
        List<String> imageFileList = List.of("test-sanitize-png-with-malicious-files-concatenated.png", "test-sanitize-gif-with-malicious-files-concatenated.gif", "test-sanitize-jpeg-with-malicious-files-concatenated.jpg", "test-sanitize-bitmap-with-malicious-files-concatenated.bmp");
        for (String imageFile : imageFileList) {
            testFile = getTestFilePath(imageFile);
            testFileLength = getTestFileSize(imageFile);
            sanitizedContent = SecurityUtils.sanitizeFile(testFile, InputFileType.IMAGE);
            assertNotEquals(testFileLength, sanitizedContent.length, String.format(errorMsg, imageFile));
            //In addition: Test that the result is still a valid image file
            ImageInfo imgInfo = Imaging.getImageInfo(sanitizedContent);
            assertTrue(imgInfo.getWidth() > 0 && imgInfo.getHeight() > 0);
        }
    }

    @Test
    public void isEmailAddress() {
        final String templateMsgFalseNegative = "Email address '%s' must be detected as invalid!";
        final String templateMsgFalsePositive = "Email address '%s' must be detected as valid!";
        //Test invalid email addresses
        List<String> invalidEmailAddressesList = Arrays.asList("=?utf-8?q?=41=42=43?=test@test.com", "=?utf-7?q?=41GYAbwBvAGIAYBy-?=@test@com", "=?utf-8?b?Zm9vYmFy?=@test.com", "@mail.mit.edu:peter@hotmail.com", "peter%hotmail.com@mail.mit.edu", "rusx!umoskva!kgbvax!dimitri@gateway.ru", "test@example.com@evil.com", "(foo)user@(bar)example.com", "postmaster@[123.123.123.123]", "postmaster@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]", "foo@xn--mnchen-2ya.com");
        invalidEmailAddressesList.forEach(addr -> {
            assertFalse(SecurityUtils.isEmailAddress(addr), String.format(templateMsgFalseNegative, addr));
        });
        //Test valid email addresses
        List<String> validEmailAddressesList = Arrays.asList("test@test.com", "test-test@test.com", "test.test@test.com", "test_test@test.com", "test132@test.com", "test+label@test.com", "\"John..Doe\"@example.com", "\"@\"@example.com");
        validEmailAddressesList.forEach(addr -> {
            assertTrue(SecurityUtils.isEmailAddress(addr), String.format(templateMsgFalsePositive, addr));
        });
    }

    @Test
    public void isPSD2StetSafeCertificateURL() {
        final String templateMsgIPFalseNegative = "URL '%s' must be detected as invalid!";
        final String templateMsgIPFalsePositive = "URL '%s' must be detected as valid!";
        //Test invalid urls
        List<String> invalidUrls = Arrays.asList("https://test.com/myQsealCertificate_714f8154ec259ac40b8a9786c9908488b2582X68b17e865fede4636d726b709fX", "https://test.com/myQsealCertificate_714f8154ec259ac40b8a9786c9908488b2582b68b17e865fede4636d726b709f?a=b", "http://test.com/myQsealCertificate_714f8154ec259ac40b8a9786c9908488b2582b68b17e865fede4636d726b709f", "https://test.com/myQsealCertificate_714f8154ec259ac40b8a9786c99", "https://test.com/myQsealCertificate-714f8154ec259ac40b8a9786c9908488b2582b68b17e865fede4636d726b709f");
        invalidUrls.forEach(u -> {
            assertFalse(SecurityUtils.isPSD2StetSafeCertificateURL(u), String.format(templateMsgIPFalseNegative, u));
        });
        //Test valid urls
        String validUrl = "https://raw.githubusercontent.com/righettod/code-snippets-security-utils/main/src/test/resources/myQsealCertificate_873dddcc49456290e2315cf3335b650715751fecdebf517e73b8642696ecc406";
        assertTrue(SecurityUtils.isPSD2StetSafeCertificateURL(validUrl), String.format(templateMsgIPFalsePositive, validUrl));
    }

    @Test
    public void applyURLDecoding() {
        final String refDecodedData = "Hello World!!!";
        //Key is the decoding threshold and value is the URL encoded value (threshold times)
        final Map<Integer, String> testData = new HashMap<>();
        testData.put(1, "Hello%20World%21%21%21");
        testData.put(2, "Hello%2520World%2521%2521%2521");
        testData.put(3, "Hello%252520World%252521%252521%252521");
        testData.put(4, "Hello%25252520World%25252521%25252521%25252521");
        testData.put(5, "Hello%2525252520World%2525252521%2525252521%2525252521");
        testData.put(6, "Hello%252525252520World%252525252521%252525252521%252525252521");
        //Test valid cases
        testData.forEach((threshold, encodedData) -> {
            assertEquals(refDecodedData, SecurityUtils.applyURLDecoding(encodedData, threshold));
        });
        //Test invalid cases
        SecurityException thrown = assertThrows(SecurityException.class, () -> SecurityUtils.applyURLDecoding(testData.get(6), 3), "SecurityException expected!");
        assertTrue(thrown.getMessage().equalsIgnoreCase("Decoding round threshold of 3 reached!"));
    }

    @Test
    public void isPathSafe() {
        final String templateMsgFalseNegative = "Path '%s' must be detected as invalid!";
        final String templateMsgFalsePositive = "Path '%s' must be detected as valid!";
        //Test invalid cases
        List<String> invalidPaths = Arrays.asList("/home/../../../../etc/password", "%2Fhome%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpassword", //URL encoding X1
                "%252Fhome%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F%252E%252E%252Fetc%252Fpassword", //URL encoding X2
                "%25252525252Fhome%25252525252F%25252525252E%25252525252E%25252525252F%25252525252E%25252525252E%25252525252F%25252525252E%25252525252E%25252525252F%25252525252E%25252525252E%25252525252Fetc%25252525252Fpassword", //URL encoding X6
                "/home/..\\/..\\/..\\/..\\/etc/password", "/home/..\\\\/..\\/..\\\\/..\\/etc/password", "D:\\test..\\\\..\\test");
        invalidPaths.forEach(p -> {
            assertFalse(SecurityUtils.isPathSafe(p), String.format(templateMsgFalseNegative, p));
        });
        //Test valid cases
        List<String> validPaths = Arrays.asList("/home/file", "C:\\test\\file", "test/file", "test\\file");
        validPaths.forEach(p -> {
            assertTrue(SecurityUtils.isPathSafe(p), String.format(templateMsgFalsePositive, p));
        });
    }

    @Test
    public void isXMLHaveCommentsOrXSLProcessingInstructions() {
        //Test detection case for comments
        String testFile = getTestFilePath("test-xml-with-comments.xml");
        boolean result = SecurityUtils.isXMLHaveCommentsOrXSLProcessingInstructions(testFile);
        assertTrue(result, "Comments were expected to be detected!");
        //Test detection case for XSL PI
        testFile = getTestFilePath("test-xml-with-xsl-pi.xml");
        result = SecurityUtils.isXMLHaveCommentsOrXSLProcessingInstructions(testFile);
        assertTrue(result, "XSL PI were expected to be detected!");
        //Test for the clean case
        testFile = getTestFilePath("test-xml-without-comment-or-xsl-pi.xml");
        result = SecurityUtils.isXMLHaveCommentsOrXSLProcessingInstructions(testFile);
        assertFalse(result, "No Comments or XSL PI were expected to be detected!");
    }

    @Test
    public void applyJWTExtraValidation() {
        final String templateMsgIPFalseNegative = "Token '%s' must be detected as invalid!";
        final String templateMsgIPFalsePositive = "Token '%s' must be detected as valid!";
        List<String> revokedTokenJTIList = List.of("TOkEn2", "TOkEn3", "TOkEn4");
        //Test invalid cases
        //--The provided type of token is not the expected one
        DecodedJWT testToken = generateJWTToken(TokenType.ACCESS, "TOKEN1", false, true);
        boolean result = SecurityUtils.applyJWTExtraValidation(testToken, TokenType.ID, revokedTokenJTIList);
        assertFalse(result, String.format(templateMsgIPFalseNegative, testToken.getToken()));
        //--The token JTI claim is part of the revoked token list
        testToken = generateJWTToken(TokenType.ID, "TOKEN2", false, true);
        result = SecurityUtils.applyJWTExtraValidation(testToken, TokenType.ID, revokedTokenJTIList);
        assertFalse(result, String.format(templateMsgIPFalseNegative, testToken.getToken()));
        //---The token JTI claim is not present
        testToken = generateJWTToken(TokenType.REFRESH, null, false, true);
        result = SecurityUtils.applyJWTExtraValidation(testToken, TokenType.REFRESH, revokedTokenJTIList);
        assertFalse(result, String.format(templateMsgIPFalseNegative, testToken.getToken()));
        //---The token is signed with the NONE algorithm
        testToken = generateJWTToken(TokenType.ACCESS, "TOKEN1", true, true);
        result = SecurityUtils.applyJWTExtraValidation(testToken, TokenType.REFRESH, revokedTokenJTIList);
        assertFalse(result, String.format(templateMsgIPFalseNegative, testToken.getToken()));
        //---The token do not have an EXP claim
        testToken = generateJWTToken(TokenType.ACCESS, "TOKEN1", false, false);
        result = SecurityUtils.applyJWTExtraValidation(testToken, TokenType.REFRESH, revokedTokenJTIList);
        assertFalse(result, String.format(templateMsgIPFalseNegative, testToken.getToken()));
        //Test valid cases
        //--Respect all the conditions
        for (TokenType tType : TokenType.values()) {
            testToken = generateJWTToken(tType, "TOKEN1", false, true);
            result = SecurityUtils.applyJWTExtraValidation(testToken, tType, revokedTokenJTIList);
            assertTrue(result, String.format(templateMsgIPFalsePositive, testToken.getToken()));
        }
    }

    private DecodedJWT generateJWTToken(TokenType tokenType, String jti, boolean useNoneAlgorithm, boolean useExpirationDateClaim) {
        String secret = "6dbdd2a3-c7c6-42cf-abea-ca8c20b4d536";
        Algorithm algorithm = Algorithm.HMAC256(secret.getBytes(StandardCharsets.UTF_8));
        Instant expirationTime = Instant.now().plus(Duration.ofHours(1));
        if (useNoneAlgorithm) {
            algorithm = Algorithm.none();
        }
        JWTCreator.Builder builder = JWT.create();
        if (jti != null) {
            builder = builder.withJWTId(jti);
        }
        switch (tokenType) {
            case ACCESS -> builder = builder.withClaim("scope", "BUSINESS_API");
            case ID -> builder = builder.withClaim("name", "test user");
        }
        if (useExpirationDateClaim) {
            builder = builder.withExpiresAt(expirationTime);
        }
        String signedToken = builder.withClaim("tokenTypeHints", tokenType.toString()).sign(algorithm);
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(signedToken);
    }

    @Test
    public void isRegexSafe() {
        final String templateMsgFalseNegative = "Regular expression '%s' must be detected as not safe!";
        final String templateMsgFalsePositive = "Regular expression '%s' must be detected as safe!";
        String testData = "a".repeat(400) + "!";
        //Test unsafe case
        String testRegex = "(.*a){10}";
        boolean result = SecurityUtils.isRegexSafe(testRegex, testData, Optional.empty());
        assertFalse(result, String.format(templateMsgFalseNegative, testRegex));
        //Test safe case
        testRegex = "[a-z]+";
        result = SecurityUtils.isRegexSafe(testRegex, testData, Optional.empty());
        assertTrue(result, String.format(templateMsgFalsePositive, testRegex));
    }

    @Test
    public void computeUUIDv7() {
        int candidatesCount = 1000;
        List<String> history = new ArrayList<>();
        UUID uuid;
        String uuidStr;
        String ref;
        DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern("YYYYMMddHHmmss");
        long mostSigBits;
        long timestampHigh;
        Instant instant;
        LocalDateTime localDateTime;
        for (int i = 0; i < candidatesCount; i++) {
            //Generate a UUID v7
            ref = LocalDateTime.now().format(dateFormat);
            uuid = SecurityUtils.computeUUIDv7();
            uuidStr = uuid.toString();
            //Apply validations
            //--Duplicate
            assertFalse(history.contains(uuidStr), "Duplicate generated UUID identified!");
            //--Version part
            assertEquals('7', uuidStr.charAt(14), "Invalid UUID version identified!");
            //--Timestamp part
            //----Retrieves the first 64 bits of the UUID via "getMostSignificantBits()"
            //----Perform a right shift by 16 bits to isolate the first 48 bits, which represent the timestamp
            //----Convert it to a Date object
            mostSigBits = uuid.getMostSignificantBits();
            timestampHigh = (mostSigBits >> 16) & 0xFFFFFFFFFFFFL;
            instant = Instant.ofEpochMilli(timestampHigh);
            localDateTime = LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
            assertEquals(ref, localDateTime.format(dateFormat), "Invalid UUID timestamp identified!");
            //Add it to the collection of generated UUID
            history.add(uuidStr);
        }
    }
}


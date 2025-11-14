package eu.righettod;


import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.imaging.ImageInfo;
import org.apache.commons.imaging.Imaging;
import org.apache.commons.imaging.common.ImageMetadata;
import org.apache.commons.validator.routines.CreditCardValidator;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDDocumentNameDictionary;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import org.apache.pdfbox.pdmodel.interactive.action.*;
import org.apache.pdfbox.pdmodel.interactive.annotation.AnnotationFilter;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.poi.poifs.filesystem.DirectoryEntry;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.poifs.macros.VBAMacroReader;
import org.apache.tika.detect.DefaultDetector;
import org.apache.tika.detect.Detector;
import org.apache.tika.io.TemporaryResources;
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.mime.MediaType;
import org.apache.tika.mime.MimeTypes;
import org.iban4j.IbanUtil;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.w3c.dom.Document;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.json.Json;
import javax.json.JsonReader;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.XMLEvent;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.ZoneId;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Provides different utilities methods to apply processing from a security perspective.<br>
 * These code snippet:
 * <ul>
 *     <li>Can be used, as "foundation", to customize the validation to the app context.</li>
 *     <li>Were implemented in a way to facilitate adding or removal of validations depending on usage context.</li>
 *     <li>Were centralized on one class to be able to enhance them across time as well as <a href="https://github.com/righettod/code-snippets-security-utils/issues">missing case/bug identification</a>.</li>
 * </ul>
 * <br>
 * <a href="https://github.com/righettod/code-snippets-security-utils">GitHub repository</a>.<br><br>
 * <a href="https://github.com/righettod/code-snippets-security-utils/blob/main/src/main/java/eu/righettod/SecurityUtils.java">Source code of the class</a>.
 */
public class SecurityUtils {
    /**
     * Default constructor: Not needed as the class only provides static methods.
     */
    private SecurityUtils() {
    }

    /**
     * Apply a collection of validation to verify if a provided PIN code is considered weak (easy to guess) or none.<br>
     * This method consider that format of the PIN code is [0-9]{6,}<br>
     * Rule to consider a PIN code as weak:
     * <ul>
     * <li>Length is inferior to 6 positions.</li>
     * <li>Contain only the same number or only a sequence of zero.</li>
     * <li>Contain sequence of following incremental or decremental numbers.</li>
     * </ul>
     *
     * @param pinCode PIN code to verify.
     * @return True only if the PIN is considered as weak.
     */
    public static boolean isWeakPINCode(String pinCode) {
        boolean isWeak = true;
        //Length is inferior to 6 positions
        //Use "Long.parseLong(pinCode)" to cause a NumberFormatException if the PIN is not a numeric one
        //and to ensure that the PIN is not only a sequence of zero
        if (pinCode != null && Long.parseLong(pinCode) > 0 && pinCode.trim().length() > 5) {
            //Contain only the same number
            String regex = String.format("^[%s]{%s}$", pinCode.charAt(0), pinCode.length());
            if (!Pattern.matches(regex, pinCode)) {
                //Contain sequence of following incremental or decremental numbers
                char previousChar = 'X';
                boolean containSequence = false;
                for (char c : pinCode.toCharArray()) {
                    if (previousChar != 'X') {
                        int previousNbr = Integer.parseInt(String.valueOf(previousChar));
                        int currentNbr = Integer.parseInt(String.valueOf(c));
                        if (currentNbr == (previousNbr - 1) || currentNbr == (previousNbr + 1)) {
                            containSequence = true;
                            break;
                        }
                    }
                    previousChar = c;
                }
                if (!containSequence) {
                    isWeak = false;
                }
            }
        }
        return isWeak;
    }

    /**
     * Apply a collection of validations on a Word 97-2003 (binary format) document file provided:
     * <ul>
     * <li>Real Microsoft Word 97-2003 document file.</li>
     * <li>No VBA Macro.<br></li>
     * <li>No embedded objects.</li>
     * </ul>
     *
     * @param wordFilePath Filename of the Word document file to check.
     * @return True only if the file pass all validations.
     * @see "https://poi.apache.org/components/"
     * @see "https://poi.apache.org/components/document/"
     * @see "https://poi.apache.org/components/poifs/how-to.html"
     * @see "https://poi.apache.org/components/poifs/embeded.html"
     * @see "https://poi.apache.org/"
     * @see "https://mvnrepository.com/artifact/org.apache.poi/poi"
     */
    public static boolean isWord972003DocumentSafe(String wordFilePath) {
        boolean isSafe = false;
        try {
            File wordFile = new File(wordFilePath);
            if (wordFile.exists() && wordFile.canRead() && wordFile.isFile()) {
                //Step 1: Try to load the file, if its fail then it imply that is not a valid Word 97-2003 format file
                try (POIFSFileSystem fs = new POIFSFileSystem(wordFile)) {
                    //Step 2: Check if the document contains VBA macros, in our case is not allowed
                    VBAMacroReader macroReader = new VBAMacroReader(fs);
                    Map<String, String> macros = macroReader.readMacros();
                    if (macros == null || macros.isEmpty()) {
                        //Step 3: Check if the document contains any embedded objects, in our case is not allowed
                        //From POI documentation:
                        //Word normally stores embedded files in subdirectories of the ObjectPool directory, itself a subdirectory of the filesystem root.
                        //Typically, these subdirectories and named starting with an underscore, followed by 10 numbers.
                        final List<String> embeddedObjectFound = new ArrayList<>();
                        DirectoryEntry root = fs.getRoot();
                        if (root.getEntryCount() > 0) {
                            root.iterator().forEachRemaining(entry -> {
                                if ("ObjectPool".equalsIgnoreCase(entry.getName()) && entry instanceof DirectoryEntry) {
                                    DirectoryEntry objPoolDirectory = (DirectoryEntry) entry;
                                    if (objPoolDirectory.getEntryCount() > 0) {
                                        objPoolDirectory.iterator().forEachRemaining(objPoolDirectoryEntry -> {
                                            if (objPoolDirectoryEntry instanceof DirectoryEntry) {
                                                DirectoryEntry objPoolDirectoryEntrySubDirectoryEntry = (DirectoryEntry) objPoolDirectoryEntry;
                                                if (objPoolDirectoryEntrySubDirectoryEntry.getEntryCount() > 0) {
                                                    objPoolDirectoryEntrySubDirectoryEntry.forEach(objPoolDirectoryEntrySubDirectoryEntryEntry -> {
                                                        if (objPoolDirectoryEntrySubDirectoryEntryEntry.isDocumentEntry()) {
                                                            embeddedObjectFound.add(objPoolDirectoryEntrySubDirectoryEntryEntry.getName());
                                                        }
                                                    });
                                                }
                                            }
                                        });
                                    }
                                }
                            });
                        }
                        isSafe = embeddedObjectFound.isEmpty();
                    }
                }
            }
        } catch (Exception e) {
            isSafe = false;
        }
        return isSafe;
    }

    /**
     * Ensure that an XML file does not contain any External Entity, DTD or XInclude instructions.
     *
     * @param xmlFilePath Filename of the XML file to check.
     * @return True only if the file pass all validations.
     * @see "https://portswigger.net/web-security/xxe"
     * @see "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#java"
     * @see "https://docs.oracle.com/en/java/javase/13/security/java-api-xml-processing-jaxp-security-guide.html#GUID-82F8C206-F2DF-4204-9544-F96155B1D258"
     * @see "https://www.w3.org/TR/xinclude-11/"
     * @see "https://en.wikipedia.org/wiki/XInclude"
     */
    public static boolean isXMLSafe(String xmlFilePath) {
        boolean isSafe = false;
        try {
            File xmlFile = new File(xmlFilePath);
            if (xmlFile.exists() && xmlFile.canRead() && xmlFile.isFile()) {
                //Step 1a: Verify that the XML file content does not contain any XInclude instructions
                boolean containXInclude = Files.readAllLines(xmlFile.toPath()).stream().anyMatch(line -> line.toLowerCase(Locale.ROOT).contains(":include "));
                if (!containXInclude) {
                    //Step 1b: Parse the XML file, if an exception occur than it's imply that the XML specified is not a valid ones
                    //Create an XML document builder throwing Exception if a DOCTYPE instruction is present
                    DocumentBuilderFactory dbfInstance = DocumentBuilderFactory.newInstance();
                    dbfInstance.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                    //Xerces 2 only
                    //dbfInstance.setFeature("http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl",true);
                    dbfInstance.setXIncludeAware(false);
                    DocumentBuilder builder = dbfInstance.newDocumentBuilder();
                    //Parse the document
                    Document doc = builder.parse(xmlFile);
                    isSafe = (doc != null && doc.getDocumentElement() != null);
                }
            }
        } catch (Exception e) {
            isSafe = false;
        }
        return isSafe;
    }


    /**
     * Extract all URL links from a PDF file provided.<br>
     * This can be used to apply validation on a PDF against contained links.
     *
     * @param pdfFilePath pdfFilePath Filename of the PDF file to process.
     * @return A List of URL objects that is empty if no links is found.
     * @throws Exception If any error occurs during the processing of the PDF file.
     * @see "https://www.gushiciku.cn/pl/21KQ"
     * @see "https://pdfbox.apache.org/"
     * @see "https://mvnrepository.com/artifact/org.apache.pdfbox/pdfbox"
     */
    public static List<URL> extractAllPDFLinks(String pdfFilePath) throws Exception {
        final List<URL> links = new ArrayList<>();
        File pdfFile = new File(pdfFilePath);
        try (PDDocument document = Loader.loadPDF(pdfFile)) {
            PDDocumentCatalog documentCatalog = document.getDocumentCatalog();
            AnnotationFilter actionURIAnnotationFilter = new AnnotationFilter() {
                @Override
                public boolean accept(PDAnnotation annotation) {
                    boolean keep = false;
                    if (annotation instanceof PDAnnotationLink) {
                        keep = (((PDAnnotationLink) annotation).getAction() instanceof PDActionURI);
                    }
                    return keep;
                }
            };
            documentCatalog.getPages().forEach(page -> {
                try {
                    page.getAnnotations(actionURIAnnotationFilter).forEach(annotation -> {
                        PDActionURI linkAnnotation = (PDActionURI) ((PDAnnotationLink) annotation).getAction();
                        try {
                            URL urlObj = new URL(linkAnnotation.getURI());
                            if (!links.contains(urlObj)) {
                                links.add(urlObj);
                            }
                        } catch (MalformedURLException e) {
                            throw new RuntimeException(e);
                        }
                    });
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
        return links;
    }

    /**
     * Apply a collection of validations on a PDF file provided:
     * <ul>
     * <li>Real PDF file.</li>
     * <li>No attachments.</li>
     * <li>No Javascript code.</li>
     * <li>No links using action of type URI/Launch/RemoteGoTo/ImportData.</li>
     * <li>No XFA forms in order to prevent exposure to XXE/SSRF like CVE-2025-54988.</li>
     * </ul>
     *
     * @param pdfFilePath Filename of the PDF file to check.
     * @return True only if the file pass all validations.
     * @see "https://stackoverflow.com/a/36161267"
     * @see "https://www.gushiciku.cn/pl/21KQ"
     * @see "https://github.com/jonaslejon/malicious-pdf"
     * @see "https://pdfbox.apache.org/"
     * @see "https://mvnrepository.com/artifact/org.apache.pdfbox/pdfbox"
     * @see "https://nvd.nist.gov/vuln/detail/CVE-2025-54988"
     * @see "https://github.com/mgthuramoemyint/POC-CVE-2025-54988"
     * @see "https://en.wikipedia.org/wiki/XFA"
     */
    public static boolean isPDFSafe(String pdfFilePath) {
        boolean isSafe = false;
        try {
            File pdfFile = new File(pdfFilePath);
            if (pdfFile.exists() && pdfFile.canRead() && pdfFile.isFile()) {
                //Step 1: Try to load the file, if its fail then it imply that is not a valid PDF file
                try (PDDocument document = Loader.loadPDF(pdfFile)) {
                    //Step 2: Check if the file contains attached files, in our case is not allowed
                    PDDocumentCatalog documentCatalog = document.getDocumentCatalog();
                    PDDocumentNameDictionary namesDictionary = new PDDocumentNameDictionary(documentCatalog);
                    if (namesDictionary.getEmbeddedFiles() == null) {
                        //Step 3: Check if the file contains any XFA forms
                        PDAcroForm acroForm = documentCatalog.getAcroForm();
                        boolean hasForm = (acroForm != null && acroForm.getXFA() != null);
                        if (!hasForm) {
                            //Step 4: Check if the file contains Javascript code, in our case is not allowed
                            if (namesDictionary.getJavaScript() == null) {
                                //Step 5: Check if the file contains links using action of type URI/Launch/RemoteGoTo/ImportData, in our case is not allowed
                                final List<Integer> notAllowedAnnotationCounterList = new ArrayList<>();
                                AnnotationFilter notAllowedAnnotationFilter = new AnnotationFilter() {
                                    @Override
                                    public boolean accept(PDAnnotation annotation) {
                                        boolean keep = false;
                                        if (annotation instanceof PDAnnotationLink) {
                                            PDAnnotationLink link = (PDAnnotationLink) annotation;
                                            PDAction action = link.getAction();
                                            if ((action instanceof PDActionURI) || (action instanceof PDActionLaunch) || (action instanceof PDActionRemoteGoTo) || (action instanceof PDActionImportData)) {
                                                keep = true;
                                            }
                                        }
                                        return keep;
                                    }
                                };
                                documentCatalog.getPages().forEach(page -> {
                                    try {
                                        notAllowedAnnotationCounterList.add(page.getAnnotations(notAllowedAnnotationFilter).size());
                                    } catch (IOException e) {
                                        throw new RuntimeException(e);
                                    }
                                });
                                if (notAllowedAnnotationCounterList.stream().reduce(0, Integer::sum) == 0) {
                                    isSafe = true;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            isSafe = false;
        }
        return isSafe;
    }

    /**
     * Remove as much as possible metadata from the provided PDF document object.
     *
     * @param document PDFBox PDF document object on which metadata must be removed.
     * @see "https://gist.github.com/righettod/d7e07443c43d393a39de741a0d920069"
     * @see "https://pdfbox.apache.org/"
     * @see "https://mvnrepository.com/artifact/org.apache.pdfbox/pdfbox"
     */
    public static void clearPDFMetadata(PDDocument document) {
        if (document != null) {
            PDDocumentInformation infoEmpty = new PDDocumentInformation();
            document.setDocumentInformation(infoEmpty);
            PDMetadata newMetadataEmpty = new PDMetadata(document);
            document.getDocumentCatalog().setMetadata(newMetadataEmpty);
        }
    }


    /**
     * Validate that the URL provided is really a relative URL.
     *
     * @param targetUrl URL to validate.
     * @return True only if the file pass all validations.
     * @see "https://portswigger.net/web-security/ssrf"
     * @see "https://stackoverflow.com/q/6785442"
     */
    public static boolean isRelativeURL(String targetUrl) {
        boolean isValid = false;
        //Reject any URL encoded content and URL starting with a double slash
        //Reject any URL contains credentials or fragment to prevent potential bypasses
        String work = targetUrl;
        if (!work.contains("%") && !work.contains("@") && !work.contains("#") && !work.startsWith("//")) {
            //Creation of a URL object must fail
            try {
                new URL(work);
                isValid = false;
            } catch (MalformedURLException mf) {
                //Last check to be sure (for prod usage compile the pattern one time)
                isValid = Pattern.compile("^/[a-z0-9]+", Pattern.CASE_INSENSITIVE).matcher(work).find();
            }
        }
        return isValid;
    }

    /**
     * Apply a collection of validations on a ZIP file provided:
     * <ul>
     * <li>Real ZIP file.</li>
     * <li>Contain less than a specified level of deepness.</li>
     * <li>Do not contain Zip-Slip entry path.</li>
     * </ul>
     *
     * @param zipFilePath       Filename of the ZIP file to check.
     * @param maxLevelDeepness  Threshold of deepness above which a ZIP archive will be rejected.
     * @param rejectArchiveFile Flag to specify if presence of any archive entry will cause the rejection of the ZIP file.
     * @return True only if the file pass all validations.
     * @see "https://rules.sonarsource.com/java/type/Security%20Hotspot/RSPEC-5042"
     * @see "https://security.snyk.io/research/zip-slip-vulnerability"
     * @see "https://en.wikipedia.org/wiki/Zip_bomb"
     * @see "https://github.com/ptoomey3/evilarc"
     * @see "https://github.com/abdulfatir/ZipBomb"
     * @see "https://www.baeldung.com/cs/zip-bomb"
     * @see "https://thesecurityvault.com/attacks-with-zip-files-and-mitigations/"
     * @see "https://wiki.sei.cmu.edu/confluence/display/java/IDS04-J.+Safely+extract+files+from+ZipInputStream"
     */
    public static boolean isZIPSafe(String zipFilePath, int maxLevelDeepness, boolean rejectArchiveFile) {
        List<String> archiveExtensions = Arrays.asList("zip", "tar", "7z", "gz", "jar", "phar", "bz2", "tgz");
        boolean isSafe = false;
        try {
            File zipFile = new File(zipFilePath);
            if (zipFile.exists() && zipFile.canRead() && zipFile.isFile() && maxLevelDeepness > 0) {
                //Step 1: Try to load the file, if its fail then it imply that is not a valid ZIP file
                try (ZipFile zipArch = new ZipFile(zipFile)) {
                    //Step 2: Parse entries
                    long deepness = 0;
                    ZipEntry zipEntry;
                    String entryExtension;
                    String zipEntryName;
                    boolean validationsFailed = false;
                    Enumeration<? extends ZipEntry> entries = zipArch.entries();
                    while (entries.hasMoreElements()) {
                        zipEntry = entries.nextElement();
                        zipEntryName = zipEntry.getName();
                        entryExtension = zipEntryName.substring(zipEntryName.lastIndexOf(".") + 1).toLowerCase(Locale.ROOT).trim();
                        //Step 2a: Check if the current entry is an archive file
                        if (rejectArchiveFile && archiveExtensions.contains(entryExtension)) {
                            validationsFailed = true;
                            break;
                        }
                        //Step 2b: Check that level of deepness is inferior to the threshold specified
                        if (zipEntryName.contains("/")) {
                            //Determine deepness by inspecting the entry name.
                            //Indeed, folder will be represented like this: folder/folder/folder/
                            //So we can count the number of "/" to identify the deepness of the entry
                            deepness = zipEntryName.chars().filter(ch -> ch == '/').count();
                            if (deepness > maxLevelDeepness) {
                                validationsFailed = true;
                                break;
                            }
                        }
                        //Step 2c: Check if any entries match pattern of zip slip payload
                        if (zipEntryName.contains("..\\") || zipEntryName.contains("../")) {
                            validationsFailed = true;
                            break;
                        }
                    }
                    if (!validationsFailed) {
                        isSafe = true;
                    }
                }
            }
        } catch (Exception e) {
            isSafe = false;
        }
        return isSafe;
    }

    /**
     * Identify the mime type of the content specified (array of bytes).<br>
     * Note that it cannot be fully trusted (see the tweet '1595824709186519041' referenced), so, additional validations are required.
     *
     * @param content The content as an array of bytes.
     * @return The mime type in lower case or null if it cannot be identified.
     * @see "https://twitter.com/righettod/status/1595824709186519041"
     * @see "https://tika.apache.org/"
     * @see "https://mvnrepository.com/artifact/org.apache.tika/tika-core"
     * @see "https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types"
     * @see "https://www.iana.org/assignments/media-types/media-types.xhtml"
     */
    public static String identifyMimeType(byte[] content) {
        String mimeType = null;
        if (content != null && content.length > 0) {
            Detector detector = new DefaultDetector(MimeTypes.getDefaultMimeTypes());
            Metadata metadata = new Metadata();
            try {
                try (TemporaryResources temporaryResources = new TemporaryResources(); TikaInputStream tikaInputStream = TikaInputStream.get(new ByteArrayInputStream(content), temporaryResources, metadata)) {
                    MediaType mt = detector.detect(tikaInputStream, metadata);
                    if (mt != null) {
                        mimeType = mt.toString().toLowerCase(Locale.ROOT);
                    }
                }
            } catch (IOException ioe) {
                mimeType = null;
            }
        }
        return mimeType;
    }

    /**
     * Apply a collection of validations on a string expected to be an public IP address:
     * <ul>
     * <li>Is a valid IP v4 or v6 address.</li>
     * <li>Is public from an Internet perspective.</li>
     * </ul>
     * <br>
     * <b>Note:</b> I often see missing such validation in the value read from HTTP request headers like "X-Forwarded-For" or "Forwarded".
     * <br><br>
     * <b>Note for IPv6:</b> I used documentation found so it is really experimental!
     *
     * @param ip String expected to be a valid IP address.
     * @return True only if the string pass all validations.
     * @see "https://commons.apache.org/proper/commons-validator/"
     * @see "https://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/routines/InetAddressValidator.html"
     * @see "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
     * @see "https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Orange_Tsai_Talk.pdf"
     * @see "https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf"
     * @see "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For"
     * @see "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded"
     * @see "https://ipcisco.com/lesson/ipv6-address/"
     * @see "https://www.juniper.net/documentation/us/en/software/junos/interfaces-security-devices/topics/topic-map/security-interface-ipv4-ipv6-protocol.html"
     * @see "https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetAddress.html#getByName(java.lang.String)"
     * @see "https://www.arin.net/reference/research/statistics/address_filters/"
     * @see "https://en.wikipedia.org/wiki/Multicast_address"
     * @see "https://stackoverflow.com/a/5619409"
     * @see "https://www.ripe.net/media/documents/ipv6-address-types.pdf"
     * @see "https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml"
     * @see "https://developer.android.com/reference/java/net/Inet6Address"
     * @see "https://en.wikipedia.org/wiki/Unique_local_address"
     */
    public static boolean isPublicIPAddress(String ip) {
        boolean isValid = false;
        try {
            //Quick validation on the string itself based on characters used to compose an IP v4/v6 address
            if (Pattern.matches("[0-9a-fA-F:.]+", ip)) {
                //If OK then use the dedicated InetAddressValidator from Apache Commons Validator
                if (InetAddressValidator.getInstance().isValid(ip)) {
                    //If OK then validate that is an public IP address
                    //From Javadoc for "InetAddress.getByName": If a literal IP address is supplied, only the validity of the address format is checked.
                    InetAddress addr = InetAddress.getByName(ip);
                    isValid = (!addr.isAnyLocalAddress() && !addr.isLinkLocalAddress() && !addr.isLoopbackAddress() && !addr.isMulticastAddress() && !addr.isSiteLocalAddress());
                    //If OK and the IP is an V6 one then make additional validation because the built-in Java API will let pass some V6 IP
                    //For the prefix map, the start of the key indicates if the value is a regex or a string
                    if (isValid && (addr instanceof Inet6Address)) {
                        Map<String, String> prefixes = new HashMap<>();
                        prefixes.put("REGEX_LOOPBACK", "^(0|:)+1$");
                        prefixes.put("REGEX_UNIQUE-LOCAL-ADDRESSES", "^f(c|d)[a-f0-9]{2}:.*$");
                        prefixes.put("STRING_LINK-LOCAL-ADDRESSES", "fe80:");
                        prefixes.put("REGEX_TEREDO", "^2001:[0]*:.*$");
                        prefixes.put("REGEX_BENCHMARKING", "^2001:[0]*2:.*$");
                        prefixes.put("REGEX_ORCHID", "^2001:[0]*10:.*$");
                        prefixes.put("STRING_DOCUMENTATION", "2001:db8:");
                        prefixes.put("STRING_GLOBAL-UNICAST", "2000:");
                        prefixes.put("REGEX_MULTICAST", "^ff[0-9]{2}:.*$");
                        final List<Boolean> results = new ArrayList<>();
                        final String ipLower = ip.trim().toLowerCase(Locale.ROOT);
                        prefixes.forEach((addressType, expr) -> {
                            String exprLower = expr.trim().toLowerCase();
                            if (addressType.startsWith("STRING_")) {
                                results.add(ipLower.startsWith(exprLower));
                            } else {
                                results.add(Pattern.matches(exprLower, ipLower));
                            }
                        });
                        isValid = ((results.size() == prefixes.size()) && !results.contains(Boolean.TRUE));
                    }
                }
            }
        } catch (Exception e) {
            isValid = false;
        }
        return isValid;
    }

    /**
     * Compute a SHA256 hash from an input composed of a collection of strings.<br><br>
     * This method take care to build the source string in a way to prevent this source string to be prone to abuse targeting the different parts composing it.<br><br>
     * <p>
     * Example of possible abuse without precautions applied during the hash calculation logic:<br>
     * Hash of <code>SHA256("Hello", "My", "World!!!")</code> will be equals to the hash of <code>SHA256("Hell", "oMyW", "orld!!!")</code>.<br>
     * </p>
     * This method ensure that both hash above will be different.<br><br>
     *
     * <b>Note:</b> The character <code>|</code> is used, as separator, of every parts so a part is not allowed to contains this character.
     *
     * @param parts Ordered list of strings to use to build the input string for which the hash must be computed on. No null value is accepted on object composing the collection.
     * @return The hash, as an array of bytes, to allow caller to convert it to the final representation wanted (HEX, Base64, etc.). If the collection passed is null or empty then the method return null.
     * @throws Exception If any exception occurs
     * @see "https://github.com/righettod/code-snippets-security-utils/issues/16"
     * @see "https://pentesterlab.com/badges/codereview"
     * @see "https://blog.trailofbits.com/2024/08/21/yolo-is-not-a-valid-hash-construction/"
     * @see "https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash"
     */
    public static byte[] computeHashNoProneToAbuseOnParts(List<String> parts) throws Exception {
        byte[] hash = null;
        String separator = "|";
        if (parts != null && !parts.isEmpty()) {
            //Ensure that not part is null
            if (parts.stream().anyMatch(Objects::isNull)) {
                throw new IllegalArgumentException("No part must be null!");
            }
            //Ensure that the separator is absent from every part
            if (parts.stream().anyMatch(part -> part.contains(separator))) {
                throw new IllegalArgumentException(String.format("The character '%s', used as parts separator, must be absent from every parts!", separator));
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final StringBuilder buffer = new StringBuilder(separator);
            parts.forEach(p -> {
                buffer.append(p).append(separator);
            });
            hash = digest.digest(buffer.toString().getBytes(StandardCharsets.UTF_8));
        }
        return hash;
    }

    /**
     * Ensure that an XML file only uses DTD/XSD references (called System Identifier) present in the allowed list provided.<br><br>
     * The code is based on the validation implemented into the OpenJDK 21, by the class <b><a href="https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.prefs/share/classes/java/util/prefs/XmlSupport.java">java.util.prefs.XmlSupport</a></b>, in the method <b><a href="https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.prefs/share/classes/java/util/prefs/XmlSupport.java#L240">loadPrefsDoc()</a></b>.<br><br>
     * The method also ensure that no Public Identifier is used to prevent potential bypasses of the validations.
     *
     * @param xmlFilePath              Filename of the XML file to check.
     * @param allowedSystemIdentifiers List of URL allowed for System Identifier specified for any XSD/DTD references.
     * @return True only if the file pass all validations.
     * @see "https://www.w3schools.com/xml/prop_documenttype_systemid.asp"
     * @see "https://www.ibm.com/docs/en/integration-bus/9.0.0?topic=doctypedecl-xml-systemid"
     * @see "https://www.liquid-technologies.com/Reference/Glossary/XML_DocType.html"
     * @see "https://www.xml.com/pub/98/08/xmlqna0.html"
     * @see "https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.prefs/share/classes/java/util/prefs/XmlSupport.java#L397"
     * @see "https://en.wikipedia.org/wiki/Formal_Public_Identifier"
     */
    public static boolean isXMLOnlyUseAllowedXSDorDTD(String xmlFilePath, final List<String> allowedSystemIdentifiers) {
        boolean isSafe = false;
        final String errorTemplate = "Non allowed %s ID detected!";
        final String emptyFakeDTD = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!ELEMENT dummy EMPTY>";
        final String emptyFakeXSD = "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"> <xs:element name=\"dummy\"/></xs:schema>";

        if (allowedSystemIdentifiers == null || allowedSystemIdentifiers.isEmpty()) {
            throw new IllegalArgumentException("At least one SID must be specified!");
        }
        File xmlFile = new File(xmlFilePath);
        if (xmlFile.exists() && xmlFile.canRead() && xmlFile.isFile()) {
            try {
                EntityResolver resolverValidator = (publicId, systemId) -> {
                    if (publicId != null) {
                        throw new SAXException(String.format(errorTemplate, "PUBLIC"));
                    }
                    if (!allowedSystemIdentifiers.contains(systemId)) {
                        throw new SAXException(String.format(errorTemplate, "SYSTEM"));
                    }
                    //If it is OK then return a empty DTD/XSD
                    return new InputSource(new StringReader(systemId.toLowerCase().endsWith(".dtd") ? emptyFakeDTD : emptyFakeXSD));
                };
                DocumentBuilderFactory dbfInstance = DocumentBuilderFactory.newInstance();
                dbfInstance.setIgnoringElementContentWhitespace(true);
                dbfInstance.setXIncludeAware(false);
                dbfInstance.setValidating(false);
                dbfInstance.setCoalescing(true);
                dbfInstance.setIgnoringComments(false);
                DocumentBuilder builder = dbfInstance.newDocumentBuilder();
                builder.setEntityResolver(resolverValidator);
                Document doc = builder.parse(xmlFile);
                isSafe = (doc != null);
            } catch (SAXException | IOException | ParserConfigurationException e) {
                isSafe = false;
            }
        }

        return isSafe;
    }

    /**
     * Apply a collection of validations on a EXCEL CSV file provided (file was expected to be opened in Microsoft EXCEL):
     * <ul>
     * <li>Real CSV file.</li>
     * <li>Do not contains any payload related to a CSV injections.</li>
     * </ul>
     * Ensure that, if Apache Commons CSV does not find any record then, the file will be considered as NOT safe (prevent potential bypasses).<br><br>
     * <b>Note:</b> Record delimiter used is the <code>,</code> (comma) character. See the Apache Commons CSV reference provided for EXCEL.<br>
     *
     * @param csvFilePath Filename of the CSV file to check.
     * @return True only if the file pass all validations.
     * @see "https://commons.apache.org/proper/commons-csv/"
     * @see "https://commons.apache.org/proper/commons-csv/apidocs/org/apache/commons/csv/CSVFormat.html#EXCEL"
     * @see "https://www.we45.com/post/your-excel-sheets-are-not-safe-heres-how-to-beat-csv-injection"
     * @see "https://www.whiteoaksecurity.com/blog/2020-4-23-csv-injection-whats-the-risk/"
     * @see "https://book.hacktricks.xyz/pentesting-web/formula-csv-doc-latex-ghostscript-injection"
     * @see "https://owasp.org/www-community/attacks/CSV_Injection"
     * @see "https://payatu.com/blog/csv-injection-basic-to-exploit/"
     * @see "https://cwe.mitre.org/data/definitions/1236.html"
     */
    public static boolean isExcelCSVSafe(String csvFilePath) {
        boolean isSafe;
        final AtomicInteger recordCount = new AtomicInteger();
        final List<Character> payloadDetectionCharacters = List.of('=', '+', '@', '-', '\r', '\t');

        try {
            final List<String> payloadsIdentified = new ArrayList<>();
            try (Reader in = new FileReader(csvFilePath)) {
                Iterable<CSVRecord> records = CSVFormat.EXCEL.parse(in);
                records.forEach(record -> {
                    record.forEach(recordValue -> {
                        if (recordValue != null && !recordValue.trim().isEmpty() && payloadDetectionCharacters.contains(recordValue.trim().charAt(0))) {
                            payloadsIdentified.add(recordValue);
                        }
                        recordCount.getAndIncrement();
                    });
                });
            }
            isSafe = (payloadsIdentified.isEmpty() && recordCount.get() > 0);
        } catch (Exception e) {
            isSafe = false;
        }

        return isSafe;
    }

    /**
     * Provide a way to add an integrity marker (<a href="https://en.wikipedia.org/wiki/HMAC">HMAC</a>) to a serialized object serialized using the <a href="https://www.baeldung.com/java-serialization">java native system</a> (binary).<br>
     * The goal is to provide <b>a temporary workaround</b> to try to prevent deserialization attacks and give time to move to a text-based serialization approach.
     *
     * @param processingModeType Define the mode of processing i.e. protect or validate. ({@link ProcessingModeType})
     * @param input              When the processing mode is "protect" than the expected input (string) is a java serialized object encoded in Base64 otherwise (processing mode is "validate") expected input is the output of this method when the "protect" mode was used.
     * @param secret             Secret to use to compute the SHA256 HMAC.
     * @return A map with the following keys: <ul><li><b>PROCESSING_MODE</b>: Processing mode used to compute the result.</li><li><b>STATUS</b>: A boolean indicating if the processing was successful or not.</li><li><b>RESULT</b>: Always contains a string representing the protected serialized object in the format <code>[SERIALIZED_OBJECT_BASE64_ENCODED]:[SERIALIZED_OBJECT_HMAC_BASE64_ENCODED]</code>.</li></ul>
     * @throws Exception If any exception occurs.
     * @see "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
     * @see "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization"
     * @see "https://portswigger.net/web-security/deserialization"
     * @see "https://www.baeldung.com/java-serialization-approaches"
     * @see "https://www.baeldung.com/java-serialization"
     * @see "https://cryptobook.nakov.com/mac-and-key-derivation/hmac-and-key-derivation"
     * @see "https://en.wikipedia.org/wiki/HMAC"
     * @see "https://smattme.com/posts/how-to-generate-hmac-signature-in-java/"
     */
    public static Map<String, Object> ensureSerializedObjectIntegrity(ProcessingModeType processingModeType, String input, byte[] secret) throws Exception {
        Map<String, Object> results;
        String resultFormatTemplate = "%s:%s";
        //Verify input provided to be consistent
        if (processingModeType == null) {
            throw new IllegalArgumentException("The processing mode is mandatory!");
        }
        if (input == null || input.trim().isEmpty()) {
            throw new IllegalArgumentException("Input data is mandatory!");
        }
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("The HMAC secret is mandatory!");
        }
        if (processingModeType.equals(ProcessingModeType.VALIDATE) && input.split(":").length != 2) {
            throw new IllegalArgumentException("Input data provided is invalid for the processing mode specified!");
        }
        //Processing
        Base64.Decoder b64Decoder = Base64.getDecoder();
        Base64.Encoder b64Encoder = Base64.getEncoder();
        String hmacAlgorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(hmacAlgorithm);
        SecretKeySpec key = new SecretKeySpec(secret, hmacAlgorithm);
        mac.init(key);
        results = new HashMap<>();
        results.put("PROCESSING_MODE", processingModeType.toString());
        switch (processingModeType) {
            case PROTECT -> {
                byte[] objectBytes = b64Decoder.decode(input);
                byte[] hmac = mac.doFinal(objectBytes);
                String encodedHmac = b64Encoder.encodeToString(hmac);
                results.put("STATUS", Boolean.TRUE);
                results.put("RESULT", String.format(resultFormatTemplate, input, encodedHmac));
            }
            case VALIDATE -> {
                String[] parts = input.split(":");
                byte[] objectBytes = b64Decoder.decode(parts[0].trim());
                byte[] hmacProvided = b64Decoder.decode(parts[1].trim());
                byte[] hmacComputed = mac.doFinal(objectBytes);
                String encodedHmacComputed = b64Encoder.encodeToString(hmacComputed);
                Boolean hmacIsValid = Arrays.equals(hmacProvided, hmacComputed);
                results.put("STATUS", hmacIsValid);
                results.put("RESULT", String.format(resultFormatTemplate, parts[0].trim(), encodedHmacComputed));
            }
            default -> throw new IllegalArgumentException("Not supported processing mode!");
        }
        return results;
    }

    /**
     * Apply a collection of validations on a JSON string provided:
     * <ul>
     * <li>Real JSON structure.</li>
     * <li>Contain less than a specified number of deepness for nested objects or arrays.</li>
     * <li>Contain less than a specified number of items in any arrays.</li>
     * </ul>
     * <br>
     * <b>Note:</b> I decided to use a parsing approach using only string processing to prevent any StackOverFlow or OutOfMemory error that can be abused.<br><br>
     * I used the following assumption:
     * <ul>
     *      <li>The character <code>{</code> identify the beginning of an object.</li>
     *      <li>The character <code>}</code> identify the end of an object.</li>
     *      <li>The character <code>[</code> identify the beginning of an array.</li>
     *      <li>The character <code>]</code> identify the end of an array.</li>
     *      <li>The character <code>"</code> identify the delimiter of a string.</li>
     *      <li>The character sequence <code>\"</code> identify the escaping of an double quote.</li>
     * </ul>
     *
     * @param json                  String containing the JSON data to validate.
     * @param maxItemsByArraysCount Maximum number of items allowed in an array.
     * @param maxDeepnessAllowed    Maximum number nested objects or arrays allowed.
     * @return True only if the string pass all validations.
     * @see "https://javaee.github.io/jsonp/"
     * @see "https://community.f5.com/discussions/technicalforum/disable-buffer-overflow-in-json-parameters/124306"
     * @see "https://github.com/InductiveComputerScience/pbJson/issues/2"
     */
    public static boolean isJSONSafe(String json, int maxItemsByArraysCount, int maxDeepnessAllowed) {
        boolean isSafe = false;

        try {
            //Step 1: Analyse the JSON string
            int currentDeepness = 0;
            int currentArrayItemsCount = 0;
            int maxDeepnessReached = 0;
            int maxArrayItemsCountReached = 0;
            boolean currentlyInArray = false;
            boolean currentlyInString = false;
            int currentNestedArrayLevel = 0;
            String jsonEscapedDoubleQuote = "\\\"";//Escaped double quote must not be considered as a string delimiter
            String work = json.replace(jsonEscapedDoubleQuote, "'");
            for (char c : work.toCharArray()) {
                switch (c) {
                    case '{': {
                        if (!currentlyInString) {
                            currentDeepness++;
                        }
                        break;
                    }
                    case '}': {
                        if (!currentlyInString) {
                            currentDeepness--;
                        }
                        break;
                    }
                    case '[': {
                        if (!currentlyInString) {
                            currentDeepness++;
                            if (currentlyInArray) {
                                currentNestedArrayLevel++;
                            }
                            currentlyInArray = true;
                        }
                        break;
                    }
                    case ']': {
                        if (!currentlyInString) {
                            currentDeepness--;
                            currentArrayItemsCount = 0;
                            if (currentNestedArrayLevel > 0) {
                                currentNestedArrayLevel--;
                            }
                            if (currentNestedArrayLevel == 0) {
                                currentlyInArray = false;
                            }
                        }
                        break;
                    }
                    case '"': {
                        currentlyInString = !currentlyInString;
                        break;
                    }
                    case ',': {
                        if (!currentlyInString && currentlyInArray) {
                            currentArrayItemsCount++;
                        }
                        break;
                    }
                }
                if (currentDeepness > maxDeepnessReached) {
                    maxDeepnessReached = currentDeepness;
                }
                if (currentArrayItemsCount > maxArrayItemsCountReached) {
                    maxArrayItemsCountReached = currentArrayItemsCount;
                }
            }
            //Step 2: Apply validation against the value specified as limits
            isSafe = ((maxItemsByArraysCount > maxArrayItemsCountReached) && (maxDeepnessAllowed > maxDeepnessReached));

            //Step 3: If the content is safe then ensure that it is valid JSON structure using the "Java API for JSON Processing" (JSR 374) parser reference implementation.
            if (isSafe) {
                JsonReader reader = Json.createReader(new StringReader(json));
                isSafe = (reader.read() != null);
            }

        } catch (Exception e) {
            isSafe = false;
        }
        return isSafe;
    }

    /**
     * Apply a collection of validations on a image file provided:
     * <ul>
     * <li>Real image file.</li>
     * <li>Its mime type is into the list of allowed mime types.</li>
     * <li>Its metadata fields do not contains any characters related to a malicious payloads.</li>
     * </ul>
     * <br>
     * <b>Important note:</b> This implementation is prone to bypass using the "<b>raw insertion</b>" method documented in the <a href="https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there">blog post</a> from the Synacktiv team.
     * To handle such case, it is recommended to resize the image to remove any non image-related content, see <a href="https://github.com/righettod/document-upload-protection/blob/master/src/main/java/eu/righettod/poc/sanitizer/ImageDocumentSanitizerImpl.java#L54">here</a> for an example.<br>
     *
     * @param imageFilePath         Filename of the image file to check.
     * @param imageAllowedMimeTypes List of image mime types allowed.
     * @return True only if the file pass all validations.
     * @see "https://commons.apache.org/proper/commons-imaging/"
     * @see "https://commons.apache.org/proper/commons-imaging/formatsupport.html"
     * @see "https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types"
     * @see "https://www.iana.org/assignments/media-types/media-types.xhtml#image"
     * @see "https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there"
     * @see "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
     * @see "https://github.com/righettod/document-upload-protection/blob/master/src/main/java/eu/righettod/poc/sanitizer/ImageDocumentSanitizerImpl.java"
     * @see "https://exiftool.org/examples.html"
     * @see "https://en.wikipedia.org/wiki/List_of_file_signatures"
     * @see "https://hexed.it/"
     * @see "https://github.com/sighook/pixload"
     */
    public static boolean isImageSafe(String imageFilePath, List<String> imageAllowedMimeTypes) {
        boolean isSafe = false;
        Pattern payloadDetectionRegex = Pattern.compile("[<>${}`]+", Pattern.CASE_INSENSITIVE);
        try {
            File imgFile = new File(imageFilePath);
            if (imgFile.exists() && imgFile.canRead() && imgFile.isFile() && !imageAllowedMimeTypes.isEmpty()) {
                final byte[] imgBytes = Files.readAllBytes(imgFile.toPath());
                //Step 1: Check the mime type of the file against the allowed ones
                ImageInfo imgInfo = Imaging.getImageInfo(imgBytes);
                if (imageAllowedMimeTypes.contains(imgInfo.getMimeType())) {
                    //Step 2: Load the image into an object using the Image API
                    BufferedImage imgObject = Imaging.getBufferedImage(imgBytes);
                    if (imgObject != null && imgObject.getWidth() > 0 && imgObject.getHeight() > 0) {
                        //Step 3: Check the metadata if the image format support it - Highly experimental
                        List<String> metadataWithPayloads = new ArrayList<>();
                        final ImageMetadata imgMetadata = Imaging.getMetadata(imgBytes);
                        if (imgMetadata != null) {
                            imgMetadata.getItems().forEach(item -> {
                                String metadata = item.toString();
                                if (payloadDetectionRegex.matcher(metadata).find()) {
                                    metadataWithPayloads.add(metadata);
                                }
                            });
                        }
                        isSafe = metadataWithPayloads.isEmpty();
                    }
                }
            }
        } catch (Exception e) {
            isSafe = false;
        }
        return isSafe;
    }

    /**
     * Rewrite the input file to remove any embedded files that is not embedded using a methods supported by the official format of the file.<br>
     * Example: a file can be embedded by adding it to the end of the source file, see the reference provided for details.
     *
     * @param inputFilePath Filename of the file to clean up.
     * @param inputFileType Type of the file provided.
     * @return A array of bytes with the cleaned file.
     * @throws IllegalArgumentException If an invalid parameter is passed
     * @throws Exception                If any technical error during the cleaning processing
     * @see "https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there"
     * @see "https://github.com/righettod/toolbox-pentest-web/tree/master/misc"
     * @see "https://github.com/righettod/toolbox-pentest-web?tab=readme-ov-file#misc"
     * @see "https://stackoverflow.com/a/13605411"
     */
    public static byte[] sanitizeFile(String inputFilePath, InputFileType inputFileType) throws Exception {
        ByteArrayOutputStream sanitizedContent = new ByteArrayOutputStream();
        File inputFile = new File(inputFilePath);
        if (!inputFile.exists() || !inputFile.canRead() || !inputFile.isFile()) {
            throw new IllegalArgumentException("Cannot read the content of the input file!");
        }
        switch (inputFileType) {
            case PDF -> {
                try (PDDocument document = Loader.loadPDF(inputFile)) {
                    document.save(sanitizedContent);
                }
            }
            case IMAGE -> {
                // Load the original image
                BufferedImage originalImage = ImageIO.read(inputFile);
                String originalFormat = identifyMimeType(Files.readAllBytes(inputFile.toPath())).split("/")[1].trim();
                // Check that image has been successfully loaded
                if (originalImage == null) {
                    throw new IOException("Cannot load the original image !");
                }
                // Get current Width and Height of the image
                int originalWidth = originalImage.getWidth(null);
                int originalHeight = originalImage.getHeight(null);
                // Resize the image by removing 1px on Width and Height
                Image resizedImage = originalImage.getScaledInstance(originalWidth - 1, originalHeight - 1, Image.SCALE_SMOOTH);
                // Resize the resized image by adding 1px on Width and Height - In fact set image to is initial size
                Image initialSizedImage = resizedImage.getScaledInstance(originalWidth, originalHeight, Image.SCALE_SMOOTH);
                // Save image to a bytes buffer
                int bufferedImageType = BufferedImage.TYPE_INT_ARGB;//By default use a format supporting transparency
                if ("jpeg".equalsIgnoreCase(originalFormat) || "bmp".equalsIgnoreCase(originalFormat)) {
                    bufferedImageType = BufferedImage.TYPE_INT_RGB;
                }
                BufferedImage sanitizedImage = new BufferedImage(initialSizedImage.getWidth(null), initialSizedImage.getHeight(null), bufferedImageType);
                Graphics2D drawer = sanitizedImage.createGraphics();
                drawer.drawImage(initialSizedImage, 0, 0, null);
                drawer.dispose();
                ImageIO.write(sanitizedImage, originalFormat, sanitizedContent);
            }
            default -> throw new IllegalArgumentException("Type of file not supported !");
        }
        if (sanitizedContent.size() == 0) {
            throw new IOException("An error occur during the rewrite operation!");
        }
        return sanitizedContent.toByteArray();
    }

    /**
     * Apply a collection of validations on a string expected to be an email address:
     * <ul>
     * <li>Is a valid email address, from a parser perspective, following RFCs on email addresses.</li>
     * <li>Is not using "Encoded-word" format.</li>
     * <li>Is not using comment format.</li>
     * <li>Is not using "Punycode" format.</li>
     * <li>Is not using UUCP style addresses.</li>
     * <li>Is not using address literals.</li>
     * <li>Is not using source routes.</li>
     * <li>Is not using the "percent hack".</li>
     * </ul><br>
     * This is based on the research work from <a href="https://portswigger.net/research/gareth-heyes">Gareth Heyes</a> added in references (Portswigger).<br><br>
     *
     * <b>Note:</b> The notion of valid, here, is to take from a secure usage of the data perspective.
     *
     * @param addr String expected to be a valid email address.
     * @return True only if the string pass all validations.
     * @see "https://commons.apache.org/proper/commons-validator/"
     * @see "https://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/routines/EmailValidator.html"
     * @see "https://datatracker.ietf.org/doc/html/rfc2047#section-2"
     * @see "https://portswigger.net/research/splitting-the-email-atom"
     * @see "https://www.jochentopf.com/email/address.html"
     * @see "https://en.wikipedia.org/wiki/Email_address"
     */
    public static boolean isEmailAddress(String addr) {
        boolean isValid = false;
        String work = addr.toLowerCase(Locale.ROOT);
        Pattern encodedWordRegex = Pattern.compile("[=?]+", Pattern.CASE_INSENSITIVE);
        Pattern forbiddenCharacterRegex = Pattern.compile("[():!%\\[\\],;]+", Pattern.CASE_INSENSITIVE);
        try {
            //Start with the use of the dedicated EmailValidator from Apache Commons Validator
            if (EmailValidator.getInstance(true, true).isValid(work)) {
                //If OK then validate it does not contains "Encoded-word" patterns using an aggressive approach
                if (!encodedWordRegex.matcher(work).find()) {
                    //If OK then validate it does not contains punycode
                    if (!work.contains("xn--")) {
                        //If OK then validate it does not use:
                        // UUCP style addresses,
                        // Comment format,
                        // Address literals,
                        // Source routes,
                        // The percent hack.
                        if (!forbiddenCharacterRegex.matcher(work).find()) {
                            isValid = true;
                        }
                    }
                }
            }
        } catch (Exception e) {
            isValid = false;
        }
        return isValid;
    }

    /**
     * The <a href="https://www.stet.eu/en/psd2/">PSD2 STET</a> specification require to use <a href="https://datatracker.ietf.org/doc/draft-cavage-http-signatures/">HTTP Signature</a>.
     * <br>
     * Section <b>3.5.1.2</b> of the document <a href="https://www.stet.eu/assets/files/PSD2/1-6-3/api-dsp2-stet-v1.6.3.1-part-1-framework.pdf">Documentation Framework</a> version <b>1.6.3</b>.
     * <br>
     * The problem is that, by design, the HTTP Signature specification is prone to blind SSRF.
     * <br>
     * URL example taken from the STET specification: <code>https://path.to/myQsealCertificate_714f8154ec259ac40b8a9786c9908488b2582b68b17e865fede4636d726b709f</code>.
     * <br>
     * The objective of this code is to try to decrease the "exploitability/interest" of this SSRF for an attacker.
     *
     * @param certificateUrl Url pointing to a Qualified Certificate (QSealC) encoded in PEM format and respecting the ETSI/TS119495 technical Specification .
     * @return TRUE only if the url point to a Qualified Certificate in PEM format.
     * @see "https://www.stet.eu/en/psd2/"
     * @see "https://www.stet.eu/assets/files/PSD2/1-6-3/api-dsp2-stet-v1.6.3.1-part-1-framework.pdf"
     * @see "https://datatracker.ietf.org/doc/draft-cavage-http-signatures/"
     * @see "https://datatracker.ietf.org/doc/rfc9421/"
     * @see "https://openjdk.org/groups/net/httpclient/intro.html"
     * @see "https://docs.oracle.com/en/java/javase/21/docs/api/java.net.http/java/net/http/package-summary.html"
     * @see "https://portswigger.net/web-security/ssrf"
     * @see "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
     */
    public static boolean isPSD2StetSafeCertificateURL(String certificateUrl) {
        boolean isValid = false;
        long connectionTimeoutInSeconds = 10;
        String userAgent = "PSD2-STET-HTTPSignature-CertificateRequest";
        try {
            //1. Ensure that the URL end with the SHA-256 fingerprint encoded in HEX of the certificate like requested by STET
            if (certificateUrl != null && certificateUrl.lastIndexOf("_") != -1) {
                String digestPart = certificateUrl.substring(certificateUrl.lastIndexOf("_") + 1);
                if (Pattern.matches("^[0-9a-f]{64}$", digestPart)) {
                    //2. Ensure that the URL is a valid url by creating a instance of the class URI
                    URI uri = URI.create(certificateUrl);
                    //3. Require usage of HTTPS and reject any url containing query parameters
                    if ("https".equalsIgnoreCase(uri.getScheme()) && uri.getQuery() == null) {
                        //4. Perform a HTTP HEAD request in order to get the content type of the remote resource
                        //and limit the interest to use the SSRF because to pass the check the url need to:
                        //- Do not having any query parameters.
                        //- Use HTTPS protocol.
                        //- End with a string having the format "_[0-9a-f]{64}".
                        //- Trigger the malicious action that the attacker want but with a HTTP HEAD without any redirect and parameters.
                        HttpResponse<String> response;
                        try (HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()) {
                            HttpRequest request = HttpRequest.newBuilder().uri(uri).timeout(Duration.ofSeconds(connectionTimeoutInSeconds)).method("HEAD", HttpRequest.BodyPublishers.noBody()).header("User-Agent", userAgent)//To provide an hint to the target about the initiator of the request
                                    .header("Cache-Control", "no-store, max-age=0")//To prevent caching issues or abuses
                                    .build();
                            response = client.send(request, HttpResponse.BodyHandlers.ofString());
                            if (response.statusCode() == 200) {
                                //5. Ensure that the response content type is "text/plain"
                                Optional<String> contentType = response.headers().firstValue("Content-Type");
                                isValid = (contentType.isPresent() && contentType.get().trim().toLowerCase(Locale.ENGLISH).startsWith("text/plain"));
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            isValid = false;
        }
        return isValid;
    }

    /**
     * Perform sequential URL decoding operations against a URL encoded data until the data is not URL encoded anymore or if the specified threshold is reached.
     *
     * @param encodedData            URL encoded data.
     * @param decodingRoundThreshold Threshold above which decoding will fail.
     * @return The decoded data.
     * @throws SecurityException If the threshold is reached.
     * @see "https://en.wikipedia.org/wiki/Percent-encoding"
     * @see "https://owasp.org/www-community/Double_Encoding"
     * @see "https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings"
     * @see "https://capec.mitre.org/data/definitions/120.html"
     */
    public static String applyURLDecoding(String encodedData, int decodingRoundThreshold) throws SecurityException {
        if (decodingRoundThreshold < 1) {
            throw new IllegalArgumentException("Threshold must be a positive number !");
        }
        if (encodedData == null) {
            throw new IllegalArgumentException("Data provided must not be null !");
        }
        Charset charset = StandardCharsets.UTF_8;
        int currentDecodingRound = 0;
        boolean isFinished = false;
        String currentRoundData = encodedData;
        String previousRoundData = encodedData;
        while (!isFinished) {
            if (currentDecodingRound > decodingRoundThreshold) {
                throw new SecurityException(String.format("Decoding round threshold of %s reached!", decodingRoundThreshold));
            }
            currentRoundData = URLDecoder.decode(currentRoundData, charset);
            isFinished = currentRoundData.equals(previousRoundData);
            previousRoundData = currentRoundData;
            currentDecodingRound++;
        }
        return currentRoundData;
    }

    /**
     * Apply a collection of validations on a string expected to be an system file/folder path:
     * <ul>
     * <li>Does not contains path traversal payload.</li>
     * <li>The canonical path is equals to the absolute path.</li>
     * </ul><br>
     *
     * @param path String expected to be a valid system file/folder path.
     * @return True only if the string pass all validations.
     * @see "https://portswigger.net/web-security/file-path-traversal"
     * @see "https://learn.snyk.io/lesson/directory-traversal/"
     * @see "https://capec.mitre.org/data/definitions/126.html"
     * @see "https://owasp.org/www-community/attacks/Path_Traversal"
     */
    public static boolean isPathSafe(String path) {
        boolean isSafe = false;
        int decodingRoundThreshold = 3;
        try {
            if (path != null && !path.isEmpty()) {
                //URL decode the path if case of data coming from a web context
                String decodedPath = applyURLDecoding(path, decodingRoundThreshold);
                //Ensure that no path traversal expression is present
                if (!decodedPath.contains("..")) {
                    File f = new File(decodedPath);
                    String canonicalPath = f.getCanonicalPath();
                    String absolutePath = f.getAbsolutePath();
                    isSafe = canonicalPath.equals(absolutePath);
                }
            }
        } catch (Exception e) {
            isSafe = false;
        }
        return isSafe;
    }

    /**
     * Identify if an XML contains any XML comments or have any XSL processing instructions.<br>
     * Stream reader based parsing is used to support large XML tree.
     *
     * @param xmlFilePath Filename of the XML file to check.
     * @return True only if XML comments or XSL processing instructions are identified.
     * @see "https://www.tutorialspoint.com/xml/xml_processing.htm"
     * @see "https://docs.oracle.com/en/java/javase/21/docs/api/java.xml/javax/xml/stream/XMLInputFactory.html"
     * @see "https://portswigger.net/kb/issues/00400700_xml-entity-expansion"
     * @see "https://www.w3.org/Style/styling-XML.en.html"
     */
    public static boolean isXMLHaveCommentsOrXSLProcessingInstructions(String xmlFilePath) {
        boolean itemsDetected = false;
        try {
            //Ensure that the parser will not be prone XML external entity (XXE) injection or XML entity expansion (XEE) attacks
            XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
            xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            xmlInputFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            xmlInputFactory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false);
            xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);

            //Parse file
            try (FileInputStream fis = new FileInputStream(xmlFilePath)) {
                XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(fis);
                int eventType;
                while (reader.hasNext() && !itemsDetected) {
                    eventType = reader.next();
                    if (eventType == XMLEvent.COMMENT) {
                        itemsDetected = true;
                    } else if (eventType == XMLEvent.PROCESSING_INSTRUCTION && "xml-stylesheet".equalsIgnoreCase(reader.getPITarget())) {
                        itemsDetected = true;
                    }
                }
            }
        } catch (Exception e) {
            //In case of error then assume that the check failed
            itemsDetected = true;
        }
        return itemsDetected;
    }


    /**
     * Perform a set of additional validations against a JWT token:
     * <ul>
     *     <li>Do not use the <b>NONE</b> signature algorithm.</li>
     *     <li>Have a <a href="https://www.iana.org/assignments/jwt/jwt.xhtml">EXP claim</a> defined.</li>
     *     <li>The token identifier (<a href="https://www.iana.org/assignments/jwt/jwt.xhtml">JTI claim</a>) is NOT part of the list of revoked token.</li>
     *     <li>Match the expected type of token: ACCESS or ID or REFRESH.</li>
     * </ul>
     *
     * @param token               JWT token for which <b>signature was already validated</b> and on which a set of additional validations will be applied.
     * @param expectedTokenType   The type of expected token using the enumeration provided.
     * @param revokedTokenJTIList A list of token identifier (<b>JTI</b> claim) referring to tokens that were revoked and to which the JTI claim of the token will be compared to.
     * @return True only the token pass all the validations.
     * @see "https://www.iana.org/assignments/jwt/jwt.xhtml"
     * @see "https://auth0.com/docs/secure/tokens/access-tokens"
     * @see "https://auth0.com/docs/secure/tokens/id-tokens"
     * @see "https://auth0.com/docs/secure/tokens/refresh-tokens"
     * @see "https://auth0.com/blog/id-token-access-token-what-is-the-difference/"
     * @see "https://jwt.io/libraries?language=Java"
     * @see "https://pentesterlab.com/blog/secure-jwt-library-design"
     * @see "https://github.com/auth0/java-jwt"
     */
    public static boolean applyJWTExtraValidation(DecodedJWT token, TokenType expectedTokenType, List<String> revokedTokenJTIList) {
        boolean isValid = false;
        TokenType tokenType;
        try {
            if (!"none".equalsIgnoreCase(token.getAlgorithm().trim())) {
                if (!token.getClaim("exp").isMissing() && token.getExpiresAt() != null) {
                    String jti = token.getId();
                    if (jti != null && !jti.trim().isEmpty()) {
                        boolean jtiIsRevoked = revokedTokenJTIList.stream().anyMatch(jti::equalsIgnoreCase);
                        if (!jtiIsRevoked) {
                            //Determine the token type based on the presence of specifics claims
                            if (!token.getClaim("scope").isMissing()) {
                                tokenType = TokenType.ACCESS;
                            } else if (!token.getClaim("name").isMissing() || !token.getClaim("email").isMissing()) {
                                tokenType = TokenType.ID;
                            } else {
                                tokenType = TokenType.REFRESH;
                            }
                            isValid = (tokenType.equals(expectedTokenType));
                        }
                    }
                }
            }

        } catch (Exception e) {
            //In case of error then assume that the check failed
            isValid = false;
        }
        return isValid;
    }

    /**
     * Apply a validations on a regular expression to ensure that is not prone to the ReDOS attack.
     * <br>If your technology is supported by <a href="https://github.com/doyensec/regexploit">regexploit</a> then <b>use it instead of this method!</b>
     * <br>Indeed, the <a href="https://www.doyensec.com/">Doyensec</a> team has made an intensive and amazing work on this topic and created this effective tool.
     *
     * @param regex                       String expected to be a valid regular expression (regex).
     * @param data                        Test data on which the regular expression is executed for the test.
     * @param maximumRunningTimeInSeconds Optional parameter to specify a number of seconds above which a regex execution time is considered as not safe (default to 4 seconds when not specified).
     * @return True only if the string pass all validations.
     * @see "https://github.blog/security/how-to-fix-a-redos/"
     * @see "https://learn.snyk.io/lesson/redos"
     * @see "https://rules.sonarsource.com/java/RSPEC-2631/"
     * @see "https://github.com/doyensec/regexploit"
     * @see "https://github.com/makenowjust-labs/recheck"
     * @see "https://github.com/tjenkinson/redos-detector"
     * @see "https://wiki.owasp.org/images/2/23/OWASP_IL_2009_ReDoS.pdf"
     * @see "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"
     */
    public static boolean isRegexSafe(String regex, String data, Optional<Integer> maximumRunningTimeInSeconds) {
        Objects.requireNonNull(maximumRunningTimeInSeconds, "Use 'Optional.empty()' to leverage the default value.");
        Objects.requireNonNull(data, "A sample data is needed to perform the test.");
        Objects.requireNonNull(regex, "A regular expression is needed to perform the test.");
        boolean isSafe = false;
        int executionTimeout = maximumRunningTimeInSeconds.orElse(4);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Callable<Boolean> task = () -> {
                Pattern pattern = Pattern.compile(regex);
                return pattern.matcher(data).matches();
            };
            List<Future<Boolean>> tasks = executor.invokeAll(List.of(task), executionTimeout, TimeUnit.SECONDS);
            if (!tasks.getFirst().isCancelled()) {
                isSafe = true;
            }
        } catch (Exception e) {
            isSafe = false;
        } finally {
            executor.shutdownNow();
        }
        return isSafe;
    }

    /**
     * Compute a UUID version 7 without using any external dependency.<br><br>
     * <b>Below are my personal point of view and perhaps I'm totally wrong!</b>
     * <br><br>
     * Why such method?
     * <ul>
     * <li>Java inferior or equals to 21 does not supports natively the generation of an UUID version 7.</li>
     * <li>Import a library just to generate such value is overkill for me.</li>
     * <li>Library that I have found, generating such version of an UUID, are not provided by entities commonly used in the java world, such as the SPRING framework provider.</li>
     * </ul>
     * <br>
     * <b>Full credits for this implementation goes to the authors and contributors of the <a href="https://github.com/nalgeon/uuidv7">UUIDv7</a> project.</b>
     * <br><br>
     * Below are the java libraries that I have found but, for which, I do not trust enough the provider to use them directly:
     * <ul>
     *     <li><a href="https://github.com/cowtowncoder/java-uuid-generator">java-uuid-generator</a></li>
     *     <li><a href="https://github.com/f4b6a3/uuid-creator">uuid-creator</a></li>
     * </ul>
     *
     * @return A UUID object representing the UUID v7.
     * @see "https://uuid7.com/"
     * @see "https://antonz.org/uuidv7/"
     * @see "https://mccue.dev/pages/3-11-25-life-altering-postgresql-patterns"
     * @see "https://www.ietf.org/archive/id/draft-peabody-dispatch-new-uuid-format-04.html#name-uuid-version-7"
     * @see "https://www.baeldung.com/java-generating-time-based-uuids"
     * @see "https://en.wikipedia.org/wiki/Universally_unique_identifier"
     * @see "https://buildkite.com/resources/blog/goodbye-integers-hello-uuids/"
     */
    public static UUID computeUUIDv7() {
        SecureRandom secureRandom = new SecureRandom();
        // Generate truly random bytes
        byte[] value = new byte[16];
        secureRandom.nextBytes(value);
        // Get current timestamp in milliseconds
        ByteBuffer timestamp = ByteBuffer.allocate(Long.BYTES);
        timestamp.putLong(System.currentTimeMillis());
        // Create the TIMESTAMP part of the UUID
        System.arraycopy(timestamp.array(), 2, value, 0, 6);
        // Create the VERSION and the VARIANT parts of the UUID
        value[6] = (byte) ((value[6] & 0x0F) | 0x70);
        value[8] = (byte) ((value[8] & 0x3F) | 0x80);
        //Create the HIGH and LOW parts of the UUID
        ByteBuffer buf = ByteBuffer.wrap(value);
        long high = buf.getLong();
        long low = buf.getLong();
        //Create and return the UUID object
        UUID uuidv7 = new UUID(high, low);
        return uuidv7;
    }

    /**
     * Ensure that an XSD file does not contain any include/import/redefine instruction (prevent exposure to SSRF).
     *
     * @param xsdFilePath Filename of the XSD file to check.
     * @return True only if the file pass all validations.
     * @see "https://portswigger.net/web-security/ssrf"
     * @see "https://www.w3schools.com/Xml/el_import.asp"
     * @see "https://www.w3schools.com/xml/el_include.asp"
     * @see "https://www.linkedin.com/posts/righettod_appsec-appsecurity-java-activity-7344048434326188053-6Ru9"
     * @see "https://docs.oracle.com/en/java/javase/21/docs/api/java.xml/javax/xml/validation/SchemaFactory.html#setProperty(java.lang.String,java.lang.Object)"
     */
    public static boolean isXSDSafe(String xsdFilePath) {
        boolean isSafe = false;
        try {
            File xsdFile = new File(xsdFilePath);
            if (xsdFile.exists() && xsdFile.canRead() && xsdFile.isFile()) {
                //Parse the XSD file, if an exception occur then it's imply that the XSD specified is not a valid ones
                //Create an schema factory throwing Exception if a external schema is specified
                SchemaFactory schemaFactory = SchemaFactory.newDefaultInstance();
                schemaFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                schemaFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
                //Parse the schema
                Schema schema = schemaFactory.newSchema(xsdFile);
                isSafe = (schema != null);
            }
        } catch (Exception e) {
            isSafe = false;
        }
        return isSafe;
    }


    /**
     * Extract all sensitive information from a string provided.<br>
     * This can be used to identify any sensitive information into a <a href="https://cwe.mitre.org/data/definitions/532.html">message expected to be written in a log</a> and then replace every sensitive values by an obfuscated ones.<br><br>
     * For the luxembourg national identification number, this method focus on detecting identifiers for a physical entity (people) and not a moral one (company).<br><br>
     * I delegated the validation of the IBAN to a dedicated library (<a href="https://github.com/arturmkrtchyan/iban4j">iban4j</a>) to not "reinvent the wheel" and then introduce buggy validation myself. I used <b>iban4j</b> over the <b><a href="https://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/routines/IBANValidator.html">IBANValidator</a></b> class from the <a href="https://commons.apache.org/proper/commons-validator/"><b>Apache Commons Validator</b></a> library because <b>iban4j</b> perform a full official IBAN specification validation so its reduce risks of false-positives by ensuring that an IBAN detected is a real IBAN.<br><br>
     * Same thing and reason regarding the validation of the bank card PAN using the  class <a href="https://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/routines/CreditCardValidator.html">CreditCardValidator</a> from the <b>Apache Commons Validator</b> library.
     *
     * @param content String in which sensitive information must be searched.
     * @return A map with the collection of identified sensitive information gathered by sensitive information type. If nothing is found then the map is empty. A type of sensitive information is only present if there is at least one item found. A set is used to not store duplicates occurrence of the same sensitive information.
     * @throws Exception If any error occurs during the processing.
     * @see "https://guichet.public.lu/en/citoyens/citoyennete/registre-national/identification/demande-numero-rnpp.html"
     * @see "https://cnpd.public.lu/fr/decisions-avis/2009/identifiant-unique.html"
     * @see "https://cnpd.public.lu/content/dam/cnpd/fr/decisions-avis/2009/identifiant-unique/48_2009.pdf"
     * @see "https://en.wikipedia.org/wiki/International_Bank_Account_Number"
     * @see "https://www.iban.com/structure"
     * @see "https://github.com/arturmkrtchyan/iban4j"
     * @see "https://cwe.mitre.org/data/definitions/532.html"
     * @see "https://www.baeldung.com/logback-mask-sensitive-data"
     * @see "https://en.wikipedia.org/wiki/Payment_card_number"
     * @see "https://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/routines/CreditCardValidator.html"
     * @see "https://commons.apache.org/proper/commons-validator/"
     */
    public static Map<SensitiveInformationType, Set<String>> extractAllSensitiveInformation(String content) throws Exception {
        CreditCardValidator creditCardValidator = CreditCardValidator.genericCreditCardValidator();
        Pattern nationalIdentifierRegex = Pattern.compile("([0-9]{13})");
        Pattern ibanNonHumanFormattedRegex = Pattern.compile("([A-Z]{2}[0-9]{2}[A-Z0-9]{11,30})", Pattern.CASE_INSENSITIVE);
        Pattern ibanHumanFormattedRegex = Pattern.compile("([A-Z]{2}[0-9]{2}(?:\\s[A-Z0-9]{4}){2,7}\\s[A-Z0-9]{1,4})", Pattern.CASE_INSENSITIVE);
        Pattern panRegex = Pattern.compile("((?:\\d[ -]*?){13,19})");
        Map<SensitiveInformationType, Set<String>> data = new HashMap<>();
        data.put(SensitiveInformationType.LUXEMBOURG_NATIONAL_IDENTIFICATION_NUMBER, new HashSet<>());
        data.put(SensitiveInformationType.IBAN, new HashSet<>());
        data.put(SensitiveInformationType.BANK_CARD_PAN, new HashSet<>());

        if (content != null && !content.isBlank()) {
            /* Step 1: Search for LU national identifier */
            //A national identifier have the following structure: [BIRTHDATE_YEAR_YYYY][BIRTHDATE_MONTH_MM][BIRTHDATE_DAY_DD][FIVE_INTEGER]
            //Define minimal and maximal birth year base on current year
            //Assume people live less than 120 years
            int maxBirthYear = LocalDate.now(ZoneId.of("Europe/Luxembourg")).getYear();
            int minBirthYear = maxBirthYear - 120;
            Matcher matcher = nationalIdentifierRegex.matcher(content);
            String nationalIdentierFull;
            int nationalIdentierYear, nationalIdentierMonth, nationalIdentierDay;
            while (matcher.find()) {
                nationalIdentierFull = matcher.group(1);
                //Check that the string is a valid national identifier and if yes then add it
                nationalIdentierYear = Integer.parseInt(nationalIdentierFull.substring(0, 4));
                nationalIdentierMonth = Integer.parseInt(nationalIdentierFull.substring(4, 6));
                nationalIdentierDay = Integer.parseInt(nationalIdentierFull.substring(6, 8));
                if (nationalIdentierYear >= minBirthYear && nationalIdentierYear <= maxBirthYear) {
                    if (nationalIdentierMonth >= 1 && nationalIdentierMonth <= 12) {
                        if (YearMonth.of(nationalIdentierYear, nationalIdentierMonth).isValidDay(nationalIdentierDay)) {
                            data.get(SensitiveInformationType.LUXEMBOURG_NATIONAL_IDENTIFICATION_NUMBER).add(nationalIdentierFull);
                        }
                    }
                }
            }

            /* Step 2a: Search for IBAN that are non human formatted */
            matcher = ibanNonHumanFormattedRegex.matcher(content);
            String iban, ibanUpperCased;
            while (matcher.find()) {
                iban = matcher.group(1);
                ibanUpperCased = iban.toUpperCase(Locale.ROOT);
                //Check that the string is a valid IBAN and if yes then add it
                if (IbanUtil.isValid(ibanUpperCased)) {
                    data.get(SensitiveInformationType.IBAN).add(iban);
                }
            }

            /* Step 2b: Search for IBAN that are human formatted */
            matcher = ibanHumanFormattedRegex.matcher(content);
            String ibanUpperCasedNoSpace;
            while (matcher.find()) {
                iban = matcher.group(1);
                ibanUpperCasedNoSpace = iban.toUpperCase(Locale.ROOT).replace(" ", "");
                //Check that the string is a valid IBAN and if yes then add it
                if (IbanUtil.isValid(ibanUpperCasedNoSpace)) {
                    data.get(SensitiveInformationType.IBAN).add(iban);
                }
            }

            /* Step 3: Search for bank card PAN */
            matcher = panRegex.matcher(content);
            String pan, panNoSeparator;
            while (matcher.find()) {
                pan = matcher.group(1);
                panNoSeparator = pan.toUpperCase(Locale.ROOT).replace(" ", "").replace("-", "");
                //Check that the string is a valid PAN and if yes then add it
                if (creditCardValidator.isValid(panNoSeparator)) {
                    data.get(SensitiveInformationType.BANK_CARD_PAN).add(pan);
                }
            }

        }

        //Cleanup if a set is empty
        if (data.get(SensitiveInformationType.LUXEMBOURG_NATIONAL_IDENTIFICATION_NUMBER).isEmpty()) {
            data.remove(SensitiveInformationType.LUXEMBOURG_NATIONAL_IDENTIFICATION_NUMBER);
        }
        if (data.get(SensitiveInformationType.IBAN).isEmpty()) {
            data.remove(SensitiveInformationType.IBAN);
        }
        if (data.get(SensitiveInformationType.BANK_CARD_PAN).isEmpty()) {
            data.remove(SensitiveInformationType.BANK_CARD_PAN);
        }

        return data;
    }

    /**
     * Apply a collection of validations on a bytes array provided representing GZIP compressed data:
     * <ul>
     * <li>Are valid GZIP compressed data.</li>
     * <li>The number of bytes once decompressed is under the specified limit.</li>
     * </ul>
     * <br><b>Note:</b> The value <code>Integer.MAX_VALUE - 8</code> was chosen because during my tests on Java 25 (JDK 64 bits on Windows 11 Pro), it was possible to decompress such amount of data with the default JVM settings without causing an <a href="https://docs.oracle.com/en/java/javase/25/docs/api//java.base/java/lang/OutOfMemoryError.html">Out Of Memory error</a>.
     *
     * @param compressedBytes                    Array of bytes containing the GZIP compressed data to check.
     * @param maxCountOfDecompressedBytesAllowed Maximum number of decompressed bytes allowed. Default to 10 MB if the specified value is inferior to 1 or superior to Integer.MAX_VALUE - 8.
     * @return True only if the file pass all validations.
     * @see "https://en.wikipedia.org/wiki/Gzip"
     * @see "https://www.rapid7.com/db/modules/auxiliary/dos/http/gzip_bomb_dos/"
     */
    public static boolean isGZIPCompressedDataSafe(byte[] compressedBytes, long maxCountOfDecompressedBytesAllowed) {
        boolean isSafe = false;

        try {
            long limit = maxCountOfDecompressedBytesAllowed;
            long totalRead = 0L;
            byte[] buffer = new byte[8 * 1024];
            int read;
            if (limit < 1 || limit > (Integer.MAX_VALUE - 8)) {
                limit = 10_000_000;
            }
            try (ByteArrayInputStream bis = new ByteArrayInputStream(compressedBytes); GZIPInputStream gzipInputStream = new GZIPInputStream(new BufferedInputStream(bis))) {
                while ((read = gzipInputStream.read(buffer)) != -1) {
                    totalRead += read;
                    if (totalRead > limit) {
                        throw new Exception();
                    }
                }
            }
            isSafe = true;
        } catch (Exception e) {
            isSafe = false;
        }

        return isSafe;
    }

    /**
     * Process a string, intended to be written in a log, to remove as much as possible information that can lead to an exposure to a log injection vulnerability.<br><br>
     * <b>Log injection</b> is also called <b>log forging</b>.<br><br>
     * The following information are removed:
     * <ul>
     *     <li>Characters: Carriage Return (CR), Linefeed (LF) and Tabulation (TAB).</li>
     *     <li>Leading and trailing spaces.</li>
     *     <li>Any HTML tags.</li>
     * </ul><br>
     * A parameter is also used to limit the maximum length of the sanitized message.
     * To remove any HTML tags, the OWASP project <a href="https://owasp.org/www-project-java-html-sanitizer/">Java HTML Sanitizer</a> is leveraged.<br>
     * I delegated such removal to a dedicated library to prevent missing of edge cases as well as potential bypasses.
     *
     * @param message          The original string message intended to be written in a log.
     * @param maxMessageLength The maximum number of characters after which the sanitized message must be truncated. If inferior to 1 then default to the value of 500.
     * @return The string message cleaned.
     * @see "https://www.wallarm.com/what/log-forging-attack"
     * @see "https://www.invicti.com/learn/crlf-injection"
     * @see "https://knowledge-base.secureflag.com/vulnerabilities/inadequate_input_validation/log_injection_vulnerability.html"
     * @see "https://capec.mitre.org/data/definitions/93.html"
     * @see "https://codeql.github.com/codeql-query-help/javascript/js-log-injection/"
     * @see "https://owasp.org/www-project-java-html-sanitizer/"
     * @see "https://github.com/OWASP/java-html-sanitizer"
     */
    public static String sanitizeLogMessage(String message, int maxMessageLength) {
        String sanitized = message;
        int maxSanitizedMessageLength = maxMessageLength;

        if (sanitized != null && !sanitized.isBlank()) {
            if (maxSanitizedMessageLength < 1) {
                maxSanitizedMessageLength = 500;
            }
            //Step 1: Remove any CR/LR/TAB characters as well as leading and trailing spaces
            sanitized = sanitized.replaceAll("[\\n\\r\\t]", "").trim();
            //Step 2: Remove any HTML tags
            PolicyFactory htmlSanitizerPolicy = new HtmlPolicyBuilder().toFactory();
            sanitized = htmlSanitizerPolicy.sanitize(sanitized);
            //Step 3: Truncate the string in case of need
            if (sanitized.length() > maxSanitizedMessageLength) {
                sanitized = sanitized.substring(0, maxSanitizedMessageLength);
            }
        }

        return sanitized;
    }
}

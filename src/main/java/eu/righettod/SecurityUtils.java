package eu.righettod;


import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
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
import org.w3c.dom.Document;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonReader;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
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
     * Rule to consider a PIN code as weak:<br>
     * - Length is inferior to 6 positions.<br>
     * - Contain only the same number or only a sequence of zero.<br>
     * - Contain sequence of following incremental or decremental numbers.<br>
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
     * Apply a collection of validations on a Word 97-2003 (binary format) document file provided:<br>
     * - Real Microsoft Word 97-2003 document file.<br>
     * - No VBA Macro.<br>
     * - No embedded objects.<br>
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
     * Apply a collection of validations on a PDF file provided:<br>
     * - Real PDF file<br>
     * - No attachments.<br>
     * - No Javascript code.<br>
     * - No links using action of type URI/Launch/RemoteGoTo/ImportData.<br>
     *
     * @param pdfFilePath Filename of the PDF file to check.
     * @return True only if the file pass all validations.
     * @see "https://stackoverflow.com/a/36161267"
     * @see "https://www.gushiciku.cn/pl/21KQ"
     * @see "https://github.com/jonaslejon/malicious-pdf"
     * @see "https://pdfbox.apache.org/"
     * @see "https://mvnrepository.com/artifact/org.apache.pdfbox/pdfbox"
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
                        //Step 3: Check if the file contains Javascript code, in our case is not allowed
                        if (namesDictionary.getJavaScript() == null) {
                            //Step 4: Check if the file contains links using action of type URI/Launch/RemoteGoTo/ImportData, in our case is not allowed
                            final List<Integer> notAllowedAnnotationCounterList = new ArrayList<>();
                            AnnotationFilter notAllowedAnnotationFilter = new AnnotationFilter() {
                                @Override
                                public boolean accept(PDAnnotation annotation) {
                                    boolean keep = false;
                                    if (annotation instanceof PDAnnotationLink) {
                                        PDAnnotationLink link = (PDAnnotationLink) annotation;
                                        PDAction action = link.getAction();
                                        if ((action instanceof PDActionURI)
                                                || (action instanceof PDActionLaunch)
                                                || (action instanceof PDActionRemoteGoTo)
                                                || (action instanceof PDActionImportData)
                                        ) {
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
     * Apply a collection of validations on a ZIP file provided:<br>
     * - Real ZIP file<br>
     * - Contain less than a specified level of deepness.<br>
     * - Do not contain Zip-Slip entry path.<br>
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
     * Apply a collection of validations on a string expected to be an public IP address:<br>
     * - Is a valid IP v4 or v6 address.<br>
     * - Is public from an Internet perspective.<br><br>
     * <b>Note:</b> I often see missing such validation in the value read from HTTP request headers like "X-Forwarded-For" or "Forwarded".
     * <br>
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
                    isValid = (!addr.isAnyLocalAddress() && !addr.isLinkLocalAddress()
                            && !addr.isLoopbackAddress() && !addr.isMulticastAddress()
                            && !addr.isSiteLocalAddress());
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
     * Example of possible abuse without precautions applied during the hash calculation logic:<br>
     * Hash of <code>SHA256("Hello", "My", "World!!!")</code> will be equals to the hash of <code>SHA256("Hell", "oMyW", "orld!!!")</code>.<br><br>
     * This method ensure that both hash above will be different.
     *
     * @param parts Ordered list of strings to use to build the input string for which the hash must be computed on. No null value is accepted on object composing the collection.
     * @return The hash, as an array of bytes, to allow caller to convert it to the final representation wanted (HEX, Base64, etc.). If the collection passed is null or empty then the method return null.
     * @throws Exception If any exception occurs
     * @see "https://pentesterlab.com/badges/codereview"
     */
    public static byte[] computeHashNoProneToAbuseOnParts(List<String> parts) throws Exception {
        byte[] hash = null;
        if (parts != null && !parts.isEmpty()) {
            //Ensure that not part is null
            if (parts.stream().anyMatch(Objects::isNull)) {
                throw new IllegalArgumentException("No part must be null!");
            }
            String separator = "|";
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
     * Apply a collection of validations on a EXCEL CSV file provided (file was expected to be opened in Microsoft EXCEL):<br>
     * - Real CSV file.<br>
     * - Do not contains any payload related to a CSV injections.<br><br>
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
     * @param processingMode Define the mode of processing i.e. protect or validate. ({@link eu.righettod.ProcessingMode})
     * @param input          When the processing mode is "protect" than the expected input (string) is a java serialized object encoded in Base64 otherwise (processing mode is "validate") expected input is the output of this method when the "protect" mode was used.
     * @param secret         Secret to use to compute the SHA256 HMAC.
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
    public static Map<String, Object> ensureSerializedObjectIntegrity(ProcessingMode processingMode, String input, byte[] secret) throws Exception {
        Map<String, Object> results;
        String resultFormatTemplate = "%s:%s";
        //Verify input provided to be consistent
        if (processingMode == null) {
            throw new IllegalArgumentException("The processing mode is mandatory!");
        }
        if (input == null || input.trim().isEmpty()) {
            throw new IllegalArgumentException("Input data is mandatory!");
        }
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("The HMAC secret is mandatory!");
        }
        if (processingMode.equals(ProcessingMode.VALIDATE) && input.split(":").length != 2) {
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
        results.put("PROCESSING_MODE", processingMode.toString());
        switch (processingMode) {
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
     * Apply a collection of validations on a JSON string provided:<br>
     * - Real JSON structure.<br>
     * - Contain less than a specified number of deepness for nested objects or arrays.<br>
     * - Contain less than a specified number of items in any arrays.<br><br>
     *
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
}

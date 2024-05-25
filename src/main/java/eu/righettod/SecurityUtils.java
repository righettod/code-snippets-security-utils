package eu.righettod;

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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Provides different utilities methods to apply processing from a security perspective.<br>
 * These code snippet can be used, as "foundation", to customize the validation to the app context.<br>
 * These code snippet were implemented in a way to facilitate adding or removal of validations depending on usage context.<br>
 * These code snippet were centralized on one class to be able to enhance them across time as well as missing case/bug identification.<br>
 */
public class SecurityUtils {

    /**
     * Default constructor: Not needed as the class only provided static methods.
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
}

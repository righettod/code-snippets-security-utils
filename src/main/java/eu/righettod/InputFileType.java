package eu.righettod;

/**
 * Enumeration used by the method <code>SecurityUtils.sanitizeFile()</code> to define the type of file to sanitize.
 */
public enum InputFileType {
    /**
     * Image: PNG, GIF, ...
     */
    IMAGE,

    /**
     * PDF file
     */
    PDF
}

package eu.righettod;

/**
 * Enumeration used by the method <code>SecurityUtils.ensureSerializedObjectIntegrity()</code> to define its working mode.
 */
public enum ProcessingMode {
    /**
     * Protection mode: Add the integrity HMAC to the linked serialized object.
     */
    PROTECT,

    /**
     * Validation of the protection mode: Verify the integrity HMAC against the linked serialized object.
     */
    VALIDATE
}

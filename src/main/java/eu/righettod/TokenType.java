package eu.righettod;

/**
 * Enumeration used by the method <code>SecurityUtils.applyJWTExtraValidation()</code> to define the type of token.
 */
public enum TokenType {

    /**
     * Access token.
     *
     * @see "https://auth0.com/docs/secure/tokens/access-tokens"
     */
    ACCESS,

    /**
     * ID token.
     *
     * @see "https://auth0.com/docs/secure/tokens/id-tokens"
     */
    ID,

    /**
     * Refresh token.
     *
     * @see "https://auth0.com/docs/secure/tokens/refresh-tokens"
     */
    REFRESH
}

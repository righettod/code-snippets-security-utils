package eu.righettod;

/**
 * Enumeration used by the method <code>SecurityUtils.extractAllSensitiveInformation()</code> to identify types of information found.
 */
public enum SensitiveInformationType {
    /**
     * National identifier used by government entities in Luxembourg to identify uniquely citizens.
     *
     * @see "https://guichet.public.lu/en/citoyens/citoyennete/registre-national/identification/demande-numero-rnpp.html"
     * @see "https://cnpd.public.lu/fr/decisions-avis/2009/identifiant-unique.html"
     *
     */
    LUXEMBOURG_NATIONAL_IDENTIFICATION_NUMBER,

    /**
     * International Bank Account Number.
     *
     * @see "https://en.wikipedia.org/wiki/International_Bank_Account_Number"
     */
    IBAN,

    /**
     * Bank payment card Primary Account Number.
     *
     * @see "https://en.wikipedia.org/wiki/Payment_card_number"
     */
    BANK_CARD_PAN

}

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package es.rickyepoderi.signerdaemon;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Properties;

/**
 * <p>Simple interface to manage a repository of certificates. The idea is
 * using it to sign and verify any data. The signer is always configured
 * with a properties file and some properties are defined here as common
 * properties.</p>
 * 
 * @author ricky
 */
public interface Signer {

    /**
     * Property for the type of the keystore type (JKS, PKCS12,...).
     */
    final static public String KEY_STORE_TYPE = "sample.applet.keyStoreType";
    
    /**
     * Property for the type of the provider type (JKS, PKCS12,...).
     */
    final static public String JCE_PROVIDER_TYPE = "sample.applet.keyProviderType";
    
    /**
     * Property for the file where the store is placed.
     */
    final static public String KEY_STORE_FILE_PATH = "sample.applet.keyStoreFilePath";
    
    /**
     * Property that marks if the repository needs a password to open it.
     */
    final static public String KEY_STORE_PASSWORD_NEEDED = "sample.applet.keyStorePasswordNeeded";
    
    /**
     * Property that marks if each certificate/key needs a second password.
     */
    final static public String KEY_ACCESS_NEEDED = "sample.applet.keyAcessNeeded";
    
    /**
     * Property that marks if the keys use the same password than the repository one.
     */
    final static public String USE_SAME_PASSWORD_FOR_KEYS = "sample.applet.useSamePasswordForKeys";
    
    /**
     * Configure the repository with a properties file. 
     * @param props The configuration properties
     * @throws Exception Some error
     */
    public void setProperties(Properties props) throws Exception ;
    
    /**
     * Method that returns if the repository is already initialized.
     * @return true if initialized, false otherwise
     */
    public boolean isInitialized();

    /**
     * Initializes the repository with the password (if needed)
     * @param password The password of the repository or null
     * @throws Exception Some error
     */
    public void initialize(String password) throws Exception;

    /**
     * Getter method to check if the repository uses a general password.
     * @return true if there is a store password, false if not
     */
    public boolean isKeyAccessNeeded();

    /**
     * Getter method to check if the keys have a second password.
     * @return true if there are password for key, false if not
     */
    public boolean isKeyStorePasswordNeeded();
    
    /**
     * Getter method to check if the password have a second password but is the
     * same than the general password.
     * @return true if the password for keys is the same, false if not
     */
    public boolean useSamePasswordForKeys();

    /**
     * Method to list all the certificates in the repository.
     * @return The list of certificates inside a map keyed by the alias
     * @throws Exception Some error
     */
    public Map<String, X509Certificate> getAllKeyCertificates() throws Exception;

    /**
     * Method to get a specified certificate from the repo.
     * @param alias The alias of the certificate to get
     * @return The certificate or null
     * @throws Exception Some error
     */
    public X509Certificate getCertificate(String alias) throws Exception;

    /**
     * Method that return the private key for a specified certificate.
     * @param alias The alias of the certificate
     * @param password The password (if needed)
     * @return The private key for that certificate
     * @throws Exception Some error
     */
    public PrivateKey getAssociatedPrivateKey(String alias, String password) throws Exception;

    /**
     * Method that really sign a data.
     * @param plain The data to sign
     * @param type The type of the signature to perform (java type like "SHA1withRSA")
     * @param alias The alias of the certificate in the repository
     * @param password The password for the key (if needed)
     * @return The signature byte array
     * @throws Exception Some error
     */
    public byte[] sign(byte[] plain, String type, String alias, String password) throws Exception;
    
    /**
     * Method that verifies a signature.
     * @param sign The signature to verify
     * @param plain The data to verify
     * @param type The type of the signature applied (java type like "SHA1withRSA")
     * @param alias The alias of the certificate in the repository
     * @return true if valid, false if not
     * @throws Exception Some error
     */
    public boolean verify(byte[] sign, byte[] plain, String type, String alias) throws Exception;

}

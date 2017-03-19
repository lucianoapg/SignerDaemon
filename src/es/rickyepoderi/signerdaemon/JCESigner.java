/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package es.rickyepoderi.signerdaemon;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * <p>General signer that manages a Java JCE signer. This class is quite generic
 * but it works for several out of the box certificate repositories (JKS, 
 * PKCS12, Windows-MY,...). So it is functional for a lot of repositories.</p>
 * 
 * @author ricky
 */
public class JCESigner implements Signer {

    protected KeyStore keyStore = null;
    protected String keyStoreType = null;
    protected String providerType = null;
    protected String keyStorePassword = null;
    private String filePathToKeyStore = null;
    protected boolean keyStorePasswordNeeded = true;
    protected boolean keyAccessNeeded = true;
    protected boolean useSamePasswordForKeys = false;

    /**
     * Method that parses the general properties defined in Signer interface.
     * @param props The configuration properties
     */
    protected void parseCommomprops(Properties props) {
        keyStorePasswordNeeded = true;
        keyAccessNeeded = true;
        useSamePasswordForKeys = false;
        if ("no".equalsIgnoreCase(props.getProperty(KEY_STORE_PASSWORD_NEEDED))
                || "false".equalsIgnoreCase(props.getProperty(KEY_STORE_PASSWORD_NEEDED))) {
            keyStorePasswordNeeded = false;
        }
        if ("no".equalsIgnoreCase(props.getProperty(KEY_ACCESS_NEEDED))
                || "false".equalsIgnoreCase(props.getProperty(KEY_ACCESS_NEEDED))) {
            keyAccessNeeded = false;
        }
        if ("yes".equalsIgnoreCase(props.getProperty(USE_SAME_PASSWORD_FOR_KEYS))
                || "true".equalsIgnoreCase(props.getProperty(USE_SAME_PASSWORD_FOR_KEYS))) {
            useSamePasswordForKeys = true;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setProperties(Properties props) throws Exception {
        keyStoreType = props.getProperty(KEY_STORE_TYPE);
        providerType = props.getProperty(JCE_PROVIDER_TYPE);
        if (keyStoreType == null || providerType == null) {
            throw new Exception(new StringBuffer(KEY_STORE_TYPE).append(" and ").append(JCE_PROVIDER_TYPE).append(" have to be provided.").toString());
        }
        filePathToKeyStore = props.getProperty(KEY_STORE_FILE_PATH);
        parseCommomprops(props);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void initialize(String password) throws Exception {
        keyStorePassword = password;
        keyStore = KeyStore.getInstance(this.keyStoreType);
        File keystoreFile = null;
        FileInputStream in = null;
        if (filePathToKeyStore != null) {
            keystoreFile = new File(filePathToKeyStore);
        }
        try {
            if (keystoreFile != null) {
                in = new FileInputStream(keystoreFile);
            }
            if (password != null) {
                keyStore.load(in, password.toCharArray());
            } else {
                keyStore.load(in, null);
            }
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isKeyAccessNeeded() {
        return keyAccessNeeded;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isKeyStorePasswordNeeded() {
        return keyStorePasswordNeeded;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean useSamePasswordForKeys() {
        return useSamePasswordForKeys;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isInitialized() {
        try {
            return keyStore != null && keyStore.size() > 0;
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, X509Certificate> getAllKeyCertificates() throws Exception {
        Map<String, X509Certificate> res = new HashMap<>();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                res.put(alias, getCertificate(alias));
            }
        }
        return res;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public X509Certificate getCertificate(String alias) throws Exception {
        return (X509Certificate) keyStore.getCertificate(alias);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PrivateKey getAssociatedPrivateKey(String alias, String password) throws Exception {
        if (password != null) {
            return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        } else if (useSamePasswordForKeys) {
            return (PrivateKey) keyStore.getKey(alias, keyStorePassword.toCharArray());
        } else {
            return (PrivateKey) keyStore.getKey(alias, null);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] sign(byte[] plain, String type, String alias, String password) throws Exception {
        X509Certificate x509 = getCertificate(alias);
        PrivateKey priv = getAssociatedPrivateKey(alias, password);
        Signature signature = Signature.getInstance(type);
        signature.initSign(priv);
        signature.update(plain);
        return signature.sign();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(byte[] plain, byte[] sign, String type, String alias) throws Exception {
        X509Certificate x509 = getCertificate(alias);
        PublicKey pub = x509.getPublicKey();
        Signature signature = Signature.getInstance(type);
        signature.initVerify(pub);
        signature.update(plain);
        return signature.verify(sign);
    }
}

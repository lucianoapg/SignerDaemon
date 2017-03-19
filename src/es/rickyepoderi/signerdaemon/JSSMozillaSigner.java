/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package es.rickyepoderi.signerdaemon;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.InitializationValues;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;
import org.mozilla.jss.util.PasswordCallback.GiveUpException;
import org.mozilla.jss.util.PasswordCallbackInfo;

/**
 * <p>This Signer is the repository used by firefox browser based in 
 * NSS (Netscape Security Services). It manages JSS (Java Security Services)
 * over the native libraries.</p>
 * 
 * @author ricky
 */
@Deprecated
public class JSSMozillaSigner extends JCESigner {

    /**
     * Property that specifies the directory where the JSS configuration is located.
     */
    final static public String JSS_CONFIG_DIR = "sample.applet.jssConfigDir";
    final static public String JSS_CERT_PREFIX = "sample.applet.jssCertPrefix";
    final static public String JSS_KEY_PREFIX = "sample.applet.jssKeyPrefix";
    final static public String JSS_SECMOD_NAME = "sample.applet.jssSecmodName";

    private CryptoManager manager = null;
    private CryptoToken token = null;
    private CryptoStore store = null;
    private String configDir = null;
    private String certPrefix = null;
    private String keyPrefix = null;
    private String secmodName = null;


    static public class JSSCallback implements PasswordCallback {

        private String password = null;

        public JSSCallback(String password) {
            this.password = password;
        }

        @Override
        public Password getPasswordFirstAttempt(PasswordCallbackInfo arg0) throws GiveUpException {
            return new Password(password.toCharArray());
        }

        @Override
        public Password getPasswordAgain(PasswordCallbackInfo arg0) throws GiveUpException {
            return new Password(password.toCharArray());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setProperties(Properties props) throws Exception {
        this.keyStoreType = "Mozilla-JSS";
        this.providerType = "Mozilla-JSS";
        // initialize JSS with the directory of my store in firefox
        configDir = props.getProperty(JSS_CONFIG_DIR);
        if (configDir == null) {
            throw new Exception(new StringBuffer(JSS_CONFIG_DIR).append(
                    " have to be provided.").toString());
        }
        certPrefix = props.getProperty(JSS_CERT_PREFIX);
        if (certPrefix == null) {
            certPrefix = "";
        }
        keyPrefix = props.getProperty(JSS_KEY_PREFIX);
        if (keyPrefix == null) {
            keyPrefix = "";
        }
        secmodName = props.getProperty(JSS_SECMOD_NAME);
        if (secmodName == null) {
            secmodName = "secmod";
        }
        // set JSS normal access for store
        this.keyStorePasswordNeeded = true;
        this.keyAccessNeeded = false;
        this.useSamePasswordForKeys = false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void initialize(String password) throws Exception {
        this.keyStorePassword = password;
        InitializationValues init = new InitializationValues(configDir, certPrefix, keyPrefix, secmodName);
        // the JSS provider must be installed to use later
        // not needed cos it's the default but...
        init.installJSSProvider = true;
        CryptoManager.initialize(init);
        // get some useful vars
        this.manager = CryptoManager.getInstance();
        this.token = manager.getInternalKeyStorageToken();
        manager.setThreadToken(token);
        this.store = token.getCryptoStore();
        manager.setPasswordCallback(new JSSCallback(password));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isInitialized() {
        return manager != null && token != null && store != null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, X509Certificate> getAllKeyCertificates() throws Exception {
        Map<String, X509Certificate> res = new HashMap<>();
        org.mozilla.jss.crypto.X509Certificate certs[] = store.getCertificates();
        for (org.mozilla.jss.crypto.X509Certificate cert : certs) {
            boolean hasKey = true;
            try {
                manager.findPrivKeyByCert(cert);
            }catch (ObjectNotFoundException e) {
                hasKey = false;
            }
            if (hasKey) {
                X509Certificate x509 = convertToX509Certificate(cert);
                res.put(cert.getNickname(), x509);
            }
        }
        return res;
    }

    /**
     * Method that converts the JSS certificate into a java X509 certificate.
     * @param cert The JSS certificate
     * @return The X509 certificate
     * @throws Exception Some error
     */
    private X509Certificate convertToX509Certificate(
            org.mozilla.jss.crypto.X509Certificate cert) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public X509Certificate getCertificate(String alias) throws Exception {
        org.mozilla.jss.crypto.X509Certificate cert = manager.findCertByNickname(alias);
        return convertToX509Certificate(cert);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PrivateKey getAssociatedPrivateKey(String alias, String password) throws Exception {
        org.mozilla.jss.crypto.X509Certificate cert = manager.findCertByNickname(alias);
        return manager.findPrivKeyByCert(cert);
    }
}

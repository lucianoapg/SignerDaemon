/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package es.rickyepoderi.signerdaemon;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * <p>Class that extends the JCESigner to use the java PKCS11 implementation.
 * The PKCS11 uses a configuration file similar to the properties file. So
 * this signer passes any property that does not start by "sample." to the
 * PKCS11 initialization.</p>
 * 
 * <p>The signer adds only a known new property, the name of the PKCS11
 * module:</p>
 * 
 * <ul>
 * <li>sample.applet.pkcs11Name: The name of the PKCS11 when adding it
 * to the security environment.</li>
 * </ul>
 * 
 * @author ricky
 * @see JCESigner
 */
public class PKCS11Signer extends JCESigner {

    /**
     * Compulsory property to define the name of the PKCS11 repo.
     */
    final static public String PKCS11_NAME = "sample.applet.pkcs11Name";
    
    /**
     * Map of providers already configured in the JVM.
     */
    static private Map<String,Provider> providers = new HashMap<>();
    
    /**
     * Name of the PKCS11 module.
     */
    private String name = null;

    static public class PKCS11Callback implements CallbackHandler {

        private String password = null;

        public PKCS11Callback(String password) {
            this.password = password;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback) callback;
                    System.err.print(pc.getPrompt());
                    System.err.flush();
                    pc.setPassword(password.toCharArray());
                } else {
                    throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
                }
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setProperties(Properties props) throws Exception {
        name = props.getProperty(PKCS11_NAME);
        if (name == null) {
            throw new Exception(new StringBuffer(PKCS11_NAME).append(
                    " have to be provided.").toString());
        }
        // common properties
        parseCommomprops(props);
        // create the names
        this.keyStoreType = "PKCS11";
        this.providerType = "SunPKCS11-" + name;
        // check if the provider is already registered
        System.err.println("adding PKCS11....");
        if (Security.getProvider(this.providerType) == null ||
                !providers.containsKey(this.providerType)) {
            System.err.println("adding PKCS11....");
            // register the provider adding all the rest of properties as lines
            StringBuilder sb = new StringBuilder();
            sb.append("name = ");
            sb.append(name);
            sb.append(System.getProperty("line.separator"));
            Enumeration keys = props.keys();
            while (keys.hasMoreElements()) {
                String key = (String) keys.nextElement();
                if (!key.startsWith("sample.")) {
                    sb.append(key);
                    sb.append(" = ");
                    sb.append(props.getProperty(key));
                    sb.append(System.getProperty("line.separator"));
                }
            }
//          sb.append("nssLibraryDirectory = /usr/lib/");
//          sb.append(System.getProperty("line.separator"));
//          sb.append("nssSecmodDirectory = /home/ricky/.mozilla/firefox/lqzn9ms9.default");
//          sb.append(System.getProperty("line.separator"));
//          sb.append("nssModule = keystore");
//          sb.append(System.getProperty("line.separator"));
//          sb.append("nssDbMode = readOnly");
//          sb.append(System.getProperty("line.separator"));
            System.err.println(sb);
            byte[] byteArray = sb.toString().getBytes(System.getProperty("file.encoding"));
            ByteArrayInputStream baos = new ByteArrayInputStream(byteArray);
            Provider p = new sun.security.pkcs11.SunPKCS11(baos);
            Security.addProvider(p);
            providers.put(providerType, p);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void initialize(String password) throws Exception {
        this.keyStorePassword = password;
        this.keyStore = KeyStore.getInstance(keyStoreType, providers.get(this.providerType));
        if (password != null) {
            this.keyStore.load(null, password.toCharArray());
        } else {
            this.keyStore.load(null, null);
        }

//        KeyStore.CallbackHandlerProtection callback = new KeyStore.CallbackHandlerProtection(
//                new PKCS11Callback(password)) ;
//        KeyStore.Builder builder = KeyStore.Builder.newInstance(keyStore, callback);
//        keyStore = builder.getKeyStore();
//        keyStore.getCertificate("CIFRADO");
    }
}

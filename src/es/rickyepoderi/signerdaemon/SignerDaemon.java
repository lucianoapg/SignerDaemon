/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package es.rickyepoderi.signerdaemon;

import com.sun.net.httpserver.HttpExchange;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Pattern;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

/**
 * <p>Class that is a little http server that handles the typical methods of
 * the Signer interface. The ideas is the server performs the interaction with
 * the signer repository but in web. All the methods supports OPTIONS and POST
 * and responds with the proper Access-Control-Allow-* headers to let 
 * the browsers interact from one domain to localhost.</p>
 * 
 * <p>All the server methods receive and produces json data. The data is
 * quite simple, usually plain attributes. The response always have a
 * "status" attribute (success or error) and in case of error an "errorMessage"
 * attribute contains the error message.</p>
 * 
 * <p>The methods that currently handles the server are the following:</p>
 * 
 * <ul>
 * <li>isInitialized: returns is the repository is initialized previously.
 * The data returned is initialized (true or false), keyAccessNeeded (true or false), 
 * storePasswordNeeded (true or false), samePasswordForKeys (true or false).</li>
 * <li>initialize: Initializes the repository with the password. It receives
 * the password if needed and return the same data than isInitialized.</li>
 * <li>listCertificates: lists all the certificates in the repository. It 
 * receives nothing and returns a certificates array with certificate information
 * (alias, subject, issuer, version, serialNumber, notAfter, notBefore, 
 * usage).</li>
 * <li>sign: Performs a signature. It receives data (the byte array to sign in base64),
 * alias (the certificate to use), type (the type of signature) and password (if 
 * needed to access the certificate). The method returns sign with the
 * signature in base64.</li>
 * <li>verify: Performs a verification. It receives data (the data to check),
 * sign (the signature in base64), alias (the certificate) and type (the type
 * of the signature).</li>
 * </ul>
 * 
 * <p>The daemon is initialized with a list of properties passed as an
 * argument. The properties are the following:</p>
 * 
 * <ul>
 * <li>sample.daemon.path: context of the application (e.g. "/signer").</li>
 * <li>sample.daemon.port: port to run the web server (e.g. 8000). 
 * The server only listens in localhost 127.0.0.1 interface.</li>
 * <li>sample.daemon.clazz: Class of the signer to use. This class is
 * re-used from the old sign applet.</li>
 * <li>sample.daemon.origin-regexp: comma separated regular expression of the
 * domains that are allowed to contact with the signer daemon 
 * (e.g. "http(s)?://localhost(:[0-9]+)?").</li>
 * </ul>
 * 
 * @author ricky
 */
public class SignerDaemon extends Thread {

    /**
     * Property used for specifying the path or context.
     */
    static public String DAEMON_PATH_PROP = "sample.daemon.path";
    
    /**
     * Property used for specifying the port of the server.
     */
    static public String DAEMON_PORT_PROP = "sample.daemon.port";
    
    /**
     * Property used for speciying the Signer class to use.
     */
    static public String DAEMON_CLAZZ_PROP = "sample.daemon.clazz";
    
    /**
     * Property for speciying the domains using a comma separated list
     * of regular expressions.
     */
    static public String DAEMON_ORIGIN_REGEXP_PROP = "sample.daemon.origin-regexp";

    /**
     * Array used for the key usages.
     */
    static private String[] KEY_USAGE = {
        "digitalSignature",
        "nonRepudiation",
        "keyEncipherment",
        "dataEncipherment",
        "keyAgreement",
        "keyCertSign",
        "cRLSign",
        "encipherOnly",
        "decipherOnly"
    };

    /**
     * HTTP server used in java 7 and later.
     */
    private com.sun.net.httpserver.HttpServer server;
    
    /**
     * Signer to use.
     * TODO: Manage more than one signer???
     */
    private Signer signer;
    
    /**
     * The password of the repository or signer.
     */
    private String password;
    
    /**
     * List of patterns for the origins allowed.
     */
    private Pattern[] origins;

    /**
     * Method that parses the request to get the JSON object sent.
     * @param he The HTTP exchange request and response
     * @return The JSON object sent by the client
     * @throws IOException Somne error
     * @throws JSONException Some error
     */
    private JSONObject parseJSON(HttpExchange he) throws IOException, JSONException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(he.getRequestBody()))) {
            StringBuilder sb = new StringBuilder();
            String line = reader.readLine();
            while (line != null) {
                sb.append(line);
                line = reader.readLine();
            }
            JSONObject obj = new JSONObject(sb.toString());
            return obj;
        }
    }

    /**
     * Method to create a response using a JSON object.
     * @param he The HTTP exchange request and response
     * @param response The JSON object of the response
     */
    private void createResponse(HttpExchange he, JSONObject response) {
        try (OutputStream os = he.getResponseBody()) {
            String origin = he.getRequestHeaders().getFirst("Origin");
            he.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
            he.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, OPTIONS");
            he.getResponseHeaders().set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
            for (Pattern p: origins) {
                // Only allowed hosts are assigned
                if (p.matcher(origin).matches()) {
                    he.getResponseHeaders().set("Access-Control-Allow-Origin", origin);
                }
            }
            String mess = (response == null)? "" : response.toString();
            System.err.println(mess);
            he.sendResponseHeaders(200, (response == null)? 0 : mess.getBytes().length);
            if (response != null) {
                os.write(mess.getBytes());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Method to create a response of type error (the response is a HTTP 200)
     * which is a JSON object with "status":"error" and "errorMessage" set
     * with the parameter passed.
     * @param message The message of the error
     * @return A JSON object with status to error and the error response
     */
    private JSONObject createError(String message) {
        try {
            JSONObject obj = new JSONObject();
            obj.put("status", "error");
            obj.put("errorMessage", message);
            return obj;
        } catch (JSONException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Method to create a success response ("status":"success").
     * @return A JSON object with status set to success.
     */
    private JSONObject createSuccess() {
        try {
            JSONObject obj = new JSONObject();
            obj.put("status", "success");
            return obj;
        } catch (JSONException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Method that handles the isInitialized end-point. The method receives
     * no data and checks if the underlaying signer is initialized. The response
     * is a JSON object with four boolean properties: "initialized", 
     * "keyAccessNeeded", "storePasswordNeeded", "samePasswordForKeys".
     * @param he The HTTP exchange request and response
     */
    synchronized private void isInitialized(HttpExchange he) {
        try {
            if ("post".equalsIgnoreCase(he.getRequestMethod())) {
                JSONObject res = createSuccess();
                res.put("initialized", signer.isInitialized());
                res.put("keyAccessNeeded", signer.isKeyAccessNeeded());
                res.put("storePasswordNeeded", signer.isKeyStorePasswordNeeded());
                res.put("samePasswordForKeys", signer.useSamePasswordForKeys());
                createResponse(he, res);
            } else if ("options".equalsIgnoreCase(he.getRequestMethod())) {
                createResponse(he, null);
            }
        } catch (Exception e) {
            e.printStackTrace();
            createResponse(he, createError(e.getMessage()));
        }
    }
    
    /**
     * Method that initializes the repository. The method receives a JSON with
     * the "password" of the signer (if needed). The method responds with the 
     * same data than in the isInitialized method: "initialized", 
     * "keyAccessNeeded", "storePasswordNeeded", "samePasswordForKeys".
     * @param he The HTTP exchange request and response
     */
    synchronized private void initialize(HttpExchange he) {
        try {
            if ("post".equalsIgnoreCase(he.getRequestMethod())) {
                JSONObject obj = parseJSON(he);
                password = obj.has("password") ? obj.getString("password") : null;
                signer.initialize(password);
                JSONObject res = createSuccess();
                res.put("initialized", true);
                res.put("keyAccessNeeded", signer.isKeyAccessNeeded());
                res.put("storePasswordNeeded", signer.isKeyStorePasswordNeeded());
                res.put("samePasswordForKeys", signer.useSamePasswordForKeys());
                createResponse(he, res);
            } else if ("options".equalsIgnoreCase(he.getRequestMethod())) {
                createResponse(he, null);
            }
        } catch (Exception e) {
            e.printStackTrace();
            createResponse(he, createError(e.getMessage()));
        }
    }

    /**
     * This method returns the list of certificates that the signer has. The
     * method receives no input data and answers with an array of "certificates"
     * (each certificate has "alias", "subject", "issuer", "version", 
     * "serialNumber", "notAfter", "notBefore" and "usage").
     * @param he The HTTP exchange request and response
     */
    synchronized private void listCertificates(HttpExchange he) {
        try {
            if ("post".equalsIgnoreCase(he.getRequestMethod())) {
                if (signer.isInitialized()) {
                    Map<String, X509Certificate> certs = signer.getAllKeyCertificates();
                    JSONObject obj = createSuccess();
                    List<JSONObject> certificates = new ArrayList<>();
                    for (Map.Entry<String, X509Certificate> e : certs.entrySet()) {
                        JSONObject certInfo = new JSONObject();
                        certInfo.put("alias", e.getKey());
                        certInfo.put("subject", e.getValue().getSubjectDN());
                        certInfo.put("issuer", e.getValue().getIssuerDN());
                        certInfo.put("version", e.getValue().getVersion());
                        certInfo.put("serialNumber", e.getValue().getSerialNumber().longValue());
                        certInfo.put("notAfter", e.getValue().getNotAfter().getTime());
                        certInfo.put("notBefore", e.getValue().getNotBefore().getTime());
                        boolean[] keyUsage = e.getValue().getKeyUsage();
                        if (keyUsage != null) {
                            List<String> usage = new ArrayList<>();
                            for (int i = 0; i < keyUsage.length; i++) {
                                usage.add(KEY_USAGE[i]);
                            }
                            certInfo.put("usage", usage);
                        }
                        certificates.add(certInfo);
                    }
                    obj.put("certificates", certificates);
                    createResponse(he, obj);
                } else {
                    createResponse(he, createError("Signer not initialized"));
                }
            } else if ("options".equalsIgnoreCase(he.getRequestMethod())) {
                createResponse(he, null);
            }
        } catch (Exception e) {
            e.printStackTrace();
            createResponse(he, createError(e.getMessage()));
        }
    }

    /**
     * Sign operation. The method receives the following input: "data" - the data
     * to sign in base64; "type" - the type of signature to execute (SHA1withRSA
     * for example); "alias" - the certificate to use; "password" - the password
     * for the ney (if needed). The response has only a "sign" attribute
     * with the base64 signature.
     * @param he The HTTP exchange request and response
     */
    synchronized private void sign(HttpExchange he) {
        try {
            if ("post".equalsIgnoreCase(he.getRequestMethod())) {
                if (signer.isInitialized()) {
                    JSONObject obj = parseJSON(he);
                    String base64Data = obj.getString("data");
                    byte[] data = Base64.getDecoder().decode(base64Data);
                    byte[] sign = signer.sign(data, obj.getString("type"), obj.getString("alias"),
                            obj.has("password") ? obj.getString("password") : null);
                    JSONObject response = createSuccess();
                    response.put("sign", Base64.getEncoder().encodeToString(sign));
                    createResponse(he, response);
                } else {
                    createResponse(he, createError("Signer not initialized"));
                }
            } else if ("options".equalsIgnoreCase(he.getRequestMethod())) {
                createResponse(he, null);
            }
        } catch (Exception e) {
            e.printStackTrace();
            createResponse(he, createError(e.getMessage()));
        }
    }
    
    /**
     * Verify a signature operation. The method receives the data: "data" - 
     * the data previously signed; "type" - the type of signature (SHA1withRSA
     * for example); "alias" - the certificate used; "sign" - the signature
     * in base64. The response has only a "sign" attribute
     * @param he The HTTP exchange request and response
     */
    synchronized private void verify(HttpExchange he) {
        try {
            if ("post".equalsIgnoreCase(he.getRequestMethod())) {
                if (signer.isInitialized()) {
                    JSONObject obj = parseJSON(he);
                    String base64Data = obj.getString("data");
                    byte[] data = Base64.getDecoder().decode(base64Data);
                    String sign64 = obj.getString("sign");
                    byte[] sign = Base64.getDecoder().decode(sign64);
                    boolean verify = signer.verify(data, sign, obj.getString("type"), obj.getString("alias"));
                    JSONObject response = createSuccess();
                    response.put("verify", verify);
                    createResponse(he, response);
                } else {
                    createResponse(he, createError("Signer not initialized"));
                }
            } else if ("options".equalsIgnoreCase(he.getRequestMethod())) {
                createResponse(he, null);
            }
        } catch (Exception e) {
            e.printStackTrace();
            createResponse(he, createError(e.getMessage()));
        }
    }
    
    /**
     * Auxiliary method to create a list of patterns from the property that
     * handle the allowed domains.
     * @param props The configuration properties
     */
    private void createMatchers(Properties props) {
        String expsProp = props.getProperty(DAEMON_ORIGIN_REGEXP_PROP);
        String[] exps = expsProp.split(",");
        List<Pattern> list = new ArrayList<>(exps.length);
        for (String exp: exps) {
            exp = exp.trim();
            list.add(Pattern.compile(exp));
        }
        origins = list.toArray(new Pattern[0]);
    }

    /**
     * Constructor of the Daemon. The properties should contain all the
     * properties needed by the daemon.
     * @param props The configuration properties
     * @throws Exception Some error
     */
    public SignerDaemon(Properties props) throws Exception {
        String clazzName = props.getProperty(DAEMON_CLAZZ_PROP);
        Class clazz = Class.forName(clazzName);
        signer = (Signer) clazz.newInstance();
        signer.setProperties(props);
        String path = props.getProperty(DAEMON_PATH_PROP, "/signer");
        int port = Integer.parseInt(props.getProperty(DAEMON_PORT_PROP, "8000"));
        createMatchers(props);
        server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), port), 1024);
        server.createContext(path, (HttpExchange he) -> {
            System.err.println("Receiving " + he.getRequestMethod() + " -> " + he.getRequestURI().getPath());
            if (he.getRequestURI().getPath().endsWith("/initialize")) {
                initialize(he);
            } else if (he.getRequestURI().getPath().endsWith("/isInitialized")) {
                isInitialized(he);
            } else if (he.getRequestURI().getPath().endsWith("/listCertificates")) {
                listCertificates(he);
            } else if (he.getRequestURI().getPath().endsWith("/sign")) {
                sign(he);
            } else if (he.getRequestURI().getPath().endsWith("/verify")) {
                verify(he);
            } else {
                createResponse(he, createError("Operation not supported"));
            }
        });
        server.setExecutor(null);
    }

    /**
     * Just start the HTTP server.
     */
    @Override
    public void run() {
        server.start();
    }

    /**
     * Stops the http server.
     * @param seconds 
     */
    public void shutdown(int seconds) {
        server.stop(seconds);
    }

    /**
     * Main method to start the daemon. Only one argument is needed and it
     * should be the configuration properties file.
     * @param args The arguments (the configuration file should be passed)
     * @throws Exception Some error
     */
    static public void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("The properties configuration file is needed");
        }
        File propFile = new File(args[0]);
        if (!propFile.exists() || propFile.isDirectory() || !propFile.canRead()) {
            throw new IllegalArgumentException("Invalid file");
        }
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(propFile)) {
            props.load(fis);
        }
        SignerDaemon daemon = new SignerDaemon(props);
        daemon.start();
    }

}

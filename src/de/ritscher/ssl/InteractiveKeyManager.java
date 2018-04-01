package de.ritscher.ssl;

import android.app.Activity;
import android.app.Application;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.security.KeyChain;
import android.util.Log;
import android.util.SparseArray;
import android.widget.Toast;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509KeyManager;

public class InteractiveKeyManager implements X509KeyManager {
    private final static String TAG = "InteractiveKeyManager";

    final static String DECISION_INTENT = "de.ritscher.ssl.DECISION";
    final static String DECISION_INTENT_ID = DECISION_INTENT + ".decisionId";
    final static String DECISION_INTENT_CERT = DECISION_INTENT + ".cert";
    final static String DECISION_INTENT_HOSTNAME = DECISION_INTENT + ".hostname";
    final static String DECISION_INTENT_PORT = DECISION_INTENT + ".port";
    private final static int NOTIFICATION_ID = 101319;

    private static String KEYSTORE_DIR = "KeyStore";
    private static String KEYSTORE_FILE = "KeyManager.bks";
    private static String ALIASMAPPING_FILE = "KeyManager.properties";
    private static String KEYSTORE_PASSWORD = "l^=alsk22:,.-32ß091HJK";
    private static String KEYSTORE_ALIAS = "KS_";
    private static String KEYCHAIN_ALIAS = "KC_";

    private File keyStoreFile;
    private File aliasMappingFile;
    private Properties aliasMapping;
    private KeyStore appKeyStore;

    final private Context context;
    private Handler masterHandler;
    private Activity foregroundAct;
    private NotificationManager notificationManager;

    private static InteractiveKeyManager instance = null;

    private static int decisionId = 0;
    final private static SparseArray<IKMDecision> openDecisions = new SparseArray<IKMDecision>();

    private Handler toastHandler;

    synchronized public static InteractiveKeyManager getInstance(Context context) {
        if (instance == null) {
            instance = new InteractiveKeyManager(context);
        }
        return instance;
    }

    InteractiveKeyManager(Context context) {
        this.context = context;
        init();
    }

    void init() {
        Log.d(TAG, "init()");
        masterHandler = new Handler(context.getMainLooper());
        notificationManager = (NotificationManager) context.getSystemService(Context
                .NOTIFICATION_SERVICE);

        Application app;
        if (context instanceof Application) {
            app = (Application) context;
        } else if (context instanceof Service) {
            app = ((Service) context).getApplication();
        } else if (context instanceof Activity) {
            app = ((Activity) context).getApplication();
        } else {
            throw new ClassCastException("InteractiveKeyManager context must be either Activity " +
                    "or Service!");
        }

        File dir = app.getDir(KEYSTORE_DIR, Context.MODE_PRIVATE);
        keyStoreFile = new File(dir + File.separator + KEYSTORE_FILE);
        appKeyStore = loadKeyStore(keyStoreFile, KEYSTORE_PASSWORD, true);
        try {
            Log.d(TAG, "keystore aliases = " + Arrays.toString(Collections.list(appKeyStore.aliases()).toArray()));
        } catch (KeyStoreException e) {
            Log.e(TAG, "Error reading keystore", e);
        }
        aliasMappingFile = new File(dir + File.separator + ALIASMAPPING_FILE);
        aliasMapping = loadProperties(aliasMappingFile, true);
        Log.d(TAG, "keychain aliases = " + Arrays.toString(aliasMapping.keySet().toArray()));

        toastHandler = new Handler(Looper.getMainLooper()) {
            @Override
            public void handleMessage(Message message) {
                Toast.makeText(context, (String) message.obj, Toast.LENGTH_SHORT).show();
            }
        };
    }

    private KeyStore loadKeyStore(File file, String password, boolean createNew) {
        KeyStore ks;
        Log.d(TAG, "loadKeyStore(" + file + ", createNew=" + createNew + ")");
        try {
            //ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks = KeyStore.getInstance("BKS");
        } catch (KeyStoreException e) {
            Log.e(TAG, "loadKeyStore()", e);
            return null;
        }
        try {
            ks.load(null, null);
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            Log.e(TAG, "loadKeyStore()", e);
        }
        if (!file.exists()) {
            if (createNew) {
                Log.d(TAG, "loadKeyStore(" + file + ") - create new keystore");
                saveKeyStore(file, ks);
                return ks;
            } else {
                Log.e(TAG, "loadKeyStore(" + file + ") - file does not exist");
                toastHandler.obtainMessage(0, context.getString(R.string.ikm_found_keystore)).sendToTarget();
                return null;
            }
        }
        InputStream is = null;
        try {
            is = new java.io.FileInputStream(file);
            ks.load(is, password.toCharArray());
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            Log.w(TAG, "loadKeyStore(" + keyStoreFile + ") - exception loading file key store", e);
            toastHandler.obtainMessage(0, context.getString(R.string.ikm_load_keystore)).sendToTarget();
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    Log.w(TAG, "loadKeyStore(" + keyStoreFile + ") - exception closing file key " +
                            "store hostnameInput stream", e);
                }
            }
        }
        Log.d(TAG, "loadKeyStore(" + keyStoreFile + ") - success");
        return ks;
    }

    private void saveKeyStore(File file, KeyStore ks) {
        // store KeyStore to file
        Log.d(TAG, "saveKeyStore(" + file + ")");
        java.io.FileOutputStream fos = null;
        try {
            fos = new java.io.FileOutputStream(file);
            ks.store(fos, KEYSTORE_PASSWORD.toCharArray());
        } catch (Exception e) {
            Log.e(TAG, "saveKeyStore(" + keyStoreFile + ")", e);
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    Log.e(TAG, "saveKeyStore(" + keyStoreFile + ")", e);
                }
            }
        }
    }

    private Properties loadProperties(File file, boolean createNew) {
        Log.d(TAG, "loadProperties(" + file + ", createNew=" + createNew + ")");
        Properties props = new Properties();
        FileReader reader = null;
        if (!file.exists()) {
            if (createNew) {
                Log.d(TAG, "loadProperties(" + file + ") - create new file");
                saveProperties(file, props);
                return props;
            } else {
                Log.e(TAG, "loadProperties(" + file + ") - file does not exist");
                return null;
            }
        }
        try {
            reader = new FileReader(file);
            props.load(reader);
        } catch (IOException e) {
            Log.e(TAG, "loadProperties(" + file + ")", e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    Log.w(TAG, "loadProperties(" + file + ")", e);
                }
            }
        }
        return props;
    }

    private boolean saveProperties(File file, Properties props) {
        Log.d(TAG, "saveProperties(" + file + ")");
        FileWriter writer = null;
        try {
            writer = new FileWriter(file);
            props.store(writer, "Generated by InteractiveKeyManager");
            return true;
        } catch (IOException e) {
            Log.e(TAG, "saveProperties(" + file + ")", e);
            return false;
        } finally {
            if (writer != null) {
                try {
                    writer.close();
                } catch (IOException e) {
                    Log.w(TAG, "saveProperties(" + file + ")", e);
                }
            }
        }
    }

    private X509KeyManager getKeyManager(KeyStore ks) {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
                    .getDefaultAlgorithm());
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());
            for (KeyManager km : kmf.getKeyManagers()) {
                if (km instanceof X509KeyManager) {
                    Log.d(TAG, "Using user-specified keys with aliases "
                            + Arrays.toString(Collections.list(ks.aliases()).toArray()) + ".");
                    return (X509KeyManager) km;
                }
            }
        } catch (Exception e) {
            // Here, we are covering up errors. It might be more useful
            // however to throw them out of the constructor so the
            // embedding app knows something went wrong.
            Log.e(TAG, "getKeyManager(" + ks + ")", e);
        }
        return null;
    }

    private void storeKey(String alias, PrivateKey key, Certificate[] chain) {
        Log.d(TAG, "storeKey(" + alias + ", "
                + (chain[0] instanceof X509Certificate ? ((X509Certificate) chain[0])
                .getSubjectDN() : chain[0]) + ")");
        if (key == null) {
            Log.e(TAG, "storekey(" + alias + ", " + Arrays.toString(chain) + "): key is null");
            return;
        }
        try {
            KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection
                    (KEYSTORE_PASSWORD.toCharArray());
            KeyStore.PrivateKeyEntry entry;
            entry = new KeyStore.PrivateKeyEntry(key, chain);
            appKeyStore.setEntry(alias, entry, protection);
        } catch (KeyStoreException e) {
            Log.e(TAG, "storeKey(" + alias + ", " + Arrays.toString(chain) + ")", e);
            return;
        }
        saveKeyStore(keyStoreFile, appKeyStore);
    }

    private String constructAlias(String type, String originalAlias, String hostname, Integer
            port) {
        StringBuilder alias = new StringBuilder();
        alias.append(type);
        alias.append(originalAlias);
        if (hostname != null) {
            alias.append(":");
            alias.append(hostname);
            if (port != null) {
                alias.append(":");
                alias.append(port);
            }
        }
        return alias.toString();
    }

    public String storeKey(PrivateKey key, Certificate[] chain, String hostname, Integer port) {
        String alias = constructAlias(KEYSTORE_ALIAS, Integer.toHexString(key.hashCode()),
                hostname, port);
        storeKey(alias, key, chain);
        PrivateKey privateKey = getPrivateKey(alias);
        return alias;
    }

    public List<String> addFromKeyStore(String fileName, String storePassword, String[]
            keyPasswords, String hostname, Integer port) {
        List<String> aliases = new LinkedList<String>();
        Log.d(TAG, "addFromKeyStore(" + fileName + ")");
        KeyStore ks = loadKeyStore(new File(fileName), storePassword, false);
        try {
            if (ks == null || !ks.aliases().hasMoreElements()) {
                Log.w(TAG, "addFromKeyStore - no aliases in keystore");
                return aliases;
            }
        } catch (KeyStoreException e) {
            Log.e(TAG, "Error reading keystore", e);
            return aliases;
        }
        try {
            for (Enumeration<String> keyStoreAliases = ks.aliases(); keyStoreAliases
                    .hasMoreElements(); ) {
                String alias = keyStoreAliases.nextElement();
                Log.d(TAG, "addFromKeyStore(" + fileName + "): found alias " + alias);
                if (!ks.isKeyEntry(alias)) {
                    continue;
                }
                boolean loadedKey = false;
                for (String password : keyPasswords) {
                    try {
                        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(
                                password.toCharArray());
                        KeyStore.Entry entry = ks.getEntry(alias, protection);
                        if (entry instanceof PrivateKeyEntry) {
                            aliases.add(storeKey(((PrivateKeyEntry) entry).getPrivateKey(),
                                    ((PrivateKeyEntry) entry).getCertificateChain(), hostname,
                                    port));
                            loadedKey = true;
                        }
                        break;
                    } catch (KeyStoreException | NoSuchAlgorithmException |
                            UnrecoverableEntryException e) {
                        Log.d(TAG, "Could not load key '" + alias + "'", e);
                    }
                }
                if (!loadedKey) {
                    Log.w(TAG, "Error loading key '" + alias + "'");
                    toastHandler.obtainMessage(0, context.getString(R.string.ikm_load_key) + alias).sendToTarget();
                }
            }
        } catch (KeyStoreException e) {
            Log.e(TAG, "Error reading keystore", e);
        }
        return aliases;
    }

    public String addKeyChainAlias(String keyChainAlias, String hostname, Integer port) {
        /*
         * Access must have been granted earlier by invokation of
		 * KeyChain.choosePrivateKeyAlias
		 */
        Log.d(TAG, "addKeyChainAlias(" + keyChainAlias + ", " + hostname + ", " + port + ")");
        String alias = constructAlias(KEYCHAIN_ALIAS, keyChainAlias, hostname, port);
        aliasMapping.setProperty(alias, "");
        saveProperties(aliasMappingFile, aliasMapping);
        Log.d(TAG, "keychain aliases = " + Arrays.toString(aliasMapping.keySet().toArray()));
        return alias;
    }

    private String checkAliasHostnamePort(String alias, String hostname, int port) {
        String[] aliasFields = alias.split(":");
        if (aliasFields.length >= 4) {
            Log.e(TAG, "checkAliasHostnamePort: " + alias + " is an invalid alias");
            return null;
        }
        if (aliasFields.length >= 2) {
            InetAddress hostaddress = null, aliasaddress = null;
            try {
                hostaddress = InetAddress.getByName(hostname);
            } catch (UnknownHostException e) {
                Log.e(TAG, "checkAliasHostName: error resolving " + hostname);
            }
            try {
                aliasaddress = InetAddress.getByName(aliasFields[1]);
            } catch (UnknownHostException e) {
                Log.e(TAG, "checkAliasHostName: error resolving " + aliasaddress);
            }
            if (aliasaddress == null || hostaddress == null || !aliasaddress.equals(hostaddress)) {
                Log.d(TAG, "checkAliasHostnamePort: " + alias + " stored for hostname " +
                        aliasFields[1] + "(" + "), not " + hostname + "(" + ")");
                return null;
            }
        }
        if (aliasFields.length >= 3) {
            if (Integer.valueOf(aliasFields[2]).compareTo(port) != 0) {
                Log.d(TAG, "getAliases: " + alias + " stored for port " + aliasFields[2] + ", not "
                        + port);
                return null;
            }
        }
        return aliasFields[0];
    }

    private List<String> getKeyChainAliases(String hostname, int port) {
        List<String> aliases = new LinkedList<String>();
        Log.d(TAG, "keychain aliases = " + Arrays.toString(aliasMapping.keySet().toArray()));
        for (Object key : aliasMapping.keySet()) {
            if (((String) key).startsWith(KEYCHAIN_ALIAS)) {
                if (checkAliasHostnamePort((String) key, hostname, port) != null) {
                    aliases.add(((String) key));
                }
            }
        }
        return aliases;
    }

    private String[] getAliases(String[] keyTypes, Principal[] issuers, String hostname, int port) {
        List<String> validAliases = new LinkedList<String>();
        try {
            Log.d(TAG, "keystore aliases = " + Arrays.toString(Collections.list(appKeyStore
                    .aliases()).toArray()));
            for (Enumeration<String> aliases = appKeyStore.aliases(); aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();
                if (checkAliasHostnamePort(alias, hostname, port) == null) {
                    continue;
                }
                if (!(appKeyStore.getCertificate(alias) instanceof X509Certificate)) {
                    Log.d(TAG, "getAliases: " + alias + " not an X509Certificate");
                    continue;
                }
                X509Certificate certificate = (X509Certificate) appKeyStore.getCertificate(alias);
                if (keyTypes != null) {
                    boolean validType = false;
                    for (String keyType : keyTypes) {
                        if (certificate.getPublicKey().getAlgorithm().equals(keyType)) {
                            validType = true;
                            break;
                        }
                    }
                    if (!validType) {
                        Log.d(TAG, "getAliases: " + alias + " has keytype " + certificate
                                .getPublicKey().getAlgorithm()
                                + ", not " + Arrays.toString(keyTypes));
                        continue;
                    }
                }
                if (issuers != null) {
                    boolean validIssuer = false;
                    for (Principal issuer : issuers) {
                        if (issuer.equals(certificate.getIssuerX500Principal())) {
                            validIssuer = true;
                        }
                    }
                    if (!validIssuer) {
                        Log.d(TAG, "getAliases: " + alias + " has issuer " + certificate
                                .getIssuerX500Principal() + ", not "
                                + Arrays.toString(issuers));
                        continue;
                    }
                }
                validAliases.add(alias);
            }
        } catch (KeyStoreException e) {
            Log.e(TAG, "getAliases(" + Arrays.toString(keyTypes) + ", " + Arrays.toString
                    (issuers) + ", " + hostname
                    + ", " + port + ")", e);
            toastHandler.obtainMessage(0, context.getString(R.string.ikm_read_keystore)).sendToTarget();
        }
        validAliases.addAll(getKeyChainAliases(hostname, port));
        Log.d(TAG, "getAliases(" + Arrays.toString(keyTypes) + ", " + Arrays.toString(issuers) +
                ", " + hostname + ", " + port + ") = " + Arrays.toString
                (validAliases.toArray()));
        return validAliases.toArray(new String[0]);
    }

    private String chooseAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        if (!(socket instanceof SSLSocket)) {
            Log.e(TAG, "chooseAlias: " + socket + " is of class " + socket.getClass().getName() +
                    ", expected " + SSLSocket.class.getName());
            return null;
        }
        String hostname = socket.getInetAddress().getCanonicalHostName();
        int port = socket.getPort();
        String[] validAliases = getAliases(keyTypes, issuers, hostname, port);
        if (validAliases != null && validAliases.length > 0) {
            Log.d(TAG, "chooseAlias(" + Arrays.toString(keyTypes) + ", " + Arrays.toString(issuers)
                    + ", " + hostname + ", " + port + ") = " + validAliases[0]);
            return validAliases[0];
        } else {
            Log.d(TAG, "chooseAlias: no alias for server " + hostname + ":" + port + " found, " +
                    "prompting user...");
            SSLSocket sslSocket = (SSLSocket) socket;
            /*Certificate[] chain = null;
            try {
                chain = sslSocket.getHandshakeSession().getPeerCertificates();
            } catch (SSLPeerUnverifiedException e) {
                Log.e(TAG, "chooseAlias: Could not get peer certificate chain.", e);
            }*/
            Log.d(TAG, "Run interactClientCert");
//            try {
//                Log.d(TAG, "Session = " + sslSocket.getSession());
//            } catch (Throwable e) {
//                Log.e(TAG,"Session", e);
//            }
//            try {
//                Log.d(TAG, "PeerPrincipal=" + sslSocket.getSession().getPeerPrincipal().toString());
//            } catch (Throwable e) {
//                Log.e(TAG,"PeerPrincipal", e);
//            }
//            try {
//                Log.d(TAG, "PeerCertificates=" + sslSocket.getSession().getPeerCertificates()[0].toString());
//            } catch (Throwable e) {
//                Log.e(TAG,"PeerCertificates", e);
//            }
//            try {
//                Log.d(TAG, "PeerHost=" + sslSocket.getSession().getPeerHost());
//            } catch (Throwable e) {
//                Log.e(TAG,"PeerHost", e);
//            }
            IKMDecision decision = interactClientCert(null, hostname, port);
            Log.d(TAG, "decision=" + decision.state);
            switch (decision.state) {
                case IKMDecision.DECISION_FILE:
                    List<String> aliases = addFromKeyStore(decision.param, "password", new
                                    String[]{"password"}, decision.hostname, decision.port);
                    if (aliases != null && aliases.size() > 0) {
                        Log.d(TAG, "Use alias " + aliases.get(0));
                        return aliases.get(0);
                    } else {
                        return null;
                    }
                case IKMDecision.DECISION_KEYCHAIN:
                    String alias = addKeyChainAlias(decision.param, decision.hostname, decision.port);
                    Log.d(TAG, "Use alias " + alias);
                    return alias;
                default:
                    return null;
            }
        }
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        Log.d(TAG, "chooseClientAlias(" + Arrays.toString(keyTypes) + ", " + Arrays.toString
                (issuers) + ")");
        try {
            return chooseAlias(keyTypes, issuers, socket);
        } catch (Throwable t) {
            Log.e(TAG, "chooseClientAlias", t);
            return null;
        }
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        Log.d(TAG, "chooseServerAlias(" + keyType + ", " + Arrays.toString(issuers) + ")");
        return chooseAlias(new String[]{keyType}, issuers, socket);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        Log.d(TAG, "getClientAliases(" + keyType + ", " + Arrays.toString(issuers) + ")");
        return getAliases(new String[]{keyType}, issuers, null, 0);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        Log.d(TAG, "getServerAliases(" + keyType + ", " + Arrays.toString(issuers) + ")");
        return getAliases(new String[]{keyType}, issuers, null, 0);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (alias.startsWith(KEYCHAIN_ALIAS)) {
            Log.d(TAG, "getCertificateChain(" + alias + ") - keychain");
            try {
                return KeyChain.getCertificateChain(context, alias.substring(KEYCHAIN_ALIAS
                        .length()));
            } catch (Exception e) {
                Log.e(TAG, "getCertificateChain(" + alias + ")", e);
                toastHandler.obtainMessage(0, context.getString(R.string.ikm_keychain)).sendToTarget();
                return null;
            }
        } else { /* for backward compability also accept aliases not beginning with KEYSTORE_ALIAS */
            Log.d(TAG, "getCertificateChain(" + alias + ") - keystore");
            List<X509Certificate> certificates = new LinkedList<X509Certificate>();
            try {
                for (Certificate certificate : appKeyStore.getCertificateChain(alias)) {
                    if (certificate instanceof X509Certificate) {
                        certificates.add((X509Certificate) certificate);
                    }
                }
            } catch (KeyStoreException e) {
                Log.e(TAG, "getCertificateChain(" + alias + ")", e);
                toastHandler.obtainMessage(0, context.getString(R.string.ikm_read_keystore)).sendToTarget();
            }
            return certificates.toArray(new X509Certificate[0]);
        }
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        if (alias.startsWith(KEYCHAIN_ALIAS)) {
            Log.d(TAG, "getPrivateKey(" + alias + ") - keychain");
            try {
                PrivateKey key = KeyChain.getPrivateKey(context, alias.substring(KEYCHAIN_ALIAS.length()));
                if (key == null) {
                    Log.e(TAG, "KeyChain.getPrivateKey(" + alias.substring(KEYCHAIN_ALIAS.length()) + ") - " + key + " is not a private key");
                }
                return key;
            } catch (Exception e) {
                Log.e(TAG, "KeyChain.getPrivateKey(" + alias + ")", e);
                toastHandler.obtainMessage(0, context.getString(R.string.ikm_keychain)).sendToTarget();
                return null;
            }
        } else { /* for backward compability also accept aliases not beginning with KEYSTORE_ALIAS */
            Log.d(TAG, "getPrivateKey(" + alias + ") - keystore");
            try {
                Key key = appKeyStore.getKey(alias, KEYSTORE_PASSWORD.toCharArray());
                if (key instanceof PrivateKey) {
                    return (PrivateKey) key;
                } else {
                    Log.e(TAG, "appKeyStore.getKey(" + alias + ") - " + key + " is not a private key");
                    return null;
                }
            } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
                Log.e(TAG, "appKeyStore.getKey(" + alias + ")", e);
                toastHandler.obtainMessage(0, "Error reading keystore").sendToTarget();
                return null;
            }
        }
    }

    private static int createDecisionId(IKMDecision decision) {
        int id;
        synchronized (openDecisions) {
            id = decisionId;
            openDecisions.put(id, decision);
            decisionId += 1;
        }
        return id;
    }

    private static String hexString(byte[] data) {
        StringBuilder si = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            si.append(String.format("%02x", data[i]));
            if (i < data.length - 1)
                si.append(":");
        }
        return si.toString();
    }

    private static String certHash(final X509Certificate cert, String digest) {
        try {
            MessageDigest md = MessageDigest.getInstance(digest);
            md.update(cert.getEncoded());
            return hexString(md.digest());
        } catch (java.security.cert.CertificateEncodingException e) {
            return e.getMessage();
        } catch (java.security.NoSuchAlgorithmException e) {
            return e.getMessage();
        }
    }

    private static void certDetails(StringBuilder si, X509Certificate c) {
        SimpleDateFormat validityDateFormater = new SimpleDateFormat("yyyy-MM-dd");
        si.append("\n");
        si.append(c.getSubjectDN().toString());
        si.append("\n");
        si.append(validityDateFormater.format(c.getNotBefore()));
        si.append(" - ");
        si.append(validityDateFormater.format(c.getNotAfter()));
        si.append("\nSHA-256: ");
        si.append(certHash(c, "SHA-256"));
        si.append("\nSHA-1: ");
        si.append(certHash(c, "SHA-1"));
        si.append("\nSigned by: ");
        si.append(c.getIssuerDN().toString());
        si.append("\n");
    }

    private String certMessage(String hostname, int port, Certificate chain[]) {
        Log.d(TAG, "certMessage(" + hostname + ", " + port + ")");
        StringBuilder si = new StringBuilder();
        si.append(hostname);
        si.append(":");
        si.append(port);
        si.append(context.getString(R.string.ikm_client_cert));
        if (chain != null) {
            si.append("\n\n");
            si.append(context.getString(R.string.ikm_cert_details));
            for (Certificate c : chain) {
                if (c instanceof X509Certificate) {
                    certDetails(si, (X509Certificate) c);
                } else {
                    si.append("Unknown certificate: ");
                    si.append(c.toString());
                }
            }
        }
        return si.toString();
    }

    /**
     * Binds an Activity to the IKM for displaying the query decisionDialog.
     * <p>
     * This is useful if your connection is run from a service that is
     * triggered by user interaction -- in such cases the activity is
     * visible and the user tends to ignore the service notification.
     * <p>
     * You should never have a hidden activity bound to IKM! Use this
     * function in onResume() and @see unbindDisplayActivity in onPause().
     *
     * @param act Activity to be bound
     */
    private void bindDisplayActivity(Activity act) {
        foregroundAct = act;
    }

    /**
     * Removes an Activity from the IKM display stack.
     * <p>
     * Always call this function when the Activity added with
     * {@link #bindDisplayActivity(Activity)} is hidden.
     *
     * @param act Activity to be unbound
     */
    private void unbindDisplayActivity(Activity act) {
        // do not remove if it was overridden by a different activity
        if (foregroundAct == act)
            foregroundAct = null;
    }

    /**
     * Reflectively call
     * <code>Notification.setLatestEventInfo(Context, CharSequence, CharSequence, PendingIntent)</code>
     * since it was remove in Android API level 23.
     *
     * @param notification
     * @param context
     * @param mtmNotification
     * @param certName
     * @param call
     */
    private static void setLatestEventInfoReflective(Notification notification,
                                                     Context context, CharSequence mtmNotification,
                                                     CharSequence certName, PendingIntent call) {
        Method setLatestEventInfo;
        try {
            setLatestEventInfo = notification.getClass().getMethod(
                    "setLatestEventInfo", Context.class, CharSequence.class,
                    CharSequence.class, PendingIntent.class);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(e);
        }

        try {
            setLatestEventInfo.invoke(notification, context, mtmNotification,
                    certName, call);
        } catch (IllegalAccessException | IllegalArgumentException
                | InvocationTargetException e) {
            throw new IllegalStateException(e);
        }
    }

    private void startActivityNotification(Intent intent, int decisionId, String message) {
        Notification notification;
        final PendingIntent call = PendingIntent.getActivity(context, 0, intent, 0);
        final String notificationTitle = context.getString(R.string.ikm_notification);
        final long currentMillis = System.currentTimeMillis();
        final Context ctx = context.getApplicationContext();

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.HONEYCOMB) {
            @SuppressWarnings("deprecation")
            // Use an extra identifier for the legacy build notification, so
                    // that we suppress the deprecation warning. We will latter assign
                    // this to the correct identifier.
                    Notification n = new Notification(android.R.drawable.ic_lock_lock,
                    notificationTitle, currentMillis);
            setLatestEventInfoReflective(n, ctx, notificationTitle, message, call);
            n.flags |= Notification.FLAG_AUTO_CANCEL;
            notification = n;
        } else {
            notification = new Notification.Builder(ctx)
                    .setContentTitle(notificationTitle)
                    .setContentText(message)
                    .setTicker(message)
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setWhen(currentMillis)
                    .setContentIntent(call)
                    .setAutoCancel(true)
                    .build();
        }

        notificationManager.notify(NOTIFICATION_ID + decisionId, notification);
    }

    /**
     * Returns the top-most entry of the activity stack.
     *
     * @return the Context of the currently bound UI or the master context if none is bound
     */
    private Context getUI() {
        return (foregroundAct != null) ? foregroundAct : context;
    }

    private IKMDecision interactClientCert(Certificate[] chain, final String hostname, final int
            port) {
        Log.d(TAG, "interactClientCert(" + Arrays.toString(chain) + ", " + hostname + ", " + port
                + ")");
        final String message = certMessage(hostname, port, chain);
        IKMDecision decision = new IKMDecision();
        final int id = createDecisionId(decision);

        masterHandler.post(new Runnable() {
            public void run() {
                Intent ni = new Intent(context, SelectKeyStoreActivity.class);
                ni.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                ni.setData(Uri.parse(SelectKeyStoreActivity.class.getName() + "/" + id));
                ni.putExtra(DECISION_INTENT_ID, id);
                ni.putExtra(DECISION_INTENT_CERT, message);
                ni.putExtra(DECISION_INTENT_HOSTNAME, hostname);
                ni.putExtra(DECISION_INTENT_PORT, port);

                // we try to directly start the activity and fall back to making a notification
                try {
                    getUI().startActivity(ni);
                } catch (Exception e) {
                    Log.d(TAG, "interactClientCert: startActivity(SelectKeyStoreActivity)", e);
                    startActivityNotification(ni, id, message);
                }
            }
        });

        Log.d(TAG, "interactClientCert: openDecisions = " + openDecisions + ", waiting on " + id);
        try {
            synchronized (decision) {
                decision.wait();
            }
        } catch (InterruptedException e) {
            Log.d(TAG, "interactClientCert: InterruptedException", e);
        }
        Log.d(TAG, "interactClientCert: finished wait on " + id + ": state=" + decision.state +
                ", param=" + decision.state);
        return decision;
    }

    protected static void interactResult(int decisionId, int state, String param, String
            hostname, Integer port) {
        IKMDecision decision;
        Log.d(TAG, "interactResult(" + decisionId + ", " + param + ", " + param + ", " + hostname
                + ", " + port);
        synchronized (openDecisions) {
            decision = openDecisions.get(decisionId);
            openDecisions.remove(decisionId);
        }
        if (decision == null) {
            Log.e(TAG, "interactResult: aborting due to stale decision reference!");
            return;
        }
        synchronized (decision) {
            decision.state = state;
            decision.param = param;
            decision.hostname = hostname;
            decision.port = port;
            decision.notify();
        }
    }
}

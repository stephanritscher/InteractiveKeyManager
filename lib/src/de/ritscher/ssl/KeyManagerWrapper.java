package de.ritscher.ssl;

import android.util.Log;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;


public class KeyManagerWrapper extends X509ExtendedKeyManager { // TODO: Currently unused; optionally wrap key manager for debugging
    private final static String TAG = "KeyManagerWrapper";
    private final X509KeyManager km;

    public KeyManagerWrapper(X509KeyManager km) {
        this.km = km;
    }

    public static KeyManager[] wrapKeyManagers(KeyManager[] kms) {
        KeyManager[] newkms = new KeyManager[kms.length];
        for (int i = 0; i < kms.length; i++) {
            if (kms[i] instanceof X509KeyManager) {
                Log.d(TAG, "Wrap key manager of " + kms[i].getClass());
                newkms[i] = new KeyManagerWrapper((X509KeyManager) kms[i]);
            } else {
                Log.d(TAG, "Don't wrap key manager of " + kms[i].getClass());
                newkms[i] = kms[i];
            }
        }
        return newkms;
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        if (km instanceof X509ExtendedKeyManager) {
            String alias = ((X509ExtendedKeyManager) km).chooseEngineClientAlias(keyType, issuers, engine);
            if (alias != null) {
                Log.d(TAG, "Choose default client alias " + alias + " for key types " + Arrays.toString(keyType) + " and issuers " + Arrays.toString(issuers));
                return alias;
            }
        }
        Log.d(TAG, "Choose client alias  for key types " + Arrays.toString(keyType) + " and issuers " + Arrays.toString(issuers));
        return "nashi";
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        if (km instanceof X509ExtendedKeyManager) {
            String alias = ((X509ExtendedKeyManager) km).chooseEngineServerAlias(keyType, issuers, engine);
            if (alias != null) {
                Log.d(TAG, "Choose default server alias " + alias + " for key types " + keyType + " and issuers " + Arrays.toString(issuers));
                return alias;
            }
        }
        Log.d(TAG, "Choose server alias null for key types " + keyType + " and issuers " + Arrays.toString(issuers));
        return null;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        String alias = km.chooseClientAlias(keyType, issuers, socket);
        if (alias != null) {
            Log.d(TAG, "Choose default client alias " + alias + " for key types " + Arrays.toString(keyType) + " and issuers " + Arrays.toString(issuers));
            return alias;
        }
        for (String kt : keyType) {
            String[] aliases = getClientAliases(kt, issuers);
            if (aliases != null && aliases.length > 0) {
                Log.d(TAG, "Choose client alias " + aliases[0] + " for key type " + kt + " and issuers " + Arrays.toString(issuers));
                return aliases[0];
            }
        }
        Log.d(TAG, "Choose client alias null for key types " + Arrays.toString(keyType) + " and issuers " + Arrays.toString(issuers));
        return null;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        String alias = km.chooseServerAlias(keyType, issuers, socket);
        if (alias != null) {
            Log.d(TAG, "Choose default server alias " + alias + " for key type " + keyType + " and issuers " + Arrays.toString(issuers));
            return alias;
        }
        String[] aliases = getServerAliases(keyType, issuers);
        if (aliases != null && aliases.length > 0) {
            Log.d(TAG, "Choose server alias " + aliases[0] + " for key type " + keyType + " and issuers " + Arrays.toString(issuers));
            return aliases[0];
        }
        Log.d(TAG, "Choose server alias null for key type " + keyType + " and issuers " + Arrays.toString(issuers));
        return null;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        X509Certificate[] cert = km.getCertificateChain(alias);
        Log.d(TAG, "Certificate chain of " + alias + ": " + Arrays.toString(cert));
        return cert;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        String[] aliases = km.getClientAliases(keyType, issuers);
        Log.d(TAG, "Client getAliases for key type " + keyType + " and issuers " + Arrays.toString(issuers) + ": " + Arrays.toString(aliases));
        return aliases;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        String[] aliases = km.getServerAliases(keyType, issuers);
        Log.d(TAG, "Client getAliases for key type " + keyType + " and issuers " + Arrays.toString(issuers) + ": " + Arrays.toString(aliases));
        return aliases;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        PrivateKey key = km.getPrivateKey(alias);
        Log.d(TAG, "Private key for " + alias + " has type " + key.getAlgorithm());
        return key;
    }

}

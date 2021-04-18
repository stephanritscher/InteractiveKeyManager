package de.ritscher.ssl;

import android.util.Log;

import java.net.InetAddress;
import java.util.Objects;

import lombok.NonNull;

public class IKMAlias {
    private final static String TAG = "IKMAlias";

    enum Type {
        KEYCHAIN("KC_"),
        KEYSTORE("KS_");

        private String prefix;

        Type(String prefix) {
            this.prefix = prefix;
        }

        public String getPrefix() {
            return prefix;
        }

        public static Type parse(String prefix) throws IllegalArgumentException {
            for (Type type : Type.values()) {
                if (type.getPrefix().equals(prefix)) {
                    return type;
                }
            }
            throw new IllegalArgumentException("unknown prefix");
        }
    }

    private Type type;
    private String alias;
    private String hostname;
    private Integer port;

    /**
     * Constructor of IKMAlias
     * @param type type of alias (KEYCHAIN or KEYSTORE)
     * @param alias alias returned from KeyChain.choosePrivateKeyAlias respectively PrivateKey.hashCode
     * @param hostname hostname for which the alias shall be used; null for any
     * @param port port for which the alias shall be used (only if hostname is not null); null for any
     */
    public IKMAlias(Type type, String alias, String hostname, Integer port) {
        this.type = type;
        this.alias = alias;
        this.hostname = hostname;
        this.port = port;
    }

    /**
     * Constructor of IKMAlias
     * @param alias value returned from IKMAlias.toString()
     */
    public IKMAlias(String alias) throws IllegalArgumentException {
        String[] aliasFields = alias.split(":");
        if (aliasFields.length > 3 || aliasFields[0].length() < 4) {
            throw new IllegalArgumentException("alias was not returned by IKMAlias.toString(): " + alias);
        }
        this.type = Type.parse(aliasFields[0].substring(0, 3));
        this.alias = aliasFields[0].substring(3);
        this.hostname = aliasFields.length > 1 ? aliasFields[1] : null;
        this.port = aliasFields.length > 2 ? Integer.valueOf(aliasFields[2]) : null;
    }

    public Type getType() {
        return type;
    }

    public String getAlias() {
        return alias;
    }

    public String getHostname() {
        return hostname;
    }

    public Integer getPort() {
        return port;
    }

    @Override
    public @NonNull String toString() {
        StringBuilder constructedAlias = new StringBuilder();
        constructedAlias.append(type.getPrefix());
        constructedAlias.append(alias);
        if (hostname != null) {
            constructedAlias.append(":");
            constructedAlias.append(hostname);
            if (port != null) {
                constructedAlias.append(":");
                constructedAlias.append(port);
            }
        }
        return constructedAlias.toString();
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof IKMAlias)) {
            return false;
        }
        IKMAlias other = (IKMAlias) object;
        return Objects.equals(type, other.type) &&
                Objects.equals(alias, other.alias) &&
                Objects.equals(hostname, other.hostname) &&
                Objects.equals(port, other.port);
    }

    /**
     * Check if IKMAlias matches the filter
     * @param filter IKMAlias object used as filter
     * @return true if each non-null field of filter equals the same field of this instance; false otherwise
     * Exception: both hostname fields are resolved to an ip address before comparing if possible.
     */
    public boolean matches(@NonNull IKMAlias filter) {
        if (filter.type != null && !filter.type.equals(type)) {
            Log.d(TAG, "matches: alias " + toString() + " does not match type " + filter.type);
            return false;
        }
        if (filter.alias != null && !filter.alias.equals(alias)) {
            Log.d(TAG, "matches: alias " + toString() + " does not match original alias " + filter.alias);
            return false;
        }
        if (hostname != null && filter.hostname != null && !filter.hostname.equals(hostname)) {
            // Resolve hostname fields to ip addresses
            InetAddress address = null, filterAddress = null;
            /*try {
                address = InetAddress.getByName(hostname);
            } catch (UnknownHostException e) {
                Log.w(TAG, "matches: error resolving " + hostname);
            }
            try {
                filterAddress = InetAddress.getByName(filter.hostname);
            } catch (UnknownHostException e) {
                Log.w(TAG, "matches: error resolving " + filter.hostname);
            }*/
            // If resolution succeeded, compare addresses, otherwise host names
            if ((address == null || !address.equals(filterAddress))) {
                Log.d(TAG, "matches: alias " + toString() + " (address=" + address + ") does not match hostname " +
                        filter.hostname + " (address=" + filterAddress + ")");
                return false;
            }
        }
        if (port != null && filter.port != null && !filter.port.equals(port)) {
            Log.d(TAG, "matches: alias " + toString() + " does not match port " + filter.port);
            return false;
        }
        return true;
    }
}

package aurick.opsec.mod.accounts;

/** Stand-in for the credential helper: the config model only needs a round trip. */
public final class AccountCrypto {

    private AccountCrypto() {
    }

    public static String encrypt(String plaintext) {
        return plaintext == null ? null : "enc:" + plaintext;
    }

    public static String decrypt(String stored) {
        if (stored == null) {
            return null;
        }
        return stored.startsWith("enc:") ? stored.substring(4) : stored;
    }
}

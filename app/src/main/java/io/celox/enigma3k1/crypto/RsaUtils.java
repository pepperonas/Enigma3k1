package io.celox.enigma3k1.crypto;

import android.util.Base64;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility-Klasse für RSA-Verschlüsselung
 */
public class RsaUtils {

    private static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";

    /**
     * Generiert ein neues RSA-Schlüsselpaar
     *
     * @param keySize Schlüsselgröße in Bits (1024, 2048 oder 4096)
     * @return Array mit [publicKeyBase64, privateKeyBase64]
     */
    public static String[] generateKeyPair(int keySize) throws Exception {
        if (keySize != 1024 && keySize != 2048 && keySize != 4096) {
            throw new IllegalArgumentException("Schlüsselgröße muss 1024, 2048 oder 4096 Bit sein");
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        String publicKeyBase64 = Base64.encodeToString(pair.getPublic().getEncoded(), Base64.DEFAULT);
        String privateKeyBase64 = Base64.encodeToString(pair.getPrivate().getEncoded(), Base64.DEFAULT);

        return new String[]{publicKeyBase64, privateKeyBase64};
    }

    /**
     * Verschlüsselt Text mit RSA
     *
     * @param plaintext       Zu verschlüsselnder Text
     * @param publicKeyBase64 Öffentlicher Schlüssel als Base64
     * @return Verschlüsselter Text als Base64
     */
    public static String encrypt(String plaintext, String publicKeyBase64) throws Exception {
        PublicKey publicKey = getPublicKeyFromBase64(publicKeyBase64);

        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
    }

    /**
     * Entschlüsselt Text mit RSA
     *
     * @param ciphertextBase64 Verschlüsselter Text als Base64
     * @param privateKeyBase64 Privater Schlüssel als Base64
     * @return Entschlüsselter Text
     */
    public static String decrypt(String ciphertextBase64, String privateKeyBase64) throws Exception {
        PrivateKey privateKey = getPrivateKeyFromBase64(privateKeyBase64);

        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedBytes = Base64.decode(ciphertextBase64, Base64.DEFAULT);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, "UTF-8");
    }

    /**
     * Verschlüsselt den privaten Schlüssel mit einem Passwort
     *
     * @param privateKeyBase64 Privater Schlüssel als Base64
     * @param password         Passwort
     * @return Verschlüsseltes Objekt mit encrypted, salt, iv
     */
    public static EncryptedPrivateKey encryptPrivateKey(String privateKeyBase64, String password) throws Exception {
        // Zufälliges Salt und IV generieren
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        random.nextBytes(iv);

        // AES-Schlüssel aus Passwort ableiten
        byte[] passwordBytes = password.getBytes("UTF-8");
        byte[] keyBytes = new byte[32]; // 256-bit Schlüssel

        // Einfaches Key Stretching (in einer vollständigen Implementierung würde man PBKDF2 verwenden)
        for (int i = 0; i < 32; i++) {
            keyBytes[i] = passwordBytes[i % passwordBytes.length];
        }

        for (int i = 0; i < salt.length; i++) {
            keyBytes[i % keyBytes.length] ^= salt[i];
        }

        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        // AES Verschlüsselung
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] encryptedData = cipher.doFinal(privateKeyBase64.getBytes("UTF-8"));

        // Ergebnis zusammenführen
        return new EncryptedPrivateKey(
                Base64.encodeToString(encryptedData, Base64.DEFAULT),
                Base64.encodeToString(salt, Base64.DEFAULT),
                Base64.encodeToString(iv, Base64.DEFAULT)
        );
    }

    /**
     * Entschlüsselt den privaten Schlüssel mit einem Passwort
     *
     * @param encryptedKey Verschlüsselter Schlüssel (Objekt mit encrypted, salt, iv)
     * @param password     Passwort
     * @return Entschlüsselter privater Schlüssel als Base64
     */
    public static String decryptPrivateKey(EncryptedPrivateKey encryptedKey, String password) throws Exception {
        byte[] encryptedData = Base64.decode(encryptedKey.getEncrypted(), Base64.DEFAULT);
        byte[] salt = Base64.decode(encryptedKey.getSalt(), Base64.DEFAULT);
        byte[] iv = Base64.decode(encryptedKey.getIv(), Base64.DEFAULT);

        // AES-Schlüssel aus Passwort ableiten (gleiche Methode wie beim Verschlüsseln)
        byte[] passwordBytes = password.getBytes("UTF-8");
        byte[] keyBytes = new byte[32]; // 256-bit Schlüssel

        for (int i = 0; i < 32; i++) {
            keyBytes[i] = passwordBytes[i % passwordBytes.length];
        }

        for (int i = 0; i < salt.length; i++) {
            keyBytes[i % keyBytes.length] ^= salt[i];
        }

        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        // AES Entschlüsselung
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] decryptedData = cipher.doFinal(encryptedData);

        return new String(decryptedData, "UTF-8");
    }

    /**
     * Konvertiert einen Base64-String in einen Public Key
     */
    public static PublicKey getPublicKeyFromBase64(String base64Key) throws Exception {
        byte[] keyBytes = Base64.decode(base64Key, Base64.DEFAULT);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * Konvertiert einen Base64-String in einen Private Key
     */
    public static PrivateKey getPrivateKeyFromBase64(String base64Key) throws Exception {
        byte[] keyBytes = Base64.decode(base64Key, Base64.DEFAULT);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Wandelt einen öffentlichen Schlüssel in das PEM-Format um
     */
    public static String publicKeyToPem(String publicKeyBase64) {
        String pemHeader = "-----BEGIN PUBLIC KEY-----\n";
        String pemFooter = "\n-----END PUBLIC KEY-----";

        // Base64 in 64-Zeichen-Zeilen formatieren
        StringBuilder formattedKey = new StringBuilder();
        for (int i = 0; i < publicKeyBase64.length(); i += 64) {
            int end = Math.min(i + 64, publicKeyBase64.length());
            formattedKey.append(publicKeyBase64.substring(i, end)).append("\n");
        }

        return pemHeader + formattedKey + pemFooter;
    }

    /**
     * Wandelt einen privaten Schlüssel in das PEM-Format um
     */
    public static String privateKeyToPem(String privateKeyBase64) {
        String pemHeader = "-----BEGIN PRIVATE KEY-----\n";
        String pemFooter = "\n-----END PRIVATE KEY-----";

        // Base64 in 64-Zeichen-Zeilen formatieren
        StringBuilder formattedKey = new StringBuilder();
        for (int i = 0; i < privateKeyBase64.length(); i += 64) {
            int end = Math.min(i + 64, privateKeyBase64.length());
            formattedKey.append(privateKeyBase64.substring(i, end)).append("\n");
        }

        return pemHeader + formattedKey + pemFooter;
    }

    /**
     * Extrahiert den Base64-Schlüssel aus einem PEM-String
     */
    public static String extractBase64FromPem(String pem) {
        // Alle Whitespaces und PEM-Header/-Footer entfernen
        return pem.replaceAll("-----BEGIN (PUBLIC|PRIVATE) KEY-----", "")
                .replaceAll("-----END (PUBLIC|PRIVATE) KEY-----", "")
                .replaceAll("\\s", "");
    }

    /**
     * Klasse zur Repräsentation eines verschlüsselten privaten Schlüssels
     */
    public static class EncryptedPrivateKey {
        private String encrypted;
        private String salt;
        private String iv;

        public EncryptedPrivateKey(String encrypted, String salt, String iv) {
            this.encrypted = encrypted;
            this.salt = salt;
            this.iv = iv;
        }

        public String getEncrypted() {return encrypted;}

        public String getSalt() {return salt;}

        public String getIv() {return iv;}
    }
}
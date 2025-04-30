package io.celox.enigma3k1.crypto;

import android.util.Base64;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility-Klasse für AES-Verschlüsselung (Advanced Encryption Standard)
 * Verwendet AES-GCM mit IV für sichere Verschlüsselung
 */
public class AesUtils {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128; // in Bits

    /**
     * Generiert einen zufälligen Hex-String als AES-Schlüssel
     *
     * @param keySize Schlüsselgröße in Bits (128, 192 oder 256)
     * @return Zufälliger Hex-String
     */
    public static String generateKey(int keySize) {
        if (keySize != 128 && keySize != 192 && keySize != 256) {
            throw new IllegalArgumentException("Schlüsselgröße muss 128, 192 oder 256 Bit sein");
        }

        SecureRandom random = new SecureRandom();
        byte[] key = new byte[keySize / 8];
        random.nextBytes(key);

        StringBuilder hexString = new StringBuilder();
        for (byte b : key) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Verschlüsselt einen Text mit AES-GCM
     *
     * @param plaintext Zu verschlüsselnder Text
     * @param password  Passwort oder Hex-Schlüssel
     * @param keySize   Schlüsselgröße in Bits (128, 192 oder 256)
     * @return Base64-kodierter verschlüsselter Text mit IV
     */
    public static String encrypt(String plaintext, String password, int keySize) throws Exception {
        // Schlüssel aus Passwort ableiten
        byte[] key = deriveKey(password, keySize);

        // IV generieren
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // AES-GCM Verschlüsselung einrichten
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        // Verschlüsseln
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

        // IV und verschlüsselte Daten kombinieren
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        byteBuffer.put(iv);
        byteBuffer.put(ciphertext);
        byte[] ciphertextWithIv = byteBuffer.array();

        // Als Base64 zurückgeben
        return Base64.encodeToString(ciphertextWithIv, Base64.DEFAULT);
    }

    /**
     * Entschlüsselt einen Text mit AES-GCM
     *
     * @param ciphertextBase64 Base64-kodierter verschlüsselter Text mit IV
     * @param password         Passwort oder Hex-Schlüssel
     * @param keySize          Schlüsselgröße in Bits (128, 192 oder 256)
     * @return Entschlüsselter Text
     */
    public static String decrypt(String ciphertextBase64, String password, int keySize) throws Exception {
        // Base64-Decodierung
        byte[] ciphertextWithIv = Base64.decode(ciphertextBase64, Base64.DEFAULT);

        // IV und verschlüsselten Text trennen
        ByteBuffer byteBuffer = ByteBuffer.wrap(ciphertextWithIv);
        byte[] iv = new byte[GCM_IV_LENGTH];
        byteBuffer.get(iv);
        byte[] ciphertext = new byte[byteBuffer.remaining()];
        byteBuffer.get(ciphertext);

        // Schlüssel aus Passwort ableiten
        byte[] key = deriveKey(password, keySize);

        // AES-GCM Entschlüsselung einrichten
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        // Entschlüsseln
        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, "UTF-8");
    }

    /**
     * Ableiten eines Schlüssels aus einem Passwort mit SHA-256
     *
     * @param password Passwort oder Hex-Schlüssel
     * @param keySize  Schlüsselgröße in Bits (128, 192 oder 256)
     * @return Abgeleiteter Schlüssel
     */
    private static byte[] deriveKey(String password, int keySize) throws Exception {
        // Überprüfen, ob das Passwort bereits ein Hex-Schlüssel der richtigen Länge ist
        if (isHexString(password) && password.length() == keySize / 4) {
            return hexStringToByteArray(password);
        }

        // Ansonsten Passwort hashen, um Schlüssel abzuleiten
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(password.getBytes("UTF-8"));

        // Auf die richtige Schlüsselgröße zuschneiden
        return Arrays.copyOf(hash, keySize / 8);
    }

    /**
     * Konvertiert einen Hex-String in ein Byte-Array
     */
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Überprüft, ob ein String ein gültiger Hex-String ist
     */
    private static boolean isHexString(String s) {
        return s.matches("[0-9a-fA-F]+");
    }
}
import java.io.*;
import java.security.PrivateKey;
import java.security.MessageDigest;
import java.security.KeyFactory;
import java.util.Arrays;
import java.util.Base64;
import java.security.spec.RSAPrivateKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;

public class ReceiverProgram {

    public static byte[] readAESKey() throws Exception {
        // relative path to the key file
        Path path = Paths.get("symmetric.key");
        byte[] fileBytes = Files.readAllBytes(path);

        // Case 1: raw binary key (already 16, 24, or 32 bytes)
        if (fileBytes.length == 16 || fileBytes.length == 24 || fileBytes.length == 32)
            return fileBytes;

        // Case 2/3: interpret as text (hex or base64)
        String content = new String(fileBytes, StandardCharsets.UTF_8).trim();
        byte[] keyBytes;

        if (content.matches("^[0-9A-Fa-f]+$")) {
            // Hex string
            int len = content.length();
            if (len % 2 != 0)
                throw new IllegalArgumentException("Invalid hex length for AES key.");
            keyBytes = new byte[len / 2];
            for (int i = 0; i < len; i += 2)
                keyBytes[i / 2] = (byte) ((Character.digit(content.charAt(i), 16) << 4)
                                        + Character.digit(content.charAt(i + 1), 16));
        } else {
            // Base64 or PEM
            content = content.replaceAll("-----BEGIN [^-]+-----", "")
                             .replaceAll("-----END [^-]+-----", "")
                             .replaceAll("\\s", "");
            keyBytes = Base64.getDecoder().decode(content);
        }

        // Validate final key length
        int len = keyBytes.length;
        if (len != 16 && len != 24 && len != 32)
            throw new IllegalArgumentException("Invalid AES key length: " + len + " bytes");

        return keyBytes;
    }

public static PrivateKey readRSAPrivateKey() throws Exception {
    // Path to the binary private key file
    String path = "YPrivate.key";

    BigInteger modulus;
    BigInteger privateExponent;

    // Read serialized BigInteger values from the file
    try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path))) {
        modulus = (BigInteger) ois.readObject();
        privateExponent = (BigInteger) ois.readObject();
    }

    // Reconstruct the PrivateKey using RSAPrivateKeySpec
    RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, privateExponent);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return keyFactory.generatePrivate(keySpec);
}

public static void rsaDecryptMessage(PrivateKey privateKey, String inputPath, String outputPath) throws Exception {
    // Determine RSA block size in bytes
    int keyBytes;
    try {
        keyBytes = (privateKey instanceof java.security.interfaces.RSAPrivateKey)
                ? (((java.security.interfaces.RSAPrivateKey) privateKey).getModulus().bitLength() + 7) / 8
                : 128; // default to 128 bytes if modulus unavailable
    } catch (Exception e) {
        keyBytes = 128; // fallback
    }

    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);

    // Open input/output streams
    try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputPath));
         BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputPath))) {

        byte[] buffer = new byte[keyBytes];
        int bytesRead;

        while ((bytesRead = bis.read(buffer)) != -1) {
            byte[] block;

            // If we read less than KEY_BYTES, copy to a smaller array
            if (bytesRead < keyBytes) {
                block = new byte[bytesRead];
                System.arraycopy(buffer, 0, block, 0, bytesRead);
            } else {
                block = buffer;
            }

            // RSA decrypt the block
            byte[] decryptedBlock = rsaCipher.doFinal(block);

            // Write decrypted block to output
            bos.write(decryptedBlock);
        }
    }
}
public static byte[] parseMessageDigest(String messagePath) throws IOException {
    byte[] aesCipherDigest = new byte[32];
    int offset = 0;
    int bytesRead;

    try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(messagePath))) {
        while (offset < 32 && (bytesRead = bis.read(aesCipherDigest, offset, 32 - offset)) != -1) {
            offset += bytesRead;
        }
    }

    if (offset != 32) {
        throw new IOException("Message too short: expected 32 bytes for AES digest, got " + offset);
    }

    return aesCipherDigest;
}
public static byte[] aesDecryptDigest(byte[] aesKey, byte[] aesCipherDigest, String outputPath) throws Exception {
    if (aesCipherDigest.length != 32) {
        throw new IllegalArgumentException("AES_CIPHER_DIGEST must be 32 bytes");
    }

    // Initialize AES cipher (AES/ECB/NoPadding)
    SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
    Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
    aesCipher.init(Cipher.DECRYPT_MODE, keySpec);

    // Decrypt the digest
    byte[] aesDecryptedDigest = aesCipher.doFinal(aesCipherDigest);

    // Save decrypted digest to file
    try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputPath))) {
        bos.write(aesDecryptedDigest);
    }

    // Print hex representation
    System.out.print("AES_DECRYPTED_DIGEST (hex): ");
    for (byte b : aesDecryptedDigest) {
        System.out.printf("%02X", b);
    }
    System.out.println();

    // Return decrypted digest so it can be used for verification
    return aesDecryptedDigest;
}



public static void verifyMessageDigest(String decryptedFilePath, byte[] aesDecryptedDigest) throws Exception {
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

    try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(decryptedFilePath))) {
        // Skip first 32 bytes (AES_CIPHER_DIGEST)
        long skipped = bis.skip(32);
        if (skipped < 32) {
            throw new Exception("Message too short to skip AES_CIPHER_DIGEST");
        }

        // Read the rest of the file in chunks and update digest
        byte[] buffer = new byte[32 * 1024]; // 32 KB buffer
        int bytesRead;
        while ((bytesRead = bis.read(buffer)) != -1) {
            sha256.update(buffer, 0, bytesRead);
        }
    }

    byte[] computedDigest = sha256.digest();

    // Print computed digest in hex
    System.out.print("COMPUTED_DIGEST (hex): ");
    for (byte b : computedDigest) {
        System.out.printf("%02X", b);
    }
    System.out.println();

    // Compare with AES_DECRYPTED_DIGEST
    if (Arrays.equals(aesDecryptedDigest, computedDigest)) {
        System.out.println("DIGESTS MATCH");
    } else {
        System.out.println("DIGESTS DIFFER");
    }
}

public static void main(String[] args) {
    try {
        // 1️⃣ Load AES + RSA keys
        byte[] aesKey = readAESKey();
        PrivateKey rsaPrivateKey = readRSAPrivateKey();
        System.out.println("Keys loaded successfully.");

        // 2️⃣ RSA-decrypt message
        rsaDecryptMessage(rsaPrivateKey, "message.rsacipher", "message.add-msg");
        System.out.println("RSA decryption done.");

        // 3️⃣ Parse and AES-decrypt the embedded digest
        byte[] aesDigest = parseMessageDigest("message.add-msg");
        byte[] aesDecryptedDigest = aesDecryptDigest(aesKey, aesDigest, "message.dd");

        // 4️⃣ Verify SHA-256
        verifyMessageDigest("message.add-msg", aesDecryptedDigest);

        // 5️⃣ Ask for final plaintext output
        System.out.println("\nAll decryption and verification complete!");
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.print("Enter name for final plaintext output file: ");
            String finalOutputName = scanner.nextLine().trim();
            if (finalOutputName.isEmpty()) finalOutputName = "final_message.txt";

            try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream("message.add-msg"));
                 BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(finalOutputName))) {

                bis.skip(32); // skip digest bytes
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = bis.read(buffer)) != -1) {
                    bos.write(buffer, 0, bytesRead);
                }

                System.out.println("Final plaintext written to: " + finalOutputName);
            }
        }

    } catch (Exception e) {
        System.err.println("Fatal error: " + e.getMessage());
        e.printStackTrace();
    }
}}
    


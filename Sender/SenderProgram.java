import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.io.*;       
import java.security.*;
import java.security.MessageDigest;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * In this option, X is the sender and Y is the receiver.
• In the sender’s program in the directory “Sender”, calculate RSA-En Ky+ (AES-En Kxy (SHA256 (M)) || M)
1 To test this program, the corresponding key files need to be copied here from the directory “KeyGen”
2 Read the information on the keys to be used in this program from the key files and generate Ky+ and Kxy.
3 Display a prompt “Input the name of the message file:” and take a user input from the keyboard. This
user input provides the name of the file containing the message M. M can NOT be assumed to be a text message. The
size of the message M could be much larger than 32KB.
4 Read the message, M, from the file specified in Step 3 piece by piece, where each piece is recommended to be a small
multiple of 1024 bytes, calculate the SHA256 hash value (digital digest) of the entire message M, i.e., SHA256(M), SAVE
it into a file named “message.dd”, and DISPLAY SHA256(M) in Hexadecimal bytes.
o An added feature for testing whether the receiver’s program can handle the case properly when the digital digest
calculated in Step 6 (the receiver’s program) is different from the digital digest obtained in Step 5 (the receiver’s
program): After calculating SHA256(M) but before saving it to the file named “message.dd” (the sender’s program),
display a prompt “Do you want to invert the 1st byte in SHA256(M)? (Y or N)”,
o If the user input is ‘Y’, modify the first byte in your byte array holding SHA256(M) by replacing it with its bitwise
inverted value (hint: the ~ operator in Java does it), complete the rest of Step 4 by SAVING & DISPLAYING the
modified SHA256(M), instead of the original SHA256(M), and continue to Step 5 (also use the modified
SHA256(M), instead of the original SHA256(M), in Steps 5 & 6).
o Otherwise (if the user input is ‘N’), make NO change to the byte array holding SHA256(M), complete the rest of
Step 4 (SAVE and DISPLAY), and continue to Step 5.
5 Calculate the AES Encryption of SHA256(M) using Kxy (NO padding is allowed or needed here. Question: how many
bytes are there in total?), SAVE this AES cyphertext into a file named “message.add-msg”, and DISPLAY it in
Hexadecimal bytes. APPEND the message M read from the file specified in Step 3 to the file “message.add-msg” piece
by piece.
6 Calculate the RSA Encryption of (AES-En Kxy (SHA256 (M)) || M) using Ky+ by reading the file “message.add-msg”
piece by piece, where each piece is recommended to be 117 bytes if "RSA/ECB/PKCS1Padding" is used. (Hint: if the
length of the last piece is less than 117 bytes, it needs to be placed in a byte array whose array size is the length of the last
piece before being encrypted.) SAVE the resulting blocks of RSA ciphertext into a file named “message.rsacipher”.
 */






public class SenderProgram{
  private static int BUFFER_SIZE = 32 * 1024;
  static Scanner scanner = new Scanner(System.in); 

  public static void main(String[] args) throws Exception {
    // 1. Load keys from local Sender directory (expecting files: "YPublic.key" and "symmetric.key")
    byte[] aesKey = loadAesKey("Sender/symmetric.key");
    PublicKey kyPlus = loadPublicKey("Sender/YPublic.key");

    // 2. Ask user for message file
    System.out.print("Input the name of the message file (default: Sender/test.txt): ");
    String filename = scanner.nextLine().trim();
    if (filename.isEmpty()) filename = "Sender/test.txt";

    // 3-4. Compute SHA-256 over the message, streaming
    byte[] digest = computeSHA256(filename);
    System.out.println("SHA-256 digest:");
    System.out.println(toHex(digest));

    // Optional: invert first byte
    System.out.print("Do you want to invert the 1st byte in SHA256(M)? (Y or N): ");
    String invert = scanner.nextLine().trim();
    if (invert.equalsIgnoreCase("Y")) {
      digest[0] = (byte) ~digest[0];
      System.out.println("Modified SHA-256 digest:");
      System.out.println(toHex(digest));
    }

    // Save digest to message.dd
    Files.write(Paths.get("Sender/message.dd"), digest);

    // 5. AES-Encrypt SHA256(M) with Kxy (NoPadding). SHA-256 is 32 bytes -> 2 AES blocks.
    byte[] aesCipher = aesEncryptDigestNoPadding(aesKey, digest);
    System.out.println("AES(Kxy, SHA256(M)):");
    System.out.println(toHex(aesCipher));

    // Save AES ciphertext into message.add-msg then append the original message bytes
    try (FileOutputStream out = new FileOutputStream("Sender/message.add-msg")) {
      out.write(aesCipher);
    }
    // Append message file piece by piece
    try (InputStream in = new BufferedInputStream(new FileInputStream(filename));
         FileOutputStream out = new FileOutputStream("Sender/message.add-msg", true)) {
      byte[] buf = new byte[4096];
      int r;
      while ((r = in.read(buf)) != -1) {
        out.write(buf, 0, r);
      }
    }

    // 6. RSA-encrypt the (AES || M) file using Ky+ in 117-byte chunks (for 1024-bit RSA, PKCS1Padding)
    rsaEncryptFile(kyPlus, "Sender/message.add-msg", "Sender/message.rsacipher");

    System.out.println("Done. Files written to Sender/: message.dd, message.add-msg, message.rsacipher");
  }

  public static String md(String f) throws Exception {
    // Deprecated helper, keep compatibility by computing hex digest
    byte[] d = computeSHA256(f);
    return toHex(d);
  }

  private static byte[] computeSHA256(String filename) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    try (InputStream in = new BufferedInputStream(new FileInputStream(filename))) {
      byte[] buf = new byte[BUFFER_SIZE];
      int r;
      while ((r = in.read(buf)) != -1) {
        md.update(buf, 0, r);
      }
    }
    return md.digest();
  }

  private static byte[] loadAllBytesFlexible(String path) throws Exception {
    byte[] raw = Files.readAllBytes(Paths.get(path));
    // Try to detect PEM/base64 text
    String s = new String(raw).trim();
    if (s.startsWith("-----BEGIN")) {
      String b64 = s.replaceAll("-----BEGIN [^\n]+-----", "").replaceAll("-----END [^\n]+-----", "").replaceAll("\s+", "");
      return Base64.getDecoder().decode(b64);
    }
    // If looks like base64 (only base64 chars), decode
    String trimmed = s.replaceAll("\s+", "");
    if (trimmed.matches("^[A-Za-z0-9+/=]+$") && trimmed.length() >= 24) {
      try {
        return Base64.getDecoder().decode(trimmed);
      } catch (IllegalArgumentException ex) {
        // fall through to return raw
      }
    }
    return raw;
  }

  private static PublicKey loadPublicKey(String path) throws Exception {
    byte[] keyBytes = loadAllBytesFlexible(path);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
  }

  private static byte[] loadAesKey(String path) throws Exception {
    byte[] raw = loadAllBytesFlexible(path);
    // Accept keys of 16/24/32 bytes. If file contains text longer (like hex), try parse as hex
    if (raw.length == 16 || raw.length == 24 || raw.length == 32) return raw;
    String s = new String(raw).trim();
    // try hex
    if (s.matches("^[0-9a-fA-F]+$") && s.length() % 2 == 0) {
      int len = s.length() / 2;
      byte[] b = new byte[len];
      for (int i = 0; i < len; i++) b[i] = (byte) Integer.parseInt(s.substring(2*i, 2*i+2), 16);
      if (b.length == 16 || b.length == 24 || b.length == 32) return b;
    }
    // try base64 decode already attempted in loadAllBytesFlexible; if raw text length corresponds to base64-decoded length
    throw new IllegalArgumentException("Unsupported AES key format or length in " + path + ". Expected 16/24/32 raw bytes or base64/pem.");
  }

  private static byte[] aesEncryptDigestNoPadding(byte[] key, byte[] digest) throws Exception {
    if (digest.length % 16 != 0) throw new IllegalArgumentException("Digest length must be multiple of AES block size when using NoPadding");
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, keySpec);
    return cipher.doFinal(digest);
  }

  private static void rsaEncryptFile(PublicKey pub, String inPath, String outPath) throws Exception {
    Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    rsa.init(Cipher.ENCRYPT_MODE, pub);

    try (InputStream in = new BufferedInputStream(new FileInputStream(inPath));
         FileOutputStream out = new FileOutputStream(outPath)) {
      int chunkSize = 117; // for 1024-bit RSA and PKCS1Padding
      byte[] buf = new byte[chunkSize];
      int r;
      while ((r = in.read(buf)) != -1) {
        byte[] toEncrypt;
        if (r == chunkSize) {
          toEncrypt = buf;
        } else {
          toEncrypt = Arrays.copyOf(buf, r);
        }
        byte[] enc = rsa.doFinal(toEncrypt);
        out.write(enc);
      }
    }
  }

  private static String toHex(byte[] b) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < b.length; i++) {
      sb.append(String.format("%02X", b[i]));
      if ((i+1) % 16 == 0) sb.append('\n'); else sb.append(' ');
    }
    return sb.toString();
  }
}


import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class SenderProgram {
	private static final int STREAM_BUF = 32 * 1024; // 32KB recommended

	public static void main(String[] args) throws Exception {
		Scanner sc = new Scanner(System.in);

		// Locate AES key and RSA public key (try Sender/ then KeyGen/)
		Path aesPath = findFirstExisting("Sender/symmetric.key", "KeyGen/symmetric.key", "symmetric.key");
		Path pubPath = findFirstExisting("Sender/YPublic.key", "KeyGen/YPublic.key", "YPublic.key");
		if (aesPath == null) throw new IllegalStateException("AES key not found in Sender/ or KeyGen/");
		if (pubPath == null) throw new IllegalStateException("Receiver public key not found in Sender/ or KeyGen/");

		byte[] aesKey = loadAesKey(aesPath);
		PublicKey kyPlus = loadPublicKeyFlexible(pubPath);

		System.out.print("Input the name of the message file (default: Sender/test.txt): ");
		String input = sc.nextLine().trim();
		String messagePath = input.isEmpty() ? "Sender/test.txt" : input;

		// Compute SHA-256 over message (streaming)
		byte[] digest = computeSHA256(messagePath);
		System.out.println("SHA-256 digest:");
		System.out.println(toHex(digest));

		// Optional invert first byte
		System.out.print("Do you want to invert the 1st byte in SHA256(M)? (Y or N): ");
		String inv = sc.nextLine().trim();
		if (inv.equalsIgnoreCase("Y")) {
			digest[0] = (byte) ~digest[0];
			System.out.println("Modified SHA-256 digest:");
			System.out.println(toHex(digest));
		}

		// Save digest
		Files.write(Paths.get("Sender/message.dd"), digest);

		// AES-encrypt digest with AES/ECB/NoPadding
		if (digest.length % 16 != 0) {
			throw new IllegalStateException("Digest length not a multiple of 16 bytes");
		}
		byte[] aesCipher = aesEncryptNoPadding(aesKey, digest);
		System.out.println("AES(Kxy, SHA256(M)):");
		System.out.println(toHex(aesCipher));

		// Create message.add-msg: write AES cipher then append message bytes
		try (FileOutputStream out = new FileOutputStream("Sender/message.add-msg")) {
			out.write(aesCipher);
		}
		try (InputStream in = new BufferedInputStream(new FileInputStream(messagePath));
				 FileOutputStream out = new FileOutputStream("Sender/message.add-msg", true)) {
			byte[] buf = new byte[4096];
			int r;
			while ((r = in.read(buf)) != -1) {
				out.write(buf, 0, r);
			}
		}

		// RSA-encrypt message.add-msg into message.rsacipher
		rsaEncryptFile(kyPlus, "Sender/message.add-msg", "Sender/message.rsacipher");

		System.out.println("Done. Files written: Sender/message.dd, Sender/message.add-msg, Sender/message.rsacipher");
	}

	private static Path findFirstExisting(String... paths) {
		for (String p : paths) {
			Path path = Paths.get(p);
			if (Files.exists(path)) return path;
		}
		return null;
	}

	private static byte[] computeSHA256(String path) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		try (InputStream in = new BufferedInputStream(new FileInputStream(path))) {
			byte[] buf = new byte[STREAM_BUF];
			int r;
			while ((r = in.read(buf)) != -1) md.update(buf, 0, r);
		}
		return md.digest();
	}

	private static byte[] loadAllBytesFlexible(Path path) throws Exception {
		byte[] raw = Files.readAllBytes(path);
		String s = new String(raw).trim();
		if (s.startsWith("-----BEGIN")) {
			String b64 = s.replaceAll("-----BEGIN [^\n]+-----", "").replaceAll("-----END [^\n]+-----", "").replaceAll("\s+", "");
			return Base64.getDecoder().decode(b64);
		}
		String trimmed = s.replaceAll("\s+", "");
		if (trimmed.matches("^[A-Za-z0-9+/=]+$") && trimmed.length() >= 24) {
			try { return Base64.getDecoder().decode(trimmed); } catch (IllegalArgumentException e) { }
		}
		return raw;
	}

	private static PublicKey loadPublicKeyFlexible(Path path) throws Exception {
		// Try X.509 / PEM / base64 DER first
		try {
			byte[] data = loadAllBytesFlexible(path);
			X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(spec);
		} catch (Exception e) {
			// fall through to try serialized BigInteger pair (from RSAConfidentiality.saveToFile)
		}
		// Try reading Java-serialized BigInteger modulus and exponent
		try (ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(new FileInputStream(path.toFile())))) {
			Object a = oin.readObject();
			Object b = oin.readObject();
			if (a instanceof BigInteger && b instanceof BigInteger) {
				BigInteger mod = (BigInteger) a;
				BigInteger exp = (BigInteger) b;
				RSAPublicKeySpec spec = new RSAPublicKeySpec(mod, exp);
				KeyFactory kf = KeyFactory.getInstance("RSA");
				return kf.generatePublic(spec);
			}
		} catch (Exception ex) {
			// can't parse
		}
		throw new IllegalArgumentException("Unsupported public key format in " + path.toString());
	}

	private static byte[] loadAesKey(Path path) throws Exception {
		byte[] raw = Files.readAllBytes(path);
		if (raw.length == 16 || raw.length == 24 || raw.length == 32) return raw;
		String s = new String(raw).trim();
		// try hex
		if (s.matches("^[0-9a-fA-F]+$") && s.length() % 2 == 0) {
			int len = s.length()/2;
			byte[] b = new byte[len];
			for (int i=0;i<len;i++) b[i] = (byte) Integer.parseInt(s.substring(2*i,2*i+2), 16);
			if (b.length==16||b.length==24||b.length==32) return b;
		}
		// try base64
		try {
			byte[] dec = Base64.getDecoder().decode(s.replaceAll("\s+",""));
			if (dec.length==16||dec.length==24||dec.length==32) return dec;
		} catch (IllegalArgumentException e) {}
		throw new IllegalArgumentException("Unsupported AES key format or length in " + path.toString());
	}

	private static byte[] aesEncryptNoPadding(byte[] key, byte[] plain) throws Exception {
		SecretKeySpec ks = new SecretKeySpec(key, "AES");
		Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
		c.init(Cipher.ENCRYPT_MODE, ks);
		return c.doFinal(plain);
	}

	private static void rsaEncryptFile(PublicKey pub, String inPath, String outPath) throws Exception {
		Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsa.init(Cipher.ENCRYPT_MODE, pub);

		int keyBytes = 0;
		if (pub instanceof RSAPublicKey) {
			keyBytes = ((RSAPublicKey) pub).getModulus().bitLength() / 8;
			if (((RSAPublicKey) pub).getModulus().bitLength() % 8 != 0) keyBytes++;
		}
		if (keyBytes <= 0) keyBytes = 128; // fallback for 1024-bit

		int blockSize = keyBytes - 11; // PKCS#1 v1.5 padding overhead

		try (InputStream in = new BufferedInputStream(new FileInputStream(inPath));
				 FileOutputStream out = new FileOutputStream(outPath)) {
			byte[] buf = new byte[blockSize];
			int r;
			while ((r = in.read(buf)) != -1) {
				byte[] toEnc = (r == blockSize) ? buf : Arrays.copyOf(buf, r);
				byte[] enc = rsa.doFinal(toEnc);
				out.write(enc);
			}
		}
	}

	private static String toHex(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (int i=0;i<b.length;i++) {
			sb.append(String.format("%02X", b[i]));
			if ((i+1)%16==0) sb.append('\n'); else sb.append(' ');
		}
		return sb.toString();
	}

}

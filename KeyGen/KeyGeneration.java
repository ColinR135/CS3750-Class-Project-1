import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;
import java.io.*;

import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;

import java.math.BigInteger;

import javax.crypto.Cipher;

public class KeyGeneration {
    static Scanner scanner = new Scanner(System.in);
    public static void main(String[] args) throws Exception {
        generateRSAKeyPair("X");
        generateRSAKeyPair("Y");
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter a symmetric key (16 characters): ");
        String skUserInput = scanner.nextLine();
        byte[] symKey = skUserInput.getBytes("UTF-8");
        if (symKey.length != 16) {
            System.out.println("Error: Symmetric key must be exactly 16 characters (16 bytes).");
            return;
        }
        BufferedOutputStream symKeyFile = new BufferedOutputStream(new FileOutputStream("symmetric.key"));
        symKeyFile.write(symKey, 0, symKey.length);
        symKeyFile.close();
        System.out.println("Symmetric key saved to symmetric.key");
        scanner.close();
    }
    public static void generateRSAKeyPair(String name) throws Exception {
        //Generate a pair of keys
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, random);  //1024: key size in bits
        //when key size of RSA is 1024 bits, the RSA Plaintext block 
        //size needs to be <= 117 bytes; and the RSA Cyphertext 
        //block is always 128 Bytes (1024 bits) long.
        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();

        /* next, store the keys to files, read them back from files, 
        and then, encrypt & decrypt using the keys from files. */

        //get the parameters of the keys: modulus and exponet
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKSpec = factory.getKeySpec(pubKey, 
            RSAPublicKeySpec.class);
        RSAPrivateKeySpec privKSpec = factory.getKeySpec(privKey, 
            RSAPrivateKeySpec.class);

        //save the parameters of the keys to the files
        String pubKeyFile = name + "Public.key";
        String privKeyFile = name + "Private.key";
        saveToFile(pubKeyFile, pubKSpec.getModulus(), 
            pubKSpec.getPublicExponent());
        saveToFile(privKeyFile, privKSpec.getModulus(), 
            privKSpec.getPrivateExponent());
    }

    public static void saveToFile(String fileName,
        BigInteger mod, BigInteger exp) throws IOException {
        ObjectOutputStream oout = new ObjectOutputStream(
        new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }
}
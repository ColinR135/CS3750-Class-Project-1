import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;

public class KeyGeneration {
    static Scanner scanner = new Scanner(System.in);
    public static void main(String[] args) throws Exception {
        BufferedOutputStream symKeyFile = new BufferedOutputStream(new FileOutputStream("symmetric.key"));
        static Scanner scanner = new Scanner(System.in);
        String skUserInput = scanner.nextLine();
        byte[] symKey = skUserInput.getBytes("UTF-8");
        symKeyFile.write(symKey, 0, symKey.length);
        symKeyFile.close();
    }
}

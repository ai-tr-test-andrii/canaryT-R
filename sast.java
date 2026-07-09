import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.servlet.http.HttpServletRequest;
import java.io.ObjectInputStream;
import java.io.FileInputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

public class MoreSastVulnerabilities {

    // 1. Command Injection (High)
    public void execute(HttpServletRequest request) throws Exception {

        String cmd = request.getParameter("cmd");

        Runtime.getRuntime().exec(cmd);
    }

    // 2. Secure Hash Algorithm (SHA-256 replaces broken SHA-1)
    public byte[] weakHash(String input) throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        return md.digest(input.getBytes());
    }

    // 3. Insecure Random (Medium)
    public int generateToken() {

        Random random = new Random();

        return random.nextInt();
    }

    // 4. Secure Encryption Algorithm (AES-GCM replaces broken DES)
    public byte[] encrypt(byte[] data) throws Exception {

        // Generate a 256-bit AES key using a cryptographically secure source
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        SecretKey secretKey = keyGen.generateKey();

        // Generate a random 96-bit IV (recommended for GCM)
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);

        // Use AES/GCM/NoPadding — authenticated encryption resists tampering
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        return cipher.doFinal(data);
    }

    // 5. Insecure Deserialization (High)
    public Object deserialize() throws Exception {

        ObjectInputStream in =
                new ObjectInputStream(
                        new FileInputStream("payload.bin"));

        return in.readObject();
    }

    // 6. Server-Side Request Forgery (High)
    public void fetch(HttpServletRequest request) throws Exception {

        String url = request.getParameter("url");

        new URL(url).openStream().close();
    }

    // 7. LDAP Injection (High)
    public String ldapFilter(HttpServletRequest request) {

        String username = request.getParameter("username");

        return "(&(uid=" + username + ")(objectClass=person))";
    }

}
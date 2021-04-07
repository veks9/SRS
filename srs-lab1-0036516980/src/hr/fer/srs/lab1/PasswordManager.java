package hr.fer.srs.lab1;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Klasa predstavlja implementaciju Password Managera.
 * Password Manager služi kao alat za upravljanje lozinkama.
 * Metoda init inicijalizira manager, put pohranjuje šifru za stranicu
 * u internu bazu, a get dohvaća šifru za stranicu iz baze.
 * @author vedran
 *
 */
public class PasswordManager {
	private static final int SALT_LEN = 256;
	private static final int ITERATIONS = 1000;
	private static final int KEY_LENGTH = 256;
	private Cipher cipher;
	private byte[] salt;
	private byte[] iv;
	private byte[] encryptedContent;
	private Map<String, String> map = new HashMap<>();
	private Mac mac = null;
	private File file = new File("./resources/safe.txt");

	public PasswordManager() {
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.out.println(e.getMessage());
		}
	}

	/**
	 * Metoda koja obrađuje slučaj kad se pošalje init naredba.
	 * Generira se mac i kriptiraju se prazan string te se napravi
	 * datoteka resources/safe.txt na disku.
	 * @param method init ili se baca iznimka
	 * @param masterPassword uneseni masterPassword
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public void initMethod(String method, String masterPassword)
			throws InvalidKeySpecException, InvalidKeyException, FileNotFoundException, IOException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		if (!method.equalsIgnoreCase("init")) {
			throw new IllegalArgumentException("Unsupported method or wrong number of arguments for this method!"
					+ "(options: init(2 arg), put(4 arg), get(3 arg)");
		}
		byte[] salt = generateRandomBytes(SALT_LEN);
		byte[] macSalt = generateRandomBytes(SALT_LEN);
		byte[] iv = generateRandomBytes(cipher.getBlockSize());
		SecretKey secretKey = generateSecretKey(masterPassword, salt);
		SecretKey macSecretKey = generateSecretKey(masterPassword, macSalt);

		try {
			mac = Mac.getInstance("HmacSHA256");
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
		}
		mac.init(macSecretKey);

		SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
		AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);

		byte[] encryptedContent = cipher.doFinal("".getBytes());
		byte[] macCalculated = mac.doFinal(appendByteArrays(salt, iv, encryptedContent));

		try (FileOutputStream outputStream = new FileOutputStream(file)) {
			outputStream.write(macSalt);
			outputStream.write(macCalculated);
			outputStream.write(salt);
			outputStream.write(iv);
			outputStream.write(encryptedContent);
		}
		
		System.out.println("Password manager initialized!");
	}
	
	/**
	 * Metoda koja pohranjuje uređeni par stranica-šifra u internu bazu
	 * @param webSite stranica
	 * @param password šifra
	 */
	private void putMethod(String webSite, String password) {
		map.put(webSite, password);
		System.out.println("Stored password for " + webSite);
	}

	/**
	 * Metoda koja dohvaća šifru za webSite stranicu iz interne baze
	 * @param webSite stranica za koju želimo dohvatiti šifru
	 */
	private void getMethod(String webSite) {
		String pswd = map.get(webSite);
		if(pswd == null) {
			System.out.println("There is no password for " + webSite);
			return;
		}
		System.out.println("Password for " + webSite + " is: " + pswd);
	}

	/**
	 * Metoda koja se zove prije nego što se obavljaju put i get metode.
	 * Služi kako bi se dekriptirali podaci iz interne baze.
	 * @param args argumenti programa
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 */
	public void unlock(String[] args) throws InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		String masterPassword = args[1];

		authenticate(masterPassword);

		SecretKey secretKey = generateSecretKey(masterPassword, salt);
		SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
		AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);

		byte[] decryptedContent = cipher.doFinal(encryptedContent);

		String decrypted = new String(decryptedContent, StandardCharsets.UTF_8);
		createMap(decrypted);

		switch (args[0]) {
		case "put":
			putMethod(args[2], args[3]);
			break;
		case "get":
			getMethod(args[2]);
			break;
		default:
			throw new IllegalArgumentException("Unsupported operation!");
		}

		lock(masterPassword);

	}

	/**
	 * Metoda koja se zove nakon što se izvršila naredba predana u argumentu.
	 * Metoda kriptira podatke i generira novi mac, također, pohranjuje podatke
	 * u internu bazu.
	 * @param masterPassword masterPassword
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 */
	private void lock(String masterPassword) throws InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		salt = generateRandomBytes(SALT_LEN);
		iv = generateRandomBytes(cipher.getBlockSize());

		SecretKey secretKey = generateSecretKey(masterPassword, salt);
		SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
		AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);

		byte[] encryptedContent = cipher.doFinal(deconstructMap());

		byte[] macSalt = generateRandomBytes(SALT_LEN);
		SecretKey macSecretKey = generateSecretKey(masterPassword, macSalt);
		mac.init(macSecretKey);
		byte[] macCalculated = mac.doFinal(appendByteArrays(salt, iv, encryptedContent));

		try (FileOutputStream outputStream = new FileOutputStream(file)) {
			outputStream.write(macSalt);
			outputStream.write(macCalculated);
			outputStream.write(salt);
			outputStream.write(iv);
			outputStream.write(encryptedContent);
		}
	}

	/**
	 * Pomoćna metoda koja generira {@link SecretKey} iz predanih argumenata
	 * @param password šifra od koje se gradi {@link SecretKey}
	 * @param salt salt koji se dodaje na šifru kad se gradi {@link SecretKey}
	 * @return novi ključ tipa {@link SecretKey} izrađen od argumenata password i salt
	 */
	private SecretKey generateSecretKey(String password, byte[] salt) {
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
		SecretKeyFactory keyFactory;
		try {
			keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			return keyFactory.generateSecret(pbeKeySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	/**
	 * Pomoćna metoda koja iz dektriptiranih podataka izradi mapu
	 * @param decrypted dekriptirani podaci
	 */
	private void createMap(String decrypted) {
		if(decrypted.length() == 0) return;
		String[] pairs = decrypted.split("\n");
		for (String pair : pairs) {
			String[] siteAndPassword = pair.split("\t");
			map.put(siteAndPassword[0], siteAndPassword[1]);
		}
	}

	/**
	 * Pomoćna metoda koja mapu pretvori u polje bajtova
	 * @return polje bajtova koji reprezentiraju mapu
	 */
	private byte[] deconstructMap() {
		String s = "";
		for (Entry<String, String> e : map.entrySet()) {
			s += e.getKey() + "\t" + e.getValue() + "\n";
		}
		return s.getBytes();
	}

	/**
	 * Pomoćna metoda koja autentificira korisnika po upisanoj master šifri.
	 * Također se provjerava je li netko mijenjao podatke u internoj bazi.
	 * Ako je kriva master šifra ili je netko mijenjao podatke, program ispisuje
	 * poruku i završava sa izvođenjem.
	 * @param masterPassword masterPassword
	 * @throws InvalidKeyException
	 */
	private void authenticate(String masterPassword) throws InvalidKeyException {
		byte[] fileContent = null;
		if(!file.exists()) {
			System.out.println("You have to call init before you can call get or put!");
			System.exit(0);
		}
		try {
			fileContent = Files.readAllBytes(file.toPath());
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
		byte[] macSalt = Arrays.copyOfRange(fileContent, 0, SALT_LEN);
		
		SecretKey macKey = generateSecretKey(masterPassword, macSalt);
		
		try {
			mac = Mac.getInstance("HmacSHA256");
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
		}
		
		mac.init(macKey);
		
		byte[] macFromBefore = Arrays.copyOfRange(fileContent, SALT_LEN, SALT_LEN + mac.getMacLength());
		salt = Arrays.copyOfRange(fileContent, SALT_LEN + mac.getMacLength(), 2 * SALT_LEN + mac.getMacLength());
		iv = Arrays.copyOfRange(fileContent, 2 * SALT_LEN + mac.getMacLength(),
				2 * SALT_LEN + mac.getMacLength() + cipher.getBlockSize());
		encryptedContent = Arrays.copyOfRange(fileContent, 2 * SALT_LEN + mac.getMacLength() + cipher.getBlockSize(),
				fileContent.length);
		byte[] macCalculated = mac.doFinal(appendByteArrays(salt, iv, encryptedContent));

		if (!Arrays.equals(macFromBefore, macCalculated)) {
			System.out.println("Access denied!");
			System.exit(0);
		}

	}

	/**
	 * Pomoćna metoda koja konkatenira polja bajtova
	 * @param salt
	 * @param iv
	 * @param encryptedContent
	 * @return konkatenirano polje bajtova
	 */
	private byte[] appendByteArrays(byte[] salt, byte[] iv, byte[] encryptedContent) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			baos.write(salt);
			baos.write(iv);
			baos.write(encryptedContent);
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
		return baos.toByteArray();
	}
	
	/**
	 * Pomoćna metoda koja generira slučajno polje bajtova
	 * duljine length
	 * @param length duljina polja
	 * @return polje bajtova sa slučajno generiram bajtovima
	 */
	private static byte[] generateRandomBytes(int length) {
		SecureRandom sr = new SecureRandom();

		byte[] bytes = new byte[length];
		sr.nextBytes(bytes);

		return bytes;

	}
}

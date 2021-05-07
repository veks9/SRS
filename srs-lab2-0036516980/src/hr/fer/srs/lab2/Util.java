package hr.fer.srs.lab2;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Util {
	private static final int SALT_LEN = 256;
	private static final int ITERATIONS = 1000;
	private static final int KEY_LENGTH = 256;
	private static final int HASH_PASSWORD_LENGTH = 32;
	
	public static Map<String, LoginEntry> readFile(File file) throws IOException {
		DataInputStream dis = new DataInputStream(new FileInputStream(file));
		Map<String, LoginEntry> map = new HashMap<>();
		
		while (dis.available() != 0) {
			String user = dis.readUTF();
			byte[] hashPassword = dis.readNBytes(HASH_PASSWORD_LENGTH);
			byte[] salt = dis.readNBytes(SALT_LEN);
			boolean changePasswordFlag = dis.readBoolean();
			map.put(user, new LoginEntry(hashPassword, salt, changePasswordFlag));
		}
		dis.close();
		
		return map;
	}
	
	public static void writeToFile(Map<String, LoginEntry> map, File file) throws IOException {
		DataOutputStream dos = new DataOutputStream(new FileOutputStream(file));
		for (Entry<String, LoginEntry> e : map.entrySet()) {
			dos.writeUTF(e.getKey());
			dos.write(e.getValue().getHashPassword(), 0, e.getValue().getHashPassword().length);
			dos.write(e.getValue().getSalt(), 0, e.getValue().getSalt().length);
			dos.writeBoolean(e.getValue().isChangePasswordFlag());
		}
		dos.close();
	}
	
	public static byte[] hashPassword(String password, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
		SecretKey key = generateSecretKey(password, salt);
		return key.getEncoded();
	}
	
	public static SecretKey generateSecretKey(String password, byte[] salt) {
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
	
	public static byte[] generateRandomBytes(int length) {
		SecureRandom sr = new SecureRandom();

		byte[] bytes = new byte[length];
		sr.nextBytes(bytes);

		return bytes;

	}
	
	public static boolean isMinimalComplexityPassword(String password, String username) {
		if(password.equalsIgnoreCase(username)) return false;
		if(password.length() < 8) return false;
		char ch;
		boolean capitalFlag = false;
		boolean lowerCaseFlag = false;
		boolean numberFlag = false;
		for (int i = 0; i < password.length(); i++) {
			ch = password.charAt(i);
			if (Character.isDigit(ch)) {
				numberFlag = true;
			} else if (Character.isUpperCase(ch)) {
				capitalFlag = true;
			} else if (Character.isLowerCase(ch)) {
				lowerCaseFlag = true;
			}
			if (numberFlag && capitalFlag && lowerCaseFlag)
				return true;
		}
		return false;
	}
}

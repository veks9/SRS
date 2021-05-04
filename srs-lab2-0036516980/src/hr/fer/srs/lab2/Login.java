package hr.fer.srs.lab2;

import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Login {
	private static final int SALT_LEN = 256;
	private static final int ITERATIONS = 1000;
	private static final int KEY_LENGTH = 256;
	private String username;
	private Map<String, LoginEntry> map = new HashMap<>();
	private File file = new File("./resources/safe.txt");

	public Login(String username) {
		this.username = username;
	}

	public void start() throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] fileContent = null;
		if (!file.exists()) {
			exitError();
		}

		try {
			fileContent = Files.readAllBytes(file.toPath());
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
		String fileContentString = new String(fileContent, StandardCharsets.UTF_8);
		createMap(fileContentString);

		if (!map.containsKey(username))
			exitError();

		Console cnsl = null;
		char[] inputPassword = null;
		do {
			try {
				cnsl = System.console();
				if (cnsl != null) 
					inputPassword = cnsl.readPassword("Password: ");	
			} catch (Exception ex) {
				System.out.println("Error!");
				System.exit(0);
			}
		} while(authenticate(new String(inputPassword)));
		checkIfNewPasswordFlag();
		
		System.out.println("Login successful.");
	}

	private void checkIfNewPasswordFlag() throws InvalidKeySpecException, NoSuchAlgorithmException {
		boolean changePasswordFlag = (map.get(username)).changePasswordFlag;
		if(changePasswordFlag) {
			changePassword();
			
		}
	}

	private void writeToFile(byte[] byteArray) {
		try (FileOutputStream fos = new FileOutputStream(file)) {
		    fos.write(byteArray);
		} catch (IOException ioe) {
			System.out.println("Error!");
			System.exit(0);
		}
		
	}

	private void changePassword() throws InvalidKeySpecException, NoSuchAlgorithmException {
		Console cnsl = null;
		char[] inputPassword = null;
		char[] repeatedPassword = null;
		do {
			try {
				cnsl = System.console();
				if (cnsl != null) {
					inputPassword = cnsl.readPassword("New password: ");
					repeatedPassword = cnsl.readPassword("Repeat new password: ");
					if(!Arrays.equals(inputPassword, repeatedPassword)) {
						System.out.println("Password change failed. Password mismatch.");
						continue;
					}
					break;
				}
	
			} catch (Exception ex) {
				System.out.println("Error!");
				System.exit(0);
			}
		} while(true);
		
		String stringInputPassword = new String(inputPassword);
		LoginEntry e = map.get(username);
		byte[] salt = generateRandomBytes(SALT_LEN);
		e.hashPassword = hashPassword(stringInputPassword, salt);
		writeToFile(deconstructMap());
	}

	private boolean authenticate(String inputPassword) throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] mapHashedPassword = (map.get(username)).hashPassword;
		byte[] salt = (map.get(username)).salt;
		byte[] inputHashedPassword = hashPassword(inputPassword, salt);
		
		if(!Arrays.equals(mapHashedPassword, inputHashedPassword)) {
			System.out.println("Username or password incorrect.");
			return false;
		}
		return true;
		
	}

	private void createMap(String fileContent) {
		if (fileContent.length() == 0)
			return;
		String[] rows = fileContent.split("\n");
		for (String row : rows) {
			String[] arr = row.split("\t");
			LoginEntry e = new LoginEntry(arr[0].getBytes(), arr[1].getBytes(), (arr[2].equals("1") ? true : false));
			map.put(arr[0], e);
		}
	}

	private byte[] deconstructMap() {
		String s = "";
		for (Entry<String, LoginEntry> e : map.entrySet()) {
			s += e.getKey() + "\t" + e.getValue().toString() + "\n";
		}
		return s.getBytes();
	}

	private void exitError() {
		System.out.println("Username or password incorrect.");
		System.exit(0);
	}

	private byte[] hashPassword(String password, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
		SecretKey key = generateSecretKey(password, salt);
		return key.getEncoded();
	}

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

	private static class LoginEntry {
		private byte[] hashPassword;
		private byte[] salt;
		private boolean changePasswordFlag;

		public LoginEntry(byte[] hashPassword, byte[] salt, boolean changePasswordFlag) {
			super();
			this.hashPassword = hashPassword;
			this.salt = salt;
			this.changePasswordFlag = changePasswordFlag;
		}

		@Override
		public String toString() {
			return hashPassword.toString() + "\t" + salt.toString() + "/t" + (changePasswordFlag ? "1" : "0");
		}

	}

	private static byte[] generateRandomBytes(int length) {
		SecureRandom sr = new SecureRandom();

		byte[] bytes = new byte[length];
		sr.nextBytes(bytes);

		return bytes;

	}
	
	public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException {
		if (args.length != 1)
			throw new IllegalArgumentException("Application has to get 1 argument, username!");

		Login login = new Login(args[0]);
		login.start();
	}

}

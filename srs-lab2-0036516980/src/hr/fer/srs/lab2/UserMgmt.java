package hr.fer.srs.lab2;

import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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

public class UserMgmt {
	private static final int SALT_LEN = 256;
	private static final int ITERATIONS = 1000;
	private static final int KEY_LENGTH = 256;
	private static final int HASH_PASSWORD_LENGTH = 32;
	private String username;
	private Map<String, LoginEntry> map = new HashMap<>();
	private File file = new File("./resources/safe.txt");	
	private File directory = new File("./resources");	

	public UserMgmt(String username) throws IOException {
		super();
		this.username = username;
		initUserMgmt();
	}

	private void initUserMgmt() throws IOException {
		if (!file.exists()) {
			if(!directory.exists())
				directory.mkdir();
			file.createNewFile();
		}

		readFile();
		if(!map.containsKey(username)) {
			System.out.println("No user " + username);
			System.exit(0);
		}
	}

	private void readFile() throws IOException {
		DataInputStream dis = new DataInputStream(new FileInputStream(file));
		while(dis.available() != 0) {
			String user = dis.readUTF();
			byte[] hashPassword = dis.readNBytes(HASH_PASSWORD_LENGTH);
			byte[] salt = dis.readNBytes(SALT_LEN);
			boolean changePasswordFlag = dis.readBoolean();
			map.put(user, new LoginEntry(hashPassword, salt, changePasswordFlag));
		}
	}


	public void add() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
		Console cnsl = null;
		char[] inputPassword = null;
		char[] repeatedPassword = null;
		do {
			try {
				cnsl = System.console();
				if (cnsl != null) {
					inputPassword = cnsl.readPassword("Password: ");
					repeatedPassword = cnsl.readPassword("Repeat password: ");
					
					if(!Arrays.equals(inputPassword, repeatedPassword)) {
						System.out.println("User add failed. Password mismatch.");
						System.exit(0);
					}
					
					if(!isMinimalComplexityPassword(new String(inputPassword))) {
						System.out.println("New password has to contain at least one uppercase letter, "
								+ "one lowercase letter and a number and has to be at least 8 characters long.");
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
		byte[] salt = generateRandomBytes(SALT_LEN);
		LoginEntry e = new LoginEntry(hashPassword(stringInputPassword, salt), salt, false);

		map.put(username, e);
		System.out.println("User successfully added.");
		writeToFile();
	}
	
	private boolean isMinimalComplexityPassword(String password) {
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
	
	private static byte[] generateRandomBytes(int length) {
		SecureRandom sr = new SecureRandom();

		byte[] bytes = new byte[length];
		sr.nextBytes(bytes);

		return bytes;
	}
	
	private void writeToFile() throws IOException {
		DataOutputStream dos = new DataOutputStream(new FileOutputStream(file));
		for(Entry<String, LoginEntry> e : map.entrySet()) {
			dos.writeUTF(e.getKey());
			dos.write(e.getValue().getHashPassword(), 0, e.getValue().getHashPassword().length);
			dos.write(e.getValue().getSalt(), 0, e.getValue().getSalt().length);
			dos.writeBoolean(e.getValue().isChangePasswordFlag());
		}
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

	public void del() throws IOException {
		map.remove(username);
		writeToFile();
		System.out.println("User successfully removed.");
	}

	public void forcepass() throws IOException {
		LoginEntry e = map.get(username);
		e.setChangePasswordFlag(true);
		writeToFile();
		System.out.println("User will be requested to change password on next login.");
	}

	public void passwd() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
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
					
					if(!isMinimalComplexityPassword(new String(inputPassword))) {
						System.out.println("New password has to contain at least one uppercase letter, "
								+ "one lowercase letter and a number and has to be at least 8 characters long.");
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
		e = new LoginEntry(hashPassword(stringInputPassword, salt), salt, false);
		map.put(username, e);
		
		writeToFile();
		System.out.println("Password change successful.");
	}
	
	public static void main(String[] args) throws Exception {
		if (args.length != 2)
			throw new IllegalArgumentException("Application has to get 2 arguments, action and username!");
		
		UserMgmt userMgmt = new UserMgmt(args[1]);
		if(args[0].equalsIgnoreCase("add")) {
			userMgmt.add();
		} else if(args[0].equalsIgnoreCase("passwd")) {
			userMgmt.passwd();
		} else if(args[0].equalsIgnoreCase("forcepass")) {
			userMgmt.forcepass();
		} else if(args[0].equalsIgnoreCase("del")) {
			userMgmt.del();
		}
	}
}

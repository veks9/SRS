package hr.fer.srs.lab2;

import static hr.fer.srs.lab2.Util.generateRandomBytes;
import static hr.fer.srs.lab2.Util.hashPassword;
import static hr.fer.srs.lab2.Util.isMinimalComplexityPassword;
import static hr.fer.srs.lab2.Util.readFile;
import static hr.fer.srs.lab2.Util.writeToFile;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Map;

public class UserMgmt {
	private static final int SALT_LEN = 256;
	private String username;
	private Map<String, LoginEntry> map;
	private File file = new File("./resources/safe.txt");
	private File directory = new File("./resources");

	public UserMgmt(String username) throws IOException {
		super();
		this.username = username;
		initUserMgmt();
	}

	private void initUserMgmt() throws IOException {
		if (!file.exists()) {
			if (!directory.exists())
				directory.mkdir();
			file.createNewFile();
		}

		map = readFile(file);
		
	}

	public void add() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
		if(map.get((username)) != null) {
			System.out.println("User already exists.");
			System.exit(0);
		}
		Console cnsl = null;
		char[] inputPassword = null;
		char[] repeatedPassword = null;
		do {
			try {
				cnsl = System.console();
				if (cnsl != null) {
					inputPassword = cnsl.readPassword("Password: ");
					repeatedPassword = cnsl.readPassword("Repeat password: ");

					if (!Arrays.equals(inputPassword, repeatedPassword)) {
						System.out.println("User add failed. Password mismatch.");
						System.exit(0);
					}

					if (!isMinimalComplexityPassword(new String(inputPassword), username)) {
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
		} while (true);

		String stringInputPassword = new String(inputPassword);
		byte[] salt = generateRandomBytes(SALT_LEN);
		LoginEntry e = new LoginEntry(hashPassword(stringInputPassword, salt), salt, false);

		map.put(username, e);
		System.out.println("User successfully added.");
		writeToFile(map, file);
	}

	public void del() throws IOException {
		checkIfUserExists();
		map.remove(username);
		writeToFile(map, file);
		System.out.println("User successfully removed.");
	}

	public void forcepass() throws IOException {
		checkIfUserExists();
		LoginEntry e = map.get(username);
		e.setChangePasswordFlag(true);
		writeToFile(map, file);
		System.out.println("User will be requested to change password on next login.");
	}

	public void passwd() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
		checkIfUserExists();
		Console cnsl = null;
		char[] inputPassword = null;
		char[] repeatedPassword = null;
		do {
			try {
				cnsl = System.console();
				if (cnsl != null) {
					inputPassword = cnsl.readPassword("New password: ");
					repeatedPassword = cnsl.readPassword("Repeat new password: ");
					if (!Arrays.equals(inputPassword, repeatedPassword)) {
						System.out.println("Password change failed. Password mismatch.");
						continue;
					}
					
					String inputPasswordString = new String(inputPassword);
					LoginEntry e = map.get(username);
					if (Arrays.equals(hashPassword(inputPasswordString, e.getSalt()), e.getHashPassword())) {
						System.out.println("New password can't be the same as old one!");
						continue;
					}

					if (!isMinimalComplexityPassword(new String(inputPassword), username)) {
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
		} while (true);

		String stringInputPassword = new String(inputPassword);
		LoginEntry e = map.get(username);
		byte[] salt = generateRandomBytes(SALT_LEN);
		e = new LoginEntry(hashPassword(stringInputPassword, salt), salt, false);
		map.put(username, e);

		writeToFile(map, file);
		System.out.println("Password change successful.");
	}
	
	private void checkIfUserExists() {
		if (!map.containsKey(username)) {
			System.out.println("No user " + username);
			System.exit(0);
		}
	}

	public static void main(String[] args) throws Exception {
		if (args.length != 2)
			throw new IllegalArgumentException("Application has to get 2 arguments, action and username!");

		UserMgmt userMgmt = new UserMgmt(args[1]);
		if (args[0].equalsIgnoreCase("add")) {
			userMgmt.add();
		} else if (args[0].equalsIgnoreCase("passwd")) {
			userMgmt.passwd();
		} else if (args[0].equalsIgnoreCase("forcepass")) {
			userMgmt.forcepass();
		} else if (args[0].equalsIgnoreCase("del")) {
			userMgmt.del();
		}
	}
}

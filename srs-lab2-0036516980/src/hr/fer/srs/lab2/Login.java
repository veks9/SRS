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

public class Login {
	private static final int SALT_LEN = 256;
	private String username;
	private Map<String, LoginEntry> map;
	private File file = new File("./resources/safe.txt");
	private long timeoutSeconds = 1L;

	public Login(String username) {
		this.username = username;
	}

	public void start() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, InterruptedException {
		if (!file.exists()) {
			exitError();
		}

		map = readFile(file);

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
		} while (!authenticate(new String(inputPassword)));
		checkIfNewPasswordFlag();

		System.out.println("Login successful.");
	}

	private void checkIfNewPasswordFlag() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
		boolean changePasswordFlag = (map.get(username)).isChangePasswordFlag();
		if (changePasswordFlag) {
			changePassword();
		}
	}

	private void changePassword() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
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

					if (!isMinimalComplexityPassword(inputPasswordString, username)) {
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
	}

	private boolean authenticate(String inputPassword)
			throws InvalidKeySpecException, NoSuchAlgorithmException, InterruptedException {
		if (map.get(username) == null) {
			authenticateFalse();
			return false;
		}
		byte[] mapHashedPassword = (map.get(username)).getHashPassword();
		byte[] salt = (map.get(username)).getSalt();
		byte[] inputHashedPassword = hashPassword(inputPassword, salt);

		if (!Arrays.equals(mapHashedPassword, inputHashedPassword)) {
			authenticateFalse();
			return false;
		}
		return true;
	}

	private void authenticateFalse() throws InterruptedException {
		System.out.println("Username or password incorrect.");
		timeoutSeconds *= 2;
		Thread.sleep(timeoutSeconds * 1000);
	}
	
	private void exitError() {
		System.out.println("Username or password incorrect.");
		System.exit(0);
	}

	public static void main(String[] args) throws Exception {
		if (args.length != 1)
			throw new IllegalArgumentException("Application has to get 1 argument, username!");

		Login login = new Login(args[0]);
		login.start();
	}
}

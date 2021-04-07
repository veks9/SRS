package hr.fer.srs.lab1;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * Klasa predstavlja ulaznu točku za aplikaciju Password Manager.
 * Program se pokreće sa 3 različite vrste argumenata:
 * init master za inicijalizaciju
 * put master webSite password za dodavanje šifre password za stranicu webSite
 * get master webSite za dohvaćanje šifre za stranicu webSite
 * @author vedran
 *
 */
public class Main {

	public static void main(String[] args) {
		if (args.length <= 1)
			throw new IllegalArgumentException("Application has to get from 2 to 4 arguments!");

		PasswordManager manager = new PasswordManager();
		switch (args.length) {
		case 2:
			try {
				manager.initMethod(args[0], args[1]);
			} catch (InvalidKeyException | InvalidKeySpecException | InvalidAlgorithmParameterException
					| IllegalBlockSizeException | BadPaddingException | IOException e) {
				System.out.println(e.getMessage());
			}
			break;
		case 3: case 4:
			try {
				manager.unlock(args);
			} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
					| BadPaddingException | IOException e) {
				System.out.println(e.getMessage());
			}
			break;
		default:
			throw new IllegalArgumentException("Expecting 2, 3 ili 4 arguments!");
		}
	}
}

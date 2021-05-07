package hr.fer.srs.lab2;

public class LoginEntry {
	private byte[] hashPassword;
	private byte[] salt;
	private boolean changePasswordFlag;

	public LoginEntry(byte[] hashPassword, byte[] salt, boolean changePasswordFlag) {
		super();
		this.hashPassword = hashPassword;
		this.salt = salt;
		this.changePasswordFlag = changePasswordFlag;
	}

	public void setHashPassword(byte[] hashPassword) {
		this.hashPassword = hashPassword;
	}

	public byte[] getHashPassword() {
		return hashPassword;
	}

	public byte[] getSalt() {
		return salt;
	}

	public boolean isChangePasswordFlag() {
		return changePasswordFlag;
	}

	public void setSalt(byte[] salt) {
		this.salt = salt;
	}

	public void setChangePasswordFlag(boolean changePasswordFlag) {
		this.changePasswordFlag = changePasswordFlag;
	}
}

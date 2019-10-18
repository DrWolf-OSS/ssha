package it.drwolf.ssha;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.Base64;

public final class SSHA {

	private static byte[] genRandomSalt() {
		java.util.Random randgen = new java.util.Random();
		byte[] saltBytes = new byte[10];
		randgen.nextBytes(saltBytes);
		return saltBytes;
	}

	private static MessageDigest getSHA256() {
		try {
			return MessageDigest.getInstance("SHA-256");
		} catch (java.security.NoSuchAlgorithmException ex) {
			throw new RuntimeException(ex);
		}
	}

	public static String hash(String plaintext) {
		byte[] saltBytes;
		MessageDigest hasher = SSHA.getSHA256();
		saltBytes = SSHA.genRandomSalt();
		hasher.reset();
		hasher.update(plaintext.getBytes(SSHA.UTF8()));
		hasher.update(saltBytes);
		byte[] digestBytes = hasher.digest();
		byte[] outBytes = new byte[saltBytes.length + 32];
		assert digestBytes.length == 32;
		System.arraycopy(digestBytes, 0, outBytes, 0, digestBytes.length);
		System.arraycopy(saltBytes, 0, outBytes, digestBytes.length, saltBytes.length);
		return "{SSHA}" + Base64.getEncoder().encodeToString(outBytes);

	}

	public static boolean matches(String hashText, String plaintext) {
		byte[] hashBytes;
		byte[] plainBytes;
		byte[] saltBytes = null;
		MessageDigest hasher = SSHA.getSHA256();
		if (hashText.indexOf("{SSHA}") == 0) {
			hashText = hashText.substring(6);
		}
		hashBytes = Base64.getDecoder().decode(hashText);
		if (hashBytes.length > 32) {
			saltBytes = new byte[hashBytes.length - 32];
			for (int i = 32; i < hashBytes.length; i++) {
				saltBytes[i - 32] = hashBytes[i];
			}
		}
		if (saltBytes != null) {
			byte[] inBytes = plaintext.getBytes(SSHA.UTF8());
			plainBytes = new byte[inBytes.length + saltBytes.length];
			for (int i = 0; i < inBytes.length; i++) {
				plainBytes[i] = inBytes[i];
			}
			for (int i = 0; i < saltBytes.length; i++) {
				plainBytes[i + inBytes.length] = saltBytes[i];
			}
		} else {
			plainBytes = plaintext.getBytes(SSHA.UTF8());
		}
		hasher.reset();
		hasher.update(plainBytes);
		byte[] matchBytes = hasher.digest();
		assert matchBytes.length == 32;
		for (int i = 0; i < matchBytes.length; i++) {
			if (matchBytes[i] != hashBytes[i]) {
				return false;
			}
		}
		return true;
	}

	private static Charset UTF8() {
		return Charset.forName("UTF-8");
	}

	private SSHA() {
	}
}

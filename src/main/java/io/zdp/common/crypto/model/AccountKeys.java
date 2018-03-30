package io.zdp.common.crypto.model;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;

import org.bitcoinj.core.Base58;

import io.zdp.common.crypto.CryptoUtils;

/**
 * DTO for a private/public key pair in Base58 format
 * 
 * @author sn_1970@yahoo.com
 *
 */
@SuppressWarnings("serial")
public class AccountKeys implements Serializable {

	private String privateKey58;

	private String publicKey58;

	public String getPrivateKey58() {
		return privateKey58;
	}

	public void setPrivateKey58(String privateKey58) {
		this.privateKey58 = privateKey58;
	}

	public String getPublicKey58() {
		return publicKey58;
	}

	public void setPublicKey58(String publicKey58) {
		this.publicKey58 = publicKey58;
	}

	public AccountKeys() {
		super();
	}

	public AccountKeys(String privateKey58) {
		super();
		this.privateKey58 = privateKey58;
		this.publicKey58 = CryptoUtils.getPublicKey58FromPrivateKey58(privateKey58);
	}

	public AccountKeys(String privateKey58, String publicKey58) {
		super();
		this.privateKey58 = privateKey58;
		this.publicKey58 = publicKey58;
	}

	public byte[] sign(String data) throws Exception {

		PrivateKey privateKey = CryptoUtils.getPrivateKeyFromECBigIntAndCurve(new BigInteger(Base58.decode(this.privateKey58)));

		return CryptoUtils.sign(privateKey, data);
	}

	@Override
	public String toString() {
		return "AccountKeys [privateKey58=" + privateKey58 + ", publicKey58=" + publicKey58 + "]";
	}

}
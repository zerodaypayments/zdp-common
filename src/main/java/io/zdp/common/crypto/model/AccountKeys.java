package io.zdp.common.crypto.model;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;

import org.bitcoinj.core.Base58;
import org.bouncycastle.util.encoders.Hex;

import io.zdp.common.crypto.CryptoUtils;
import io.zdp.common.crypto.Cryptos;

/**
 * DTO for a private/public key pair in Base58 format
 * 
 * @author sn_1970@yahoo.com
 *
 */
@SuppressWarnings("serial")
public class AccountKeys implements Serializable {

	private BigInteger priv;

	public AccountKeys(BigInteger priv) {
		super();
		this.priv = priv;
	}

	public String getPrivateKey58() {
		return Base58.encode(priv.toByteArray());
	}

	public String getPublicKey58AsAddress() {
		return "zdp" + Cryptos.toPublicBase58(Cryptos.getPublicKeyFromPrivate(priv));
	}

	public byte[] sign(String data) throws Exception {

		PrivateKey privateKey = CryptoUtils.getPrivateKeyFromECBigIntAndCurve(priv);

		return CryptoUtils.sign(privateKey, data);
	}

	public String getPrivateKeyAsHex() {
		return Hex.toHexString(priv.toByteArray());
	}

	public String getPublicKeyAsHex() {
		return Hex.toHexString(Cryptos.getPublicKeyFromPrivate(priv));
	}

	@Override
	public String toString() {
		return "AccountKeys [getPrivateKey58()=" + getPrivateKey58() + ", getPublicKey58()=" + getPublicKey58AsAddress() + "]";
	}

}
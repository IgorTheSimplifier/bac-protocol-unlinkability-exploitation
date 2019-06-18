/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2015  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id: SecureMessagingWrapper.java 1559 2014-11-14 12:46:26Z martijno $
 */

package org.jmrtd;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.tlv.TLVUtil;

/**
 * An AES secure messaging wrapper for APDUs. Based on TR-SAC.
 *
 * @author Martijn Oostdijk (martijn.oostdijk@gmail.com)
 * 	
 * @version $Revision: $
 */
public class AESSecureMessagingWrapper extends SecureMessagingWrapper implements Serializable {

	private static final long serialVersionUID = 2086301081448345496L;

	private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

	private SecretKey ksEnc, ksMac;
	private transient Cipher sscIVCipher;
	private transient Cipher cipher;
	private transient Mac mac;

	private long ssc;

	/**
	 * Constructs a secure messaging wrapper based on the secure messaging
	 * session keys and the initial value of the send sequence counter.
	 * Used in BAC and EAC 1.
	 * 
	 * @param ksEnc the session key for encryption
	 * @param ksMac the session key for macs
	 * @param ssc the initial value of the send sequence counter
	 * 
	 * @throws GeneralSecurityException when the available JCE providers cannot provide the necessary cryptographic primitives
	 */
	public AESSecureMessagingWrapper(SecretKey ksEnc, SecretKey ksMac, long ssc) throws GeneralSecurityException {
		this.ksEnc = ksEnc;
		this.ksMac = ksMac;
		this.ssc = ssc;

		sscIVCipher = Cipher.getInstance("AES/ECB/NoPadding");
		sscIVCipher.init(Cipher.ENCRYPT_MODE, ksEnc);

		cipher = Cipher.getInstance("AES/CBC/NoPadding");
		/* NOTE: We will init this cipher in wrapCommandAPDU and unwrapResponseAPDU. */

		String macAlg = "AESCMAC";
		mac = Mac.getInstance(macAlg);
		mac.init(ksMac);
	}

	/**
	 * Gets the current value of the send sequence counter.
	 * 
	 * @return the current value of the send sequence counter.
	 */
	public long getSendSequenceCounter() {
		return ssc;
	}

	/**
	 * Wraps the apdu buffer <code>capdu</code> of a command apdu.
	 * As a side effect, this method increments the internal send
	 * sequence counter maintained by this wrapper.
	 *
	 * @param commandAPDU buffer containing the command apdu.
	 *
	 * @return length of the command apdu after wrapping.
	 */
	public CommandAPDU wrap(CommandAPDU commandAPDU) {
		try {
			return wrapCommandAPDU(commandAPDU);
		} catch (GeneralSecurityException gse) {
			LOGGER.severe("Exception: " + gse.getMessage());
			throw new IllegalStateException(gse.toString());
		} catch (IOException ioe) {
			LOGGER.severe("Exception: " + ioe.getMessage());
			throw new IllegalStateException(ioe.toString());
		}
	}

	/**
	 * Unwraps the buffer of a response APDU.
	 * 
	 * @param responseAPDU buffer containing the response apdu
	 * @param len length of the actual response apdu
	 * 
	 * @return a new byte array containing the unwrapped buffer
	 */
	public ResponseAPDU unwrap(ResponseAPDU responseAPDU, int len) {
		try {
			byte[] rapdu = responseAPDU.getBytes();
			if (rapdu.length == 2) {
				// no sense in unwrapping - card indicates some kind of error
				throw new IllegalStateException("Card indicates SM error, SW = " + Integer.toHexString(responseAPDU.getSW() & 0xFFFF));
				/* FIXME: wouldn't it be cleaner to throw a CardServiceException? */
			}
			return new ResponseAPDU(unwrapResponseAPDU(rapdu, len));
		} catch (GeneralSecurityException gse) {
			LOGGER.severe("Exception: " + gse.getMessage());
			throw new IllegalStateException(gse.toString());
		} catch (IOException ioe) {
			LOGGER.severe("Exception: " + ioe.getMessage());
			throw new IllegalStateException(ioe.toString());
		}
	}

	/**
	 * Does the actual encoding of a command APDU.
	 * Based on Section E.3 of ICAO-TR-PKI, especially the examples.
	 *
	 * @param capdu buffer containing the APDU data. It must be large enough to receive the wrapped apdu
	 * @param len length of the APDU data
	 *
	 * @return a byte array containing the wrapped apdu buffer
	 */
	private CommandAPDU wrapCommandAPDU(CommandAPDU commandAPDU) throws GeneralSecurityException, IOException {
		int lc = commandAPDU.getNc();
		int le = commandAPDU.getNe();

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();		

		byte[] maskedHeader = new byte[] { (byte)(commandAPDU.getCLA() | (byte)0x0C), (byte)commandAPDU.getINS(), (byte)commandAPDU.getP1(), (byte)commandAPDU.getP2() };
		byte[] paddedMaskedHeader = Util.padWithCAN(maskedHeader, 16); // 128 bits is 16 bytes

		boolean hasDO85 = ((byte)commandAPDU.getINS() == ISO7816.INS_READ_BINARY2);

		byte[] do8587 = new byte[0];
		byte[] do97 = new byte[0];

		if (le > 0) {
			bOut.reset();
			bOut.write((byte)0x97);
			bOut.write((byte)0x01);
			bOut.write((byte)le);
			do97 = bOut.toByteArray();
		}

		ssc++;
		byte[] sscBytes = getSSCAsBytes(ssc);

		if (lc > 0) {
			/* If we have command data, encrypt it. */
			byte[] data = Util.padWithCAN(commandAPDU.getData(), 16);

			/* Re-initialize cipher, this time with IV based on SSC. */
			cipher.init(Cipher.ENCRYPT_MODE, ksEnc, getIV(sscBytes));

			byte[] ciphertext = cipher.doFinal(data);

			bOut.reset();
			bOut.write(hasDO85 ? (byte)0x85 : (byte)0x87);
			bOut.write(TLVUtil.getLengthAsBytes(ciphertext.length + (hasDO85 ? 0 : 1)));
			if (!hasDO85) { bOut.write(0x01); };
			bOut.write(ciphertext);
			do8587 = bOut.toByteArray();
		}

		bOut.reset();
		bOut.write(paddedMaskedHeader);
		bOut.write(do8587);
		bOut.write(do97);

		byte[] m = bOut.toByteArray();

		bOut.reset();
		bOut.write(sscBytes);
		bOut.write(m);
		bOut.flush();
		byte[] n = Util.padWithCAN(bOut.toByteArray(), 16);

		/* Compute cryptographic checksum... */
		mac.init(ksMac);
		byte[] cc = mac.doFinal(n);
		int ccLength = cc.length;
		if (ccLength != 8) {
			ccLength = 8;
		}

		bOut.reset();
		bOut.write((byte) 0x8E);
		bOut.write(ccLength);
		bOut.write(cc, 0, ccLength);
		byte[] do8E = bOut.toByteArray();

		/* Construct protected apdu... */
		bOut.reset();
		bOut.write(do8587);
		bOut.write(do97);
		bOut.write(do8E);
		byte[] data = bOut.toByteArray();

		CommandAPDU wc = new CommandAPDU(maskedHeader[0], maskedHeader[1], maskedHeader[2], maskedHeader[3], data, 256);
		return wc;
	}

	/**
	 * Does the actual decoding of a response apdu. Based on Section E.3 of
	 * TR-PKI, especially the examples.
	 * 
	 * @param rapdu buffer containing the apdu data
	 * @param len length of the apdu data
	 * 
	 * @return a byte array containing the unwrapped apdu buffer
	 */
	private byte[] unwrapResponseAPDU(byte[] rapdu, int len) throws GeneralSecurityException, IOException {
		long oldssc = ssc;
		try {
			if (rapdu == null || rapdu.length < 2 || len < 2) {
				throw new IllegalArgumentException("Invalid response APDU");
			}
			ssc++;
			byte[] sscBytes = getSSCAsBytes(ssc);
			cipher.init(Cipher.DECRYPT_MODE, ksEnc, getIV(sscBytes));
			DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(rapdu));
			byte[] data = new byte[0];
			short sw = 0;
			boolean finished = false;
			byte[] cc = null;
			while (!finished) {
				int tag = inputStream.readByte();
				switch (tag) {
				case (byte) 0x87: data = readDO87(inputStream, false); break;
				case (byte) 0x85: data = readDO87(inputStream, true); break;
				case (byte) 0x99: sw = readDO99(inputStream); break;
				case (byte) 0x8E: cc = readDO8E(inputStream); finished = true; break;
				}
			}
			if (!checkMac(rapdu, cc)) {
				throw new IllegalStateException("Invalid MAC");
			}
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			bOut.write(data, 0, data.length);
			bOut.write((sw & 0xFF00) >> 8);
			bOut.write(sw & 0x00FF);
			return bOut.toByteArray();
		} finally {
			/*
			 * If we fail to unwrap, at least make sure we have the same counter
			 * as the ICC, so that we can continue to communicate using secure
			 * messaging...
			 */
			if (ssc == oldssc) {
				ssc++;
			}
		}
	}

	/**
	 * The <code>0x87</code> tag has already been read.
	 * 
	 * @param inputStream inputstream to read from
	 */
	private byte[] readDO87(DataInputStream inputStream, boolean do85) throws IOException, GeneralSecurityException {
		/* Read length... */
		int length = 0;
		int buf = inputStream.readUnsignedByte();
		if ((buf & 0x00000080) != 0x00000080) {
			/* Short form */
			length = buf;
			if(!do85) {
				buf = inputStream.readUnsignedByte(); /* should be 0x01... */
				if (buf != 0x01) {
					throw new IllegalStateException("DO'87 expected 0x01 marker, found " + Integer.toHexString(buf & 0xFF));
				}
			}
		} else {
			/* Long form */
			int lengthBytesCount = buf & 0x0000007F;
			for (int i = 0; i < lengthBytesCount; i++) {
				length = (length << 8) | inputStream.readUnsignedByte();
			}
			if(!do85) {
				buf = inputStream.readUnsignedByte(); /* should be 0x01... */
				if (buf != 0x01) {
					throw new IllegalStateException("DO'87 expected 0x01 marker");
				}
			}
		}
		if(!do85) {
			length--; /* takes care of the extra 0x01 marker... */
		}
		/* Read, decrypt, unpad the data... */
		byte[] ciphertext = new byte[length];
		inputStream.readFully(ciphertext);
		byte[] paddedData = cipher.doFinal(ciphertext);
		byte[] data = Util.unpad(paddedData);
		return data;
	}

	/**
	 * The <code>0x99</code> tag has already been read.
	 * 
	 * @param in inputstream to read from.
	 */
	private short readDO99(DataInputStream in) throws IOException {
		int length = in.readUnsignedByte();
		if (length != 2) {
			throw new IllegalStateException("DO'99 wrong length");
		}
		byte sw1 = in.readByte();
		byte sw2 = in.readByte();
		return (short) (((sw1 & 0x000000FF) << 8) | (sw2 & 0x000000FF));
	}

	/**
	 * The <code>0x8E</code> tag has already been read.
	 * 
	 * @param inputStream inputstream to read from.
	 */
	private byte[] readDO8E(DataInputStream inputStream) throws IOException, GeneralSecurityException {
		int length = inputStream.readUnsignedByte();
		if (length != 8) {
			throw new IllegalStateException("DO'8E wrong length");
		}
		byte[] cc1 = new byte[8];
		inputStream.readFully(cc1);
		return cc1;
	}

	private boolean checkMac(byte[] rapdu, byte[] cc1) throws GeneralSecurityException {
		return true; // FIXME: Note this will be a 16 byte Mac?
	}

	/**
	 * Gets the IV by encrypting the SSC.
	 * 
	 * AES uses IV = E K_Enc , SSC), see ICAO SAC TR Section 4.6.3.
	 * 
	 * @param sscBytes the SSC as blocksize aligned byte array
	 */
	private IvParameterSpec getIV(byte[] sscBytes) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] encryptedSSC = sscIVCipher.doFinal(sscBytes);
		IvParameterSpec ivParams = new IvParameterSpec(encryptedSSC);
		return ivParams;
	}

	/**
	 * Gets the SSC as bytes.
	 * 
	 * @param ssc
	 * 
	 * @return the ssc as a 16 byte array
	 */
	private byte[] getSSCAsBytes(long ssc) {
		try {
			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(16);
			byteArrayOutputStream.write(0x00);
			byteArrayOutputStream.write(0x00);
			byteArrayOutputStream.write(0x00);
			byteArrayOutputStream.write(0x00);
			byteArrayOutputStream.write(0x00);
			byteArrayOutputStream.write(0x00);
			byteArrayOutputStream.write(0x00);
			byteArrayOutputStream.write(0x00);

			/* A long will take 8 bytes. */
			DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
			dataOutputStream.writeLong(ssc);
			dataOutputStream.close();
			return byteArrayOutputStream.toByteArray();
		} catch (IOException ioe) {
			LOGGER.warning("Exception: " + ioe.getMessage());
		}
		return null;
	}
}

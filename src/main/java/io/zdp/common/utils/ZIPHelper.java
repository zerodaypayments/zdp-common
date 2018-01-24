package io.zdp.common.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class ZIPHelper {

	private static final Logger log = LoggerFactory.getLogger(ZIPHelper.class);

	public static byte[] compress(String string) {
		try {
			return compress(string.getBytes(StandardCharsets.UTF_8.displayName()));
		} catch (UnsupportedEncodingException e) {
			log.error("Error: ", e);
		}
		return null;
	}

	public static byte[] compress(byte[] data) {

		// Create the compressor with highest level of compression
		final Deflater compressor = new Deflater();
		compressor.setLevel(Deflater.BEST_COMPRESSION);

		// Give the compressor the data to compress
		compressor.setInput(data);
		compressor.finish();

		// Create an expandable byte array to hold the compressed data.
		// You cannot use an array that's the same size as the orginal because
		// there is no guarantee that the compressed data will be smaller than
		// the uncompressed data.
		final ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length);

		// Compress the data
		byte[] buf = new byte[1024];
		while (!compressor.finished()) {
			final int count = compressor.deflate(buf);
			bos.write(buf, 0, count);
		}
		try {
			bos.close();
		} catch (IOException e) {
		}

		// Get the compressed data
		final byte[] compressedData = bos.toByteArray();

		compressor.end();

		return compressedData;
	}

	public static byte[] decompressAsBytes(byte[] data) {

		if (data == null) {
			return null;
		}

		// Create the decompressor and give it the data to compress
		final Inflater decompressor = new Inflater();
		decompressor.setInput(data);

		// Create an expandable byte array to hold the decompressed data
		final ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length);

		// Decompress the data
		final byte[] buf = new byte[1024];
		while (!decompressor.finished()) {
			try {
				final int count = decompressor.inflate(buf);
				bos.write(buf, 0, count);
			} catch (DataFormatException e) {
			}
		}
		try {
			bos.close();
		} catch (IOException e) {
		}

		// Get the decompressed data
		final byte[] decompressedData = bos.toByteArray();

		decompressor.end();

		return decompressedData;
	}

	public static String decompress(byte[] data) {

		if (data == null) {
			return null;
		}

		// Get the decompressed data
		final byte[] decompressedData = decompressAsBytes(data);

		try {
			return new String(decompressedData, StandardCharsets.UTF_8.displayName());
		} catch (UnsupportedEncodingException e) {
			log.error("Error: ", e);
		}
		return null;
	}

}

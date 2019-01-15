package com.liferay.portal.saml.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;

import javax.servlet.ServletConfig;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.binary.Base64;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * 
 * @author Thao Nguyen
 * 
 */
public class Util {
	protected final static String DEFAULT_CHARSET = "UTF8";

	/**
	 * Generates a unique Id for Authentication Requests
	 * 
	 * @return generated unique ID
	 */
	public static String createID() {

		byte[] bytes = new byte[20]; // 160 bit

		new Random().nextBytes(bytes);

		char[] charMapping = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
				'j', 'k', 'l', 'm', 'n', 'o', 'p' };

		char[] chars = new char[40];

		for (int i = 0; i < bytes.length; i++) {
			int left = (bytes[i] >> 4) & 0x0f;
			int right = bytes[i] & 0x0f;
			chars[i * 2] = charMapping[left];
			chars[i * 2 + 1] = charMapping[right];
		}

		return String.valueOf(chars);
	}

	public static String getConfiguration(ServletConfig servletConfig,
			String configuration) {
		return servletConfig.getInitParameter(configuration);

	}

	/**
	 * Decoding and deflating the encoded AuthReq
	 * 
	 * @param encodedStr
	 *            encoded AuthReq
	 * @return decoded AuthReq
	 */
	public static String decode(String encodedStr) throws Exception {
		try {
			org.apache.commons.codec.binary.Base64 base64Decoder = new org.apache.commons.codec.binary.Base64();
			byte[] xmlBytes = encodedStr.getBytes("UTF-8");
			byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);
			String decodedStr = new String(base64DecodedByteArray);
			return decodedStr;
		} catch (IOException e) {
			throw new Exception("Error when decoding the SAML Request.", e);

		}

	}

	/**
	 * This method removes spaces from string
	 * 
	 * @param s
	 *            orginal string
	 * @return A string without any spaces
	 */
	protected String removeSpaces(String s) {
		StringTokenizer st = new StringTokenizer(s, " ", false);
		String t = "";
		while (st.hasMoreElements())
			t += st.nextElement();
		return t;
	}

	/**
	 * This method generates a random alphabetic String
	 * 
	 * @return A random alphabetic String
	 */
	public static String randomString() {

		String AB = "abcdefghijklmnopqrstuvwyz";
		Random rnd = new Random();
		StringBuilder sb = new StringBuilder(8);
		for (int i = 0; i < 8; i++)
			sb.append(AB.charAt(rnd.nextInt(AB.length())));
		return sb.toString();
	}

	/**
	 * Allocates and returns a Deflater-object.
	 * 
	 * @return A Deflater-object.
	 */
	private static Deflater getDeflater() {
		return new Deflater(Constants.COMPRESSION_LEVEL, Constants.USE_GZIP);
	}

	/**
	 * Deflates a given byte-array and returns the result as a byte-array.
	 * 
	 * @param theBytes
	 *            a byte-array that is to be deflated.
	 * @return A byte-array with the deflated bytes.
	 * @throws IOException
	 *             If an I/O has occurred.
	 */
	public static byte[] deflateBytes(byte[] theBytes) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(
				baos, getDeflater());
		deflaterOutputStream.write(theBytes, 0, theBytes.length);
		deflaterOutputStream.close();
		return baos.toByteArray();
	}

	/**
	 * Deflates a string and returns the result as a byte-array.
	 * 
	 * @param toDeflate
	 *            The String to be compressed.
	 * @return a byte-array with the compressed string.
	 * @throws IOException
	 *             If the string cannot be transformed to UTF-8.
	 */
	public static byte[] deflateString(String toDeflate) throws IOException {
		return deflateBytes(toDeflate.getBytes("UTF-8"));
	}

	/**
	 * Uncompress a byte array.
	 * 
	 * @param bytesToInflate
	 *            Bytes to uncompress
	 * @return The uncompressed byte array
	 * @throws DataFormatException
	 *             If inputdata can't be inflated
	 */
	public static byte[] inflateBytes(byte[] bytesToInflate)
			throws DataFormatException {
		Inflater decompresser = new Inflater(Constants.USE_GZIP);
		decompresser.setInput(bytesToInflate);
		byte[] result = new byte[bytesToInflate.length * 10];
		int resultLength = decompresser.inflate(result);
		decompresser.end();

		// Kopierer resultatet til et nytt array med rett lengde
		byte[] resultArr = new byte[resultLength];
		System.arraycopy(result, 0, resultArr, 0, resultLength);
		return resultArr;

	}

	/**
	 * Deflates and converts a String to base64, and returns the result as a
	 * String.
	 *
	 * @param toEncode
	 *            The String to be compressed and converted to base64.
	 * @return A String that is deflated and converted to base64.
	 * @throws IOException
	 *             If the String cannot be converted to UTF-8.
	 */
	public static String deflateAndBase64EncodeString(String toEncode)
			throws IOException {
		return new String(Base64.encodeBase64(deflateString(toEncode)));
	}

	/**
	 * Decodes a byte-array from base64 and returns a new byte-array with the
	 * decoded bytes.
	 *
	 * @param bytes
	 *            The bytes to be decoded from base64.
	 * @return The resulting byte-array.
	 * 
	 */
	public static byte[] base64Decode(byte[] bytes) {
		return Base64.decodeBase64(bytes);
	}

	/**
	 * Decodes a <em>String</em> from base64 and returns a new byte-array with
	 * the decoded bytes.
	 *
	 * @param str
	 *            The String to be decoded.
	 * @return The resulting array of bytes.
	 * @throws UnsupportedEncodingException
	 *             If the String cannot be converted to <em>UTF-8</em>.
	 */
	public static byte[] base64Decode(String str)
			throws UnsupportedEncodingException {
		return base64Decode(str.getBytes("UTF-8"));
	}

	public static Map<String, String> getResult(XMLObject responseXmlObj) {
		if (responseXmlObj.getDOM().getNodeName()
				.equals("saml2p:LogoutResponse")) {
			return null;
		}

		Response response = (Response) responseXmlObj;

		Assertion assertion = response.getAssertions().get(0);
		Map<String, String> resutls = new HashMap<String, String>();

		/*
		 * If the request has failed, the IDP shouldn't send an assertion. SSO
		 * profile spec 4.1.4.2 <Response> Usage
		 */
		if (assertion != null) {

			String subject = assertion.getSubject().getNameID().getValue();
			resutls.put("Subject", subject); // get the subject

			// get the authentication session index to be used in single logout
			List<AuthnStatement> authnStatements = assertion
					.getAuthnStatements();
			if (authnStatements != null) {
				for (AuthnStatement stmt : authnStatements) {
					String sessionIndex = stmt.getSessionIndex();
					// set this in the session to be used later in single logout
					resutls.put("sessionIndex", sessionIndex);
				}
			}

			List<AttributeStatement> attributeStatementList = assertion
					.getAttributeStatements();

			if (attributeStatementList != null) {
				// we have received attributes of user
				Iterator<AttributeStatement> attribStatIter = attributeStatementList
						.iterator();
				while (attribStatIter.hasNext()) {
					AttributeStatement statment = attribStatIter.next();
					List<Attribute> attributesList = statment.getAttributes();
					Iterator<Attribute> attributesIter = attributesList
							.iterator();
					while (attributesIter.hasNext()) {
						Attribute attrib = attributesIter.next();
						Element value = attrib.getAttributeValues().get(0)
								.getDOM();
						String attribValue = value.getTextContent();
						resutls.put(attrib.getName(), attribValue);
					}
				}
			}
		}
		return resutls;
	}

	public static XMLObject unmarshall(String responseMessage)
			throws ConfigurationException, ParserConfigurationException,
			SAXException, IOException, UnmarshallingException {

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder docBuilder = documentBuilderFactory
				.newDocumentBuilder();

		ByteArrayInputStream is = new ByteArrayInputStream(
				responseMessage.getBytes());

		Document document = docBuilder.parse(is);
		Element element = document.getDocumentElement();
		UnmarshallerFactory unmarshallerFactory = Configuration
				.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory
				.getUnmarshaller(element);
		return unmarshaller.unmarshall(element);

	}

	/**
	 * Read bytes from inputstream till empty and convert to string. based on
	 * supplied charset encoding Inputstream is NOT closed at return.
	 * 
	 * @param is
	 *            The inputstream to read from.
	 * @param enc
	 *            The character encoding to use in conversion.
	 * @param doClose
	 *            Should the underlying inputstream be closed. <true|false>
	 * @return String containing the data from the inputstream
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @category utility method
	 * @see http://java.sun.com/j2se/1.5.0/docs/guide/intl/encoding.doc.html
	 */

	public static String stream2string(InputStream is, String enc,
			boolean doClose) throws IOException {

		int xRead = 0;
		byte[] ba = new byte[512];
		DataInputStream isInput = new DataInputStream(new BufferedInputStream(
				is));
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		// Retrieve message as bytes and put them in a string
		while ((xRead = isInput.read(ba)) != -1) {
			bos.write(ba, 0, xRead);
			// clear the buffer
			// Arrays.fill(ba, (byte) 0); /// Why? Just to be sure?
		}
		return (bos.toString(enc)); // RH, 20080714, n
	}

	/**
	 * Stream2string.
	 * 
	 * @param is
	 *            the is
	 * @param close
	 *            the close
	 * @return the string
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String stream2string(InputStream is, boolean close)
			throws IOException {
		return stream2string(is, DEFAULT_CHARSET, close);
	}

	/**
	 * Stream2string.
	 * 
	 * @param is
	 *            the is
	 * @param enc
	 *            the enc
	 * @return the string
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String stream2string(InputStream is, String enc)
			throws IOException {
		return stream2string(is, enc, true);
	}

	/**
	 * Stream2string.
	 * 
	 * @param is
	 *            the is
	 * @return the string
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String stream2string(InputStream is) throws IOException {
		return stream2string(is, DEFAULT_CHARSET, true);
	}

	public static void main(String args[]) {

		String encodedMessage ="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWwycDpSZXNwb25zZSBEZXN0aW5hdGlvbj0iaHR0cDovL3BvcnRhbC1kZXYudm5mb3Jlc3QuZ292LnZuL2MvcG9ydGFsL2xvZ2luIiBJRD0ibmtnYWhvZW5qbm5hcGNuZ2JmaWpjYW9sY21sZGJoYW9rY21ranBwYSIgSW5SZXNwb25zZVRvPSIwIiBJc3N1ZUluc3RhbnQ9IjIwMTUtMDEtMjlUMTA6Mjk6NDguNzQ1WiIgVmVyc2lvbj0iMi4wIiB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI+PHNhbWwyOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSIgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmxvY2FsaG9zdDwvc2FtbDI6SXNzdWVyPjxzYW1sMnA6U3RhdHVzPjxzYW1sMnA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1sMnA6U3RhdHVzPjxzYW1sMjpBc3NlcnRpb24gSUQ9InBsZ25wbnBua2tsYWZib29nYWxqZWpuZmhnb2ZiYWJrbm1tYnBjbGIiIElzc3VlSW5zdGFudD0iMjAxNS0wMS0yOVQxMDoyOTo0OC43NDVaIiBWZXJzaW9uPSIyLjAiIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48c2FtbDI6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5sb2NhbGhvc3Q8L3NhbWwyOklzc3Vlcj48c2FtbDI6U3ViamVjdD48c2FtbDI6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIj5hZG1pbjwvc2FtbDI6TmFtZUlEPjxzYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz0iMCIgTm90T25PckFmdGVyPSIyMDE1LTAxLTI5VDEwOjM0OjQ4Ljc0NVoiIFJlY2lwaWVudD0iaHR0cDovL3BvcnRhbC1kZXYudm5mb3Jlc3QuZ292LnZuL2MvcG9ydGFsL2xvZ2luIi8+PC9zYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uPjwvc2FtbDI6U3ViamVjdD48c2FtbDI6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMTUtMDEtMjlUMTA6Mjk6NDguNzQ1WiIgTm90T25PckFmdGVyPSIyMDE1LTAxLTI5VDEwOjM0OjQ4Ljc0NVoiPjxzYW1sMjpBdWRpZW5jZVJlc3RyaWN0aW9uPjxzYW1sMjpBdWRpZW5jZT5wb3J0YWw8L3NhbWwyOkF1ZGllbmNlPjwvc2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWwyOkNvbmRpdGlvbnM+PHNhbWwyOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNS0wMS0yOVQxMDoyOTo0OC43NDZaIiBTZXNzaW9uSW5kZXg9Ijk3ZDQ2OTNjLTA3MTYtNGQzMS1hOTUxLTU1MmJiZTlkNzgyMSI+PHNhbWwyOkF1dGhuQ29udGV4dD48c2FtbDI6QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmQ8L3NhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDI6QXV0aG5Db250ZXh0Pjwvc2FtbDI6QXV0aG5TdGF0ZW1lbnQ+PHNhbWwyOkF0dHJpYnV0ZVN0YXRlbWVudD48c2FtbDI6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly93c28yLm9yZy9jbGFpbXMvbGFzdG5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFkbWluPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48L3NhbWwyOkF0dHJpYnV0ZT48c2FtbDI6QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly93c28yLm9yZy9jbGFpbXMvZnVsbG5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmFkbWluPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48L3NhbWwyOkF0dHJpYnV0ZT48L3NhbWwyOkF0dHJpYnV0ZVN0YXRlbWVudD48L3NhbWwyOkFzc2VydGlvbj48L3NhbWwycDpSZXNwb25zZT4=";
		try {
			DefaultBootstrap.bootstrap();
			String decodedMessage = Util.decode(encodedMessage);
			System.out.println("decodedMessage:" + decodedMessage);
			/*XMLObject xmlObj = Util.unmarshall(decodedMessage);
			Map<String, String> result = Util.getResult(xmlObj);
			System.out.println(result);*/
		} catch (Exception e) {

			e.printStackTrace();
		}
	}

}

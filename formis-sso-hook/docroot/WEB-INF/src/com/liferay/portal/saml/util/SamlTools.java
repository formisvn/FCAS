package com.liferay.portal.saml.util;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class SamlTools {
	/**
	 * Gets the node.
	 * 
	 * @param node
	 *            the node
	 * @param sSearch
	 *            the s search
	 * @return the node
	 */
	public static Node getNode(Node node, String sSearch) {
		Node nResult = null;
		NodeList nodeList = node.getChildNodes();
		for (int i = 0; i < nodeList.getLength() && nResult == null; i++) {
			if (sSearch.equals(nodeList.item(i).getLocalName()))
				nResult = nodeList.item(i);
			else
				nResult = getNode(nodeList.item(i), sSearch);
		}
		return nResult;
	}

	/**
	 * Build Logout Response. <br>
	 * 
	 * @param issuer
	 *            String with issuer.
	 * @param statusCodeValue
	 *            String with ???.
	 * @param inResponseTo
	 *            String with ???.
	 * @return the logout response
	 * @throws ASelectException
	 *             If building logout response fails.
	 */
	@SuppressWarnings("unchecked")
	public static LogoutResponse buildLogoutResponse(String issuer,
			String statusCodeValue, String inResponseTo) throws Exception {
		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration
				.getBuilderFactory();
		SAMLObjectBuilder<LogoutResponse> logoutResponseBuilder = (SAMLObjectBuilder<LogoutResponse>) builderFactory
				.getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME);
		LogoutResponse logoutResponse = logoutResponseBuilder.buildObject();

		logoutResponse.setID(Util.randomString());
		logoutResponse.setVersion(SAMLVersion.VERSION_20);
		logoutResponse.setIssueInstant(new DateTime());

		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
				.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status status = statusBuilder.buildObject();
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
				.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		StatusCode statusCode = statusCodeBuilder.buildObject();
		statusCode.setValue(statusCodeValue);
		status.setStatusCode(statusCode);
		logoutResponse.setStatus(status);

		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuerObject = issuerBuilder.buildObject();
		issuerObject.setValue(issuer);
		logoutResponse.setIssuer(issuerObject);
		logoutResponse.setInResponseTo(inResponseTo);

		MarshallerFactory factory = org.opensaml.xml.Configuration
				.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(logoutResponse);
		try {
			Node node = marshaller.marshall(logoutResponse);
			String msg = XMLHelper.prettyPrintXML(node);
		} catch (MarshallingException e) {

			throw e;
		}
		return logoutResponse;
	}

	/**
	 * Helper method that marshalls the given message.
	 * 
	 * @param message
	 *            message the marshall and serialize
	 * @return marshalled message
	 * @throws MessageEncodingException
	 *             thrown if the give message can not be marshalled into its DOM
	 *             representation
	 */
	public static Element marshallMessage(XMLObject message)
			throws MessageEncodingException {

		try {
			Marshaller marshaller = org.opensaml.xml.Configuration
					.getMarshallerFactory().getMarshaller(message);
			if (marshaller == null) {

			}
			Element messageElem = marshaller.marshall(message);
			// systemLogger.log(Level.INFO, MODULE, sMethod,
			// "Marshalled message into DOM:\n"+XMLHelper.nodeToString(messageElem));

			return messageElem;
		} catch (MarshallingException e) {
			throw new MessageEncodingException(
					"Encountered error marshalling message into its DOM representation",
					e);
		}
	}

	/**
	 * Set saml20 appropriate headers and send the HTTP SOAP response and close
	 * the stream.
	 * 
	 * @param response
	 *            , the servletresponse
	 * @param envelope
	 *            , the (soapenvelope) string to send
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void sendSOAPResponse(HttpServletResponse response,
			String envelope) throws IOException {
		final String CONTENT_TYPE = "text/xml; charset=utf-8";

		response.setContentType(CONTENT_TYPE);
		response.setCharacterEncoding("UTF-8"); // RH, 20131230, n
		response.setHeader("Pragma", "no-cache");
		response.setHeader("Cache-Control",
				"no-cache, no-store, must-revalidate");

		// RH, 20131230, so
		// ServletOutputStream sos = response.getOutputStream();
		// sos.print(envelope);
		// sos.println("\r\n\r\n");
		// RH, 20131230, eo
		// RH, 20131230, sn
		java.io.PrintWriter sos = response.getWriter();
		sos.write(envelope);
		sos.write("\r\n\r\n\r\n"); // Backward compatibility
		sos.close();
		// RH, 20131230, en
	}

}

package com.liferay.portal.saml.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.exception.SystemException;
import com.liferay.portal.model.User;
import com.liferay.portal.util.PortalUtil;

public class SamlConsumerManager {
	private static final String SSO_SESSION_INDEX = "sessionIndex";

	private String consumerUrl = null;
	private String authReqRandomId = Integer.toHexString(new Double(Math
			.random()).intValue());
	private String relayState = null;
	private String issuerId = null;
	private String idpUrl = null;
	private String attribIndex = null;
	private static Log _log = LogFactory.getLog(SamlConsumerManager.class);

	public SamlConsumerManager(ServletConfig servletConfig)
			throws ConfigurationException {

		consumerUrl = Util.getConfiguration(servletConfig, "ConsumerUrl");
		idpUrl = Util.getConfiguration(servletConfig, "IdpUrl");
		issuerId = Util.getConfiguration(servletConfig, "Issuer");
		attribIndex = Util.getConfiguration(servletConfig,
				"AttributeConsumingServiceIndex");

		/* Initializing the OpenSAML library, loading default configurations */
		DefaultBootstrap.bootstrap();
	}

	public SamlConsumerManager(String consumerUrl, String issuerId,
			String idpUrl, String attribIndex) throws ConfigurationException {
		super();
		this.consumerUrl = consumerUrl;
		this.issuerId = issuerId;
		this.idpUrl = idpUrl;
		this.attribIndex = attribIndex;
		DefaultBootstrap.bootstrap();
	}

	/**
	 * Returns the redirection URL with the appended SAML2 Request message
	 * 
	 * @param request
	 * 
	 * @return redirectionUrl<dependency> <groupId>org.opensaml</groupId>
	 *         <artifactId>opensaml</artifactId> <version>2.2.3</version>
	 *         </dependency>
	 */
	public String buildRequestMessage(HttpServletRequest request) {
		RequestAbstractType requestMessage = null;
		// time to build the authentication request message

		String encodedRequestMessage = "";
		try {
			if (request.getAttribute("logout") == null) {
				requestMessage = buildAuthnRequestObject();

			} else { // ok, user needs to be single logged out
				requestMessage = buildLogoutRequest(request);

			}
			encodedRequestMessage = encodeRequestMessage(requestMessage);
		} catch (MarshallingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (PortalException e) {
			e.printStackTrace();
		} catch (SystemException e) {
			e.printStackTrace();
		}
		_log.error("Logout requestMessage:[" + requestMessage + "]");
		return idpUrl + "?SAMLRequest=" + encodedRequestMessage
				+ "&RelayState=" + relayState;
	}

	private LogoutRequest buildLogoutRequest(HttpServletRequest request)
			throws PortalException, SystemException {
		User curUser = PortalUtil.getUser(request);
		LogoutRequest logoutReq = new LogoutRequestBuilder().buildObject();
		String idPSession = (String) request.getSession().getAttribute(
				SamlPropsKeys.SAM_SSO_SESS_INDEX);
		logoutReq.setID(Util.createID());
		DateTime issueInstant = new DateTime();
		logoutReq.setIssueInstant(issueInstant);
		logoutReq.setNotOnOrAfter(new DateTime(
				issueInstant.getMillis() + 5 * 60 * 1000));

		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(issuerId);
		logoutReq.setIssuer(issuer);

		NameID nameId = new NameIDBuilder().buildObject();
		nameId.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
		nameId.setValue(curUser.getScreenName());
		logoutReq.setNameID(nameId);

		SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();
		sessionIndex.setSessionIndex(idPSession);
		logoutReq.getSessionIndexes().add(sessionIndex);
		logoutReq.setReason("Single Logout");
		_log.error("Logout Request:[" + logoutReq.toString() + "]");
		return logoutReq;
	}

	private AuthnRequest buildAuthnRequestObject() {

		/* Building Issuer object */
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject(
				"urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "samlp");
		issuer.setValue(issuerId);

		/* NameIDPolicy */
		NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
		NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
		nameIdPolicy
				.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
		nameIdPolicy.setSPNameQualifier("Isser");
		nameIdPolicy.setAllowCreate(new Boolean(true));

		/* AuthnContextClass */
		AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
		AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder
				.buildObject("urn:oasis:names:tc:SAML:2.0:assertion",
						"AuthnContextClassRef", "saml");
		authnContextClassRef
				.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

		/* AuthnContex */
		RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
		RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder
				.buildObject();
		requestedAuthnContext
				.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
		requestedAuthnContext.getAuthnContextClassRefs().add(
				authnContextClassRef);

		DateTime issueInstant = new DateTime();

		/* Creation of AuthRequestObject */
		AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
		AuthnRequest authRequest = authRequestBuilder
				.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",
						"AuthnRequest", "samlp");
		authRequest.setForceAuthn(new Boolean(false));
		authRequest.setIsPassive(new Boolean(false));
		authRequest.setIssueInstant(issueInstant);
		authRequest
				.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		authRequest.setAssertionConsumerServiceURL(consumerUrl);
		authRequest.setIssuer(issuer);
		authRequest.setNameIDPolicy(nameIdPolicy);
		authRequest.setRequestedAuthnContext(requestedAuthnContext);
		authRequest.setID(authReqRandomId);
		authRequest.setVersion(SAMLVersion.VERSION_20);

		/* Requesting Attributes. This Index value is registered in the IDP */
		;
		if (attribIndex != null && !attribIndex.equals("")) {
			authRequest.setAttributeConsumingServiceIndex(Integer
					.parseInt(attribIndex));
		}

		return authRequest;
	}

	private String encodeRequestMessage(RequestAbstractType requestMessage)
			throws MarshallingException, IOException {

		Marshaller marshaller = Configuration.getMarshallerFactory()
				.getMarshaller(requestMessage);
		Element authDOM = marshaller.marshall(requestMessage);

		Deflater deflater = new Deflater(Deflater.DEFLATED, true);
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(
				byteArrayOutputStream, deflater);

		StringWriter rspWrt = new StringWriter();
		XMLHelper.writeNode(authDOM, rspWrt);
		deflaterOutputStream.write(rspWrt.toString().getBytes());
		deflaterOutputStream.close();
		/* Encoding the compressed message */
		String encodedRequestMessage = Base64.encodeBytes(
				byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
		return URLEncoder.encode(encodedRequestMessage, "UTF-8").trim();
	}

	public Map<String, String> processResponseMessage(String responseMessage,
			HttpServletRequest request) {

		XMLObject responseXmlObj = null;

		try {
			responseXmlObj = unmarshall(responseMessage);

		} catch (ConfigurationException e) {
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnmarshallingException e) {
			e.printStackTrace();
		}

		return getResult(responseXmlObj, request);
	}

	public XMLObject unmarshall(String responseMessage)
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

	/*
	 * Process the response and returns the results
	 */
	private Map<String, String> getResult(XMLObject responseXmlObj,
			HttpServletRequest request) {

		if (responseXmlObj.getDOM().getNodeName()
				.equals("saml2p:LogoutResponse")) {
			_log.info("SAML Logout response received");
			return null;
		}

		Response response = (Response) responseXmlObj;
		_log.info("SAML Response: " + response);

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
					resutls.put(Constants.IDP_SESSION, sessionIndex);
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

	@Override
	public String toString() {
		return "SamlConsumerManager [consumerUrl=" + consumerUrl
				+ ", authReqRandomId=" + authReqRandomId + ", relayState="
				+ relayState + ", issuerId=" + issuerId + ", idpUrl=" + idpUrl
				+ ", attribIndex=" + attribIndex + "]";
	}
}

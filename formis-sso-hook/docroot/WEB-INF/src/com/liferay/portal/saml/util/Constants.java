package com.liferay.portal.saml.util;

public class Constants {

	/**
	 * The compression-level when compressing SAMLRequests.
	 */
	public static final int COMPRESSION_LEVEL = 5;

	/**
	 * Whenever to use gzip-algorithm when compressing URLs.
	 */
	public static final boolean USE_GZIP = true;

	/**
	 * Message keys
	 * */
	public static final String SAML_CONF_FILE = "/sso.properties";
	public static final String SAML_IDP_URL_KEY = "org.formis.sso.idp.url";
	public static final String SAML_CONSUMER_URL_KEY = "org.formis.sso.consumer.url";
	public static final String SAML_ISSUE_ID_KEY = "org.formis.sso.issue.id";
	public static final String SAML_ATTRBUTE_INDEX_KEY = "org.formis.sso.atrribute.index";
	public static final String HTTP_POST_PARAM_SAML2_AUTH_REQ = "SAMLRequest";
	public static final String HTTP_POST_PARAM_SAML2_RESP = "SAMLResponse";
	public static final String IDP_SESSION = "IdPSession";
	public static final String LAST_ACCESSED_TIME = "lastAccessed";
	public static final String AUTHENTICATED = "authenticated";

	public Constants() {
		super();
	}

}

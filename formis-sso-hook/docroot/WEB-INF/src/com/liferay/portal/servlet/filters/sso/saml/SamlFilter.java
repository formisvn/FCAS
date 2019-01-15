package com.liferay.portal.servlet.filters.sso.saml;

import java.net.URL;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import com.liferay.portal.kernel.exception.SystemException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.servlet.BaseFilter;
import com.liferay.portal.kernel.util.GetterUtil;
import com.liferay.portal.kernel.util.PrefsPropsUtil;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.saml.util.Constants;
import com.liferay.portal.saml.util.SSOSessionManager;
import com.liferay.portal.saml.util.SamlConsumerManager;
import com.liferay.portal.saml.util.SamlPropsKeys;
import com.liferay.portal.saml.util.SamlTools;
import com.liferay.portal.saml.util.SoapManager;
import com.liferay.portal.saml.util.Util;
import com.liferay.portal.util.PortalUtil;

public class SamlFilter extends BaseFilter {
	private String screenName = "";
	private String comsumerURL;
	private String idpURL;
	private String issueId;
	private String attribIndex;
	private String sessionIndex;

	@Override
	public boolean isFilterEnabled() {
		return true;
	}

	private static Log _log = LogFactoryUtil.getLog(SamlFilter.class);
	private SamlConsumerManager consumer;

	@Override
	protected void processFilter(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws Exception {
		HttpSession session;
		String requestURI;
		session = request.getSession(false);
		requestURI = GetterUtil.getString(request.getRequestURI());
		long companyId;
		boolean enabled;
		String SamlServiceProvierURL;
		companyId = PortalUtil.getCompanyId(request);
		String isenabled;
		isenabled = PrefsPropsUtil
				.getString(SamlPropsKeys.SAML_SSO_AUTH_ENABLED);
		enabled = PrefsPropsUtil
				.getBoolean(SamlPropsKeys.SAML_SSO_AUTH_ENABLED);
		SamlServiceProvierURL = PrefsPropsUtil
				.getString(SamlPropsKeys.SAML_SSO_SP_URL);
		// enabled = isenabled != null;
		if (!enabled || Validator.isNull(SamlServiceProvierURL)) {
			processFilter(SamlFilter.class, request, response, filterChain);
			return;
		}
		String portalRootURL;
		URL reconstructedURL = new URL(request.getScheme(),
				request.getServerName(), request.getServerPort(), "");
		portalRootURL = reconstructedURL.toString();
		if (requestURI.endsWith("/c/portal/login") && enabled) {
			String responseMessage = request.getParameter("SAMLResponse");
			if (responseMessage != null) {
				try {
					responseMessage = Util.decode(responseMessage);
					Map<String, String> result = consumer
							.processResponseMessage(responseMessage, request);
					if (result == null) {
						response.sendRedirect((new StringBuilder()).append(
								portalRootURL).toString());
					} else if (result.size() == 0) {
						response.sendRedirect((new StringBuilder()).append(
								portalRootURL).toString());
					} else if (result.size() > 0) {
						sessionIndex = result.get(Constants.IDP_SESSION);
						if (null != sessionIndex) {
							_log.error("Try to add session index is: "
									+ sessionIndex);
							SSOSessionManager.addAuthenticatedSession(
									sessionIndex, session);
						}
						Object[] keys = result.keySet().toArray();
						for (int i = 0; i < result.size(); i++) {
							String key = (String) keys[i];
							String value = (String) result.get(key);
							if (key.contains("Subject")) {
								screenName = value;
								break;
							}
						}
						processLogin(request, response, filterChain, session,
								companyId, true);
						response.sendRedirect((new StringBuilder()).append(
								portalRootURL).toString());

					}
				} catch (Exception e) {
					_log.error(e);
					e.printStackTrace();
				}
			} else {
				try {
					String requestMessage = consumer
							.buildRequestMessage(request);
					response.sendRedirect(requestMessage);

				} catch (Exception e) {
					_log.error(e);
				}
			}

		} else if (requestURI.endsWith("c/portal/saml-logout") && enabled) {
			_log.error("Retrieve Single Logout from IDP Server");
			String samlRequest = request
					.getParameter(Constants.HTTP_POST_PARAM_SAML2_AUTH_REQ);
			if (samlRequest != null) {
				XMLObject samlObject = Util
						.unmarshall(Util.decode(samlRequest));
				if (samlObject instanceof LogoutRequest) {
					_log.error("SamlLogoutRequest is :["
							+ Util.decode(samlRequest) + "]");
					LogoutRequest logoutRequest = (LogoutRequest) samlObject;
					String requestId = logoutRequest.getID();
					String statusCode = StatusCode.SUCCESS_URI;
					LogoutResponse logoutResponse = SamlTools
							.buildLogoutResponse(comsumerURL, statusCode,
									requestId);
					SoapManager soapManager = new SoapManager();
					Envelope envelope = soapManager
							.buildSOAPMessage(logoutResponse);
					String iDPSessionIndex = logoutRequest.getSessionIndexes()
							.get(0).getSessionIndex();
					SSOSessionManager
							.invalidateSessionByIdPSId(iDPSessionIndex);
					Element envelopeElem = SamlTools.marshallMessage(envelope);
					SamlTools.sendSOAPResponse(response,
							XMLHelper.nodeToString(envelopeElem));
					return;

				}
			} else {
				String homeURL = PortalUtil.getHomeURL(request);
				response.sendRedirect(homeURL);

			}

		} else if (requestURI.endsWith("/c/portal/logout") && enabled) {
			try {
				request.setAttribute("logout", "true");
				String requestMessage = consumer.buildRequestMessage(request);
				String sessionIndex = (String) request.getSession()
						.getAttribute(SamlPropsKeys.SAM_SSO_SESS_INDEX);
				_log.error("Logout request from user with IPD session index is:["
						+ sessionIndex + "]");
				SSOSessionManager.invalidateSessionByIdPSId(sessionIndex);
				response.sendRedirect(requestMessage);

			} catch (Exception e) {
				_log.error(e);
			}
		} else {
			String homeURL = PortalUtil.getHomeURL(request);
			response.sendRedirect(homeURL);

		}
	}

	@Override
	public void init(FilterConfig filterConfig) {
		try {
			comsumerURL = PrefsPropsUtil
					.getString(SamlPropsKeys.SAML_SSO_SP_URL);
			idpURL = PrefsPropsUtil.getString(SamlPropsKeys.SAML_SSO_IDP_URL);
			issueId = PrefsPropsUtil.getString(SamlPropsKeys.SAML_SSO_ISSUE_ID);
			attribIndex = PrefsPropsUtil
					.getString(SamlPropsKeys.SAML_SSO_ATTR_INDEX);
			consumer = new SamlConsumerManager(comsumerURL, issueId, idpURL,
					attribIndex);

		} catch (ConfigurationException e) {
			e.printStackTrace();
		} catch (SystemException e) {
			e.printStackTrace();
		}
		super.init(filterConfig);
	}

	private void processLogin(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain,
			HttpSession session, long companyId, boolean authenticated)
			throws Exception {
		request.getSession().setAttribute(SamlPropsKeys.SAML_SSO_USER_NAME,
				screenName);

	}

	@Override
	protected Log getLog() {
		return _log;
	}

}

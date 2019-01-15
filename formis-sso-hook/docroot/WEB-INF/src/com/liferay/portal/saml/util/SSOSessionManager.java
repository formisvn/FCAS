package com.liferay.portal.saml.util;

import java.util.Hashtable;
import java.util.Map;

import javax.servlet.http.HttpSession;

import com.liferay.portal.util.PortalUtil;

public class SSOSessionManager {
	private static Map<String, HttpSession> ssoSessions = new Hashtable<String, HttpSession>();

	public static void invalidateSessionByIdPSId(String idPSessionId) {
		try {
			HttpSession session = ssoSessions.get(idPSessionId);
			if (session != null) {
				session.invalidate();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public static void addAuthenticatedSession(String idPSessionId,
			HttpSession session) {
		ssoSessions.put(idPSessionId, session);
		session.setAttribute(Constants.AUTHENTICATED, Boolean.TRUE);
		session.setAttribute(SamlPropsKeys.SAM_SSO_SESS_INDEX, idPSessionId);
	}
}

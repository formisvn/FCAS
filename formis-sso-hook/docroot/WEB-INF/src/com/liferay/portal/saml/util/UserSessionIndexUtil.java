package com.liferay.portal.saml.util;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Thao Nguyen
 *
 */
public class UserSessionIndexUtil {
	private Map<String, String> userSessionIndex = null;
	private static UserSessionIndexUtil instance = null;

	private UserSessionIndexUtil() {
		userSessionIndex = new HashMap<String, String>();
	}

	public static void putEntry(String userName, String sessionIndex) {
		if (instance == null) {
			instance = new UserSessionIndexUtil();
		}
		instance.userSessionIndex.put(userName, sessionIndex);
	}

	public static void removeEntry(String userName) {
		if (instance == null) {
			instance = new UserSessionIndexUtil();
		}
		if (instance.userSessionIndex != null
				&& instance.userSessionIndex.containsKey(userName)) {
			instance.userSessionIndex.remove(userName);
		}
	}

	public static String getUserSessionIndex(String userName) {
		if (instance == null) {
			return new String("");
		} else {
			if (instance.userSessionIndex.containsKey(userName)) {
				return instance.userSessionIndex.get(userName);

			} else {
				return new String("");
			}
		}
	}

}

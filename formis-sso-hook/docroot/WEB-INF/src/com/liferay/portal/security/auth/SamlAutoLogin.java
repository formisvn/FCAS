package com.liferay.portal.security.auth;

import java.util.Calendar;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.liferay.portal.NoSuchUserException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.LocaleUtil;
import com.liferay.portal.kernel.util.StringPool;
import com.liferay.portal.kernel.util.WebKeys;
import com.liferay.portal.model.User;
import com.liferay.portal.saml.util.SamlPropsKeys;
import com.liferay.portal.service.ServiceContext;
import com.liferay.portal.service.UserLocalServiceUtil;
import com.liferay.portal.theme.ThemeDisplay;
import com.liferay.portal.util.PortalUtil;
import com.liferay.util.PwdGenerator;

public class SamlAutoLogin implements AutoLogin {
	private static Log _log = LogFactoryUtil.getLog(SamlAutoLogin.class);

	@Override
	public String[] login(HttpServletRequest request,
			HttpServletResponse response) throws AutoLoginException {
		String credentials[] = null;
		HttpSession session = request.getSession();
		String userName = (String) session
				.getAttribute(SamlPropsKeys.SAML_SSO_USER_NAME);
		try {
			if (userName == null) {
				return null;
			} else {
				long companyId = PortalUtil.getCompany(request).getCompanyId();
				User user = null;
				try {
					user = UserLocalServiceUtil.getUserByScreenName(companyId,
							userName);
				} catch (Exception e) {
					_log.error(e);
				}

				if (user != null) {
					long userId = user.getUserId();
					String password = user.getPassword();
					credentials = new String[3];
					credentials[0] = Long.toString(userId);
					credentials[1] = password;
					credentials[2] = Boolean.TRUE.toString();

				} else {
					ThemeDisplay themeDisplay = (ThemeDisplay) request
							.getAttribute(WebKeys.THEME_DISPLAY);
					Locale locale = LocaleUtil.getDefault();

					if (themeDisplay != null) {
						locale = themeDisplay.getLocale();
					}
					if (_log.isDebugEnabled()) {
						_log.debug("Adding user " + userName);
					}
					String email = userName + "@formis.vn";
					user = addUser(companyId, userName, userName, email,
							userName, locale);
				}
				long userId = user.getUserId();
				String password = user.getPassword();
				credentials = new String[3];
				credentials[0] = Long.toString(userId);
				credentials[1] = password;
				credentials[2] = Boolean.TRUE.toString();
			}

		} catch (NoSuchUserException nuse) {
			_log.error(nuse);
		} catch (Exception e) {
			_log.error(e);

		}

		return credentials;
	}

	protected User addUser(long companyId, String firstName, String lastName,
			String emailAddress, String screenName, Locale locale)
			throws Exception {

		long creatorUserId = 0;
		boolean autoPassword = false;
		String password1 = PwdGenerator.getPassword();
		String password2 = password1;
		boolean autoScreenName = false;
		long facebookId = 0;
		String openId = StringPool.BLANK;
		String middleName = StringPool.BLANK;
		int prefixId = 0;
		int suffixId = 0;
		boolean male = true;
		int birthdayMonth = Calendar.JANUARY;
		int birthdayDay = 1;
		int birthdayYear = 1970;
		String jobTitle = StringPool.BLANK;
		long[] groupIds = null;
		long[] organizationIds = null;
		long[] roleIds = null;
		long[] userGroupIds = null;
		boolean sendEmail = false;
		ServiceContext serviceContext = new ServiceContext();

		return UserLocalServiceUtil.addUser(creatorUserId, companyId,
				autoPassword, password1, password2, autoScreenName, screenName,
				emailAddress, facebookId, openId, locale, firstName,
				middleName, lastName, prefixId, suffixId, male, birthdayMonth,
				birthdayDay, birthdayYear, jobTitle, groupIds, organizationIds,
				roleIds, userGroupIds, sendEmail, serviceContext);
	}

	@Override
	public String[] handleException(HttpServletRequest arg0,
			HttpServletResponse arg1, Exception arg2) throws AutoLoginException {
		return null;
	}

}

package com.wixpress.mitre;

import com.google.common.base.Strings;
import org.mitre.openid.connect.client.UserInfoFetcher;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.mitre.openid.connect.model.UserInfo;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Created by Jefim_Matzkin on 2/10/15.
 */
public abstract class OIDCAuthenticationProviderBase implements AuthenticationProvider {
    protected UserInfoFetcher userInfoFetcher = new UserInfoFetcher();

    @Override
    public Authentication authenticate(final Authentication authentication)
            throws AuthenticationException {

        if (!supports(authentication.getClass())) {
            return null;
        }

        if (authentication instanceof OIDCAuthenticationToken) {
            return getAuthentication((OIDCAuthenticationToken) authentication);
        }

        return null;
    }

    protected Authentication getAuthentication(OIDCAuthenticationToken token) {
        UserInfo userInfo = userInfoFetcher.loadUserInfo(token);

        if (userInfo == null) {
            throw new UsernameNotFoundException("failed to fetch user details");
        } else {
            if (!Strings.isNullOrEmpty(userInfo.getSub()) && !userInfo.getSub().equals(token.getSub())) {
                // the userinfo came back and the user_id fields don't match what was in the id_token
                throw new UsernameNotFoundException("user_id mismatch between id_token and user_info call: " + token.getSub() + " / " + userInfo.getSub());
            }
        }

        return handleUserInfo(userInfo, token);
    }

    protected abstract Authentication handleUserInfo(UserInfo userInfo, OIDCAuthenticationToken token);

    /*
 * (non-Javadoc)
 *
 * @see
 * org.springframework.security.authentication.AuthenticationProvider#supports
 * (java.lang.Class)
 */
    @Override
    public boolean supports(Class<?> authentication) {
        return OIDCAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

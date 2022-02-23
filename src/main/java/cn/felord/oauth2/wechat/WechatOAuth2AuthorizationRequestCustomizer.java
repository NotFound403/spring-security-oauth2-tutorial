package cn.felord.oauth2.wechat;

import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.web.util.UriBuilder;

import java.net.URI;
import java.util.Map;
import java.util.function.Consumer;

/**
 * customizer {@link OAuth2AuthorizationRequest}
 * <p>
 * client_id 变成 appid ，并追加锚点#wechat_redirect
 *
 * @author felord.cn
 * @see DefaultOAuth2AuthorizationRequestResolver#setAuthorizationRequestCustomizer(Consumer)
 */
public class WechatOAuth2AuthorizationRequestCustomizer {
    private static final String WECHAT_APP_ID = "appid";
    private static final String WECHAT_FRAGMENT = "wechat_redirect";
    private final String wechatRegistrationId;

    public WechatOAuth2AuthorizationRequestCustomizer(String wechatRegistrationId) {
        Assert.notNull(wechatRegistrationId, "wechat registrationId flag must not be null");
        this.wechatRegistrationId = wechatRegistrationId;
    }


    public void customize(OAuth2AuthorizationRequest.Builder builder) {
        String registrationId = (String) builder.build()
                .getAttributes()
                .get(OAuth2ParameterNames.REGISTRATION_ID);
        if (wechatRegistrationId.equals(registrationId)) {
            builder.parameters(this::wechatParametersConsumer);
            builder.authorizationRequestUri(this::authorizationRequestUriFunction);
        }
    }


    private void wechatParametersConsumer(Map<String, Object> parameters) {
        //   client_id replace into appid here
        parameters.put(WECHAT_APP_ID, parameters.remove(OAuth2ParameterNames.CLIENT_ID));
    }

    private URI authorizationRequestUriFunction(UriBuilder builder) {
        //  add  wechat fragment here
        return builder.fragment(WECHAT_FRAGMENT).build();
    }
}

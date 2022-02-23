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
 * @see   DefaultOAuth2AuthorizationRequestResolver#setAuthorizationRequestCustomizer(Consumer)
 * @author felord.cn
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
           //todo  i  need  a  method  to  get registrationId   here      So that the following code logic can be executed
            builder.parameters(WechatOAuth2AuthorizationRequestCustomizer::wechatParametersConsumer);
            builder.authorizationRequestUri(WechatOAuth2AuthorizationRequestCustomizer::authorizationRequestUriFunction);

    }


    private static void matchProvider(Map<String, Object>attributes){
        String registrationId = (String) attributes.get(OAuth2ParameterNames.REGISTRATION_ID);

    }

    private static void wechatParametersConsumer(Map<String, Object> parameters) {
        //   client_id replace into appid here
        parameters.put(WECHAT_APP_ID, parameters.remove(OAuth2ParameterNames.CLIENT_ID));
    }

    private static URI authorizationRequestUriFunction(UriBuilder builder) {
        //  add  wechat fragment here
        return builder.fragment(WECHAT_FRAGMENT).build();
    }
}

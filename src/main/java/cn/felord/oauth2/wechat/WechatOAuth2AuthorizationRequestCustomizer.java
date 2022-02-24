package cn.felord.oauth2.wechat;

import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.web.util.UriBuilder;

import java.net.URI;
import java.util.LinkedHashMap;
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

    /**
     * 默认情况下Spring Security会生成授权链接：
     * {@code https://open.weixin.qq.com/connect/oauth2/authorize?response_type=code
     * &client_id=wxdf9033184b238e7f
     * &scope=snsapi_userinfo
     * &state=5NDiQTMa9ykk7SNQ5-OIJDbIy9RLaEVzv3mdlj8TjuE%3D
     * &redirect_uri=https%3A%2F%2Fmov-h5-test.felord.cn}
     * 缺少了微信协议要求的{@code #wechat_redirect}，同时 {@code client_id}应该替换为{@code app_id}
     *
     * @param builder the builder
     */
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
        LinkedHashMap<String, Object> linkedParameters =  new LinkedHashMap<>();
        //  k v 有固定顺序
        parameters.forEach((k,v)->{
          if (OAuth2ParameterNames.CLIENT_ID.equals(k)){
              linkedParameters.put(WECHAT_APP_ID,v);
          }else {
              linkedParameters.put(k,v);
          }
        });

        parameters.clear();
        parameters.putAll(linkedParameters);
    }

    private URI authorizationRequestUriFunction(UriBuilder builder) {
        //  add  wechat fragment here
        return builder.fragment(WECHAT_FRAGMENT).build();
    }
}

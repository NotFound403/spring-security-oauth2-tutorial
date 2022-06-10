package cn.felord.oauth2.wechat;

import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.util.Arrays;
import java.util.Objects;
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
    public static void customize(OAuth2AuthorizationRequest.Builder builder) {
        builder.attributes(attributes ->
                Arrays.stream(ClientProviders.values())
                        .filter(clientProvider ->
                                Objects.equals(clientProvider.registrationId(),
                                        attributes.get(OAuth2ParameterNames.REGISTRATION_ID)))
                        .findAny()
                        .map(ClientProviders::requestConsumer)
                        .ifPresent(requestConsumer ->
                                requestConsumer.accept(builder)));
    }

}

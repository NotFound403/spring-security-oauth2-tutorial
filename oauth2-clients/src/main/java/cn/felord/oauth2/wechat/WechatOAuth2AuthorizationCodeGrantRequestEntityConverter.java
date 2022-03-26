/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cn.felord.oauth2.wechat;

import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

/**
 * 兼容微信请求参数的请求参数封装工具类,扩展了{@link OAuth2AuthorizationCodeGrantRequestEntityConverter}
 *
 * @author  felord.cn
 * @see OAuth2AuthorizationCodeGrantRequestEntityConverter
 * @see Converter
 * @see OAuth2AuthorizationCodeGrantRequest
 * @see RequestEntity
 * @since 5.1
 */
public class WechatOAuth2AuthorizationCodeGrantRequestEntityConverter
        implements Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>> {
    private static final String WECHAT_ID = "wechat";
    private final OAuth2AuthorizationCodeGrantRequestEntityConverter defaultConverter = new  OAuth2AuthorizationCodeGrantRequestEntityConverter();
    /**
     * Returns the {@link RequestEntity} used for the Access Token Request.
     *
     * @param authorizationCodeGrantRequest the authorization code grant request
     * @return the {@link RequestEntity} used for the Access Token Request
     */
    @Override
    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {
        ClientRegistration clientRegistration = authorizationCodeGrantRequest.getClientRegistration();

        String tokenUri = clientRegistration.getProviderDetails().getTokenUri();
        // 针对微信的定制  WECHAT_ID表示为微信公众号专用的registrationId
        if (WECHAT_ID.equals(clientRegistration.getRegistrationId())) {
            MultiValueMap<String, String> queryParameters = this.buildWechatQueryParameters(authorizationCodeGrantRequest);
            URI uri = UriComponentsBuilder.fromUriString(tokenUri).queryParams(queryParameters).build().toUri();
            return RequestEntity.get(uri).build();
        }else {
            defaultConverter.addParametersConverter(new NimbusJwtClientAuthenticationParametersConverter<>(registration ->{
                Assert.isTrue(ClientAuthenticationMethod.CLIENT_SECRET_JWT.equals(registration.getClientAuthenticationMethod()),"CLIENT_SECRET_JWT Only");
                byte[] pin = registration.getClientSecret().getBytes(StandardCharsets.UTF_8);
                SecretKeySpec  secretKey = new SecretKeySpec(pin,"HmacSHA256");
                return new  OctetSequenceKey.Builder(secretKey).build();
            } ));
            return defaultConverter.convert(authorizationCodeGrantRequest);
        }
    }


    private MultiValueMap<String, String> buildWechatQueryParameters(OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {
        // 获取微信的客户端配置
        ClientRegistration clientRegistration = authorizationCodeGrantRequest.getClientRegistration();
        OAuth2AuthorizationExchange authorizationExchange = authorizationCodeGrantRequest.getAuthorizationExchange();
        MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
        // grant_type
        formParameters.add(OAuth2ParameterNames.GRANT_TYPE, authorizationCodeGrantRequest.getGrantType().getValue());
        // code
        formParameters.add(OAuth2ParameterNames.CODE, authorizationExchange.getAuthorizationResponse().getCode());
        // 如果有redirect-uri
        String redirectUri = authorizationExchange.getAuthorizationRequest().getRedirectUri();
        if (redirectUri != null) {
            formParameters.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
        }
        //appid
        formParameters.add("appid", clientRegistration.getClientId());
        //secret
        formParameters.add("secret", clientRegistration.getClientSecret());
        return formParameters;
    }

    private static HttpHeaders getDefaultTokenRequestHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));
        final MediaType contentType = MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
        headers.setContentType(contentType);
        return headers;
    }
}

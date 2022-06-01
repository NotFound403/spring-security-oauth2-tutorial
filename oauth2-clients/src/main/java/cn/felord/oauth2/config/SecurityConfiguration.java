package cn.felord.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.web.SecurityFilterChain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * @author felord.cn
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {
    private final StringKeyGenerator secureKeyGenerator = new Base64StringKeyGenerator(
            Base64.getUrlEncoder().withoutPadding(), 96);

    /***
     * 自定义
     *
     * @param http http
     * @return SecurityFilterChain
     * @throws Exception exception
     */
    @Bean
    SecurityFilterChain customSecurityFilterChain(HttpSecurity http,  ClientRegistrationRepository clientRegistrationRepository) throws Exception {


        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient = accessTokenResponseClient();
        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);

        authorizationRequestResolver.setAuthorizationRequestCustomizer(builder -> builder.attributes(attributes -> {
            if (!attributes.containsKey(PkceParameterNames.CODE_VERIFIER)) {
                String codeVerifier = this.secureKeyGenerator.generateKey();
                attributes.put(PkceParameterNames.CODE_VERIFIER, codeVerifier);

                builder.additionalParameters(additionalParameters -> {
                    try {
                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
                        additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
                        additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
                    } catch (NoSuchAlgorithmException ex) {
                        //  plain  方式  这种方式几乎作废了
                        additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, codeVerifier);
                    }
                });

            }
        }));
        http.authorizeRequests((requests) -> requests
//                        .antMatchers("/foo/bar").anonymous()
                        .antMatchers("/foo/bar", "/oauth2/jwks")
                        .hasAnyAuthority("ROLE_ANONYMOUS", "SCOPE_userinfo")
                        .anyRequest().authenticated())
                .oauth2Login().authorizationEndpoint().authorizationRequestResolver(authorizationRequestResolver)
                .and()
                // 获取token端点配置  比如根据code 获取 token
                .tokenEndpoint().accessTokenResponseClient(accessTokenResponseClient);


        http.oauth2Client()
                .authorizationCodeGrant().authorizationRequestResolver(authorizationRequestResolver)
                .accessTokenResponseClient(accessTokenResponseClient);
        return http.build();
    }


    /**
     * 调用token-uri去请求授权服务器获取token的OAuth2 Http 客户端
     *
     * @return OAuth2AccessTokenResponseClient
     */
    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        OAuth2AuthorizationCodeGrantRequestEntityConverter grantRequestEntityConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
        JwkResolver jwkResolver = new JwkResolver();
        NimbusJwtClientAuthenticationParametersConverter<OAuth2AuthorizationCodeGrantRequest> converter = new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver::apply);
        grantRequestEntityConverter.addParametersConverter(converter);
        DefaultAuthorizationCodeTokenResponseClient tokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
        tokenResponseClient.setRequestEntityConverter(grantRequestEntityConverter);
        return tokenResponseClient;
    }

    @Bean
    WebSecurityCustomizer ignore() {
        return web -> web.ignoring().antMatchers("/favicon.ico");
    }
}



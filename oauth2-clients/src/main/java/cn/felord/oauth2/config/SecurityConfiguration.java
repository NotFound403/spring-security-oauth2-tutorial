package cn.felord.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author felord.cn
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {
    private static final String WECHAT_PROVIDER = "wechat";

    /***
     *
     * 默认配置，用来对比
     *
     * @param http http
     * @return SecurityFilterChain
     * @throws Exception exception
     */
//    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests((requests) -> requests.anyRequest().authenticated());
        http.oauth2Login(Customizer.withDefaults());
        http.oauth2Client();
        return http.build();
    }


    /***
     * 自定义
     *
     * @param http http
     * @return SecurityFilterChain
     * @throws Exception exception
     */
    @Bean
    SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient = accessTokenResponseClient();

        http.authorizeRequests((requests) -> requests
//                        .antMatchers("/foo/bar").anonymous()
                        .antMatchers("/foo/bar")
                        .hasAnyAuthority("ROLE_ANONYMOUS","SCOPE_userinfo")
                        .anyRequest().authenticated())
                .oauth2Login().authorizationEndpoint()

                .and()
                // 获取token端点配置  比如根据code 获取 token
                .tokenEndpoint().accessTokenResponseClient(accessTokenResponseClient);
        http.oauth2Client()
                .authorizationCodeGrant()
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



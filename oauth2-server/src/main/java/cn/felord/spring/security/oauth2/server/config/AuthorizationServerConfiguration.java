package cn.felord.spring.security.oauth2.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyStore;
import java.util.UUID;

/**
 * The type Authorization server configuration.
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

    /**
     * Authorization server 集成
     *
     * @param http the http
     * @return the security filter chain
     * @throws Exception the exception
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Authorization Server 默认配置
        this.defaultOAuth2AuthorizationServerConfigurer(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    void defaultOAuth2AuthorizationServerConfigurer(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        // TODO 你可以根据需求对authorizationServerConfigurer进行一些个性化配置
        RequestMatcher authorizationServerEndpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        // 拦截 授权服务器相关的请求端点
        http.requestMatcher(authorizationServerEndpointsMatcher)
                .authorizeRequests().anyRequest().authenticated().and()
                // 忽略掉相关端点的csrf
                .csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerEndpointsMatcher))
                // 开启form登录
                .formLogin()
                .and()
                // 应用 授权服务器的配置
                .apply(authorizationServerConfigurer);
    }


    /**
     * 对jwt token 进行增强，如果有需要的话
     *
     * @return oauth 2 token customizer
     */
//    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return jwtEncodingContext -> {
            JwtClaimsSet.Builder claims = jwtEncodingContext.getClaims();
            claims.claim("xxxx", "xxxxx");
            JwtEncodingContext.with(jwtEncodingContext.getHeaders(), claims);
        };
    }


    /**
     * 注册一个客户端应用
     *
     * @param jdbcTemplate the jdbc template
     * @return the registered client repository
     */
    @SneakyThrows
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        // TODO 生产上 注册客户端需要使用接口 不应该采用下面的方式
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//               客户端ID和密码
                .clientId("felord-client")
                .clientSecret("secret")
//                名称 可不定义
                .clientName("felord")
//                授权方法
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                授权类型
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                回调地址名单，不在此列将被拒绝 而且只能使用IP或者域名  不能使用 localhost
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/felord-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .redirectUri("http://127.0.0.1:8080/foo/bar")
                .redirectUri("https://baidu.com")
//                OIDC支持
                .scope(OidcScopes.OPENID)
//                其它Scope
                .scope("message.read")
                .scope("message.write")
//                JWT的配置项 包括TTL  是否复用refreshToken等等
                .tokenSettings(TokenSettings.builder().build())
//                配置客户端相关的配置项，包括验证密钥或者 是否需要授权页面
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

//         每次都会初始化  生产的话 只初始化JdbcRegisteredClientRepository
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
//TODO        return registeredClientRepository;
        registeredClientRepository.save(registeredClient);
        return registeredClientRepository;
    }

    /**
     * 授权服务
     *
     * @param jdbcTemplate               the jdbc template
     * @param registeredClientRepository the registered client repository
     * @return the o auth 2 authorization service
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * Authorization consent service o auth 2 authorization consent service.
     *
     * @param jdbcTemplate               the jdbc template
     * @param registeredClientRepository the registered client repository
     * @return the o auth 2 authorization consent service
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 加载JWK资源
     *
     * @return the jwk source
     */
    @SneakyThrows
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        //TODO 这里优化到配置
        String path = "felordcn.jks";
        String alias = "felordcn";
        String pass = "123456";

        ClassPathResource resource = new ClassPathResource(path);
        KeyStore jks = KeyStore.getInstance("jks");
        char[] pin = pass.toCharArray();
        jks.load(resource.getInputStream(), pin);
        RSAKey rsaKey = RSAKey.load(jks, alias, pin);

        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    /**
     * 配置 OAuth2.0 provider元信息
     *
     * @return the provider settings
     */
    @Bean
    public ProviderSettings providerSettings(@Value("${server.port}") Integer port) {
        //TODO 生产应该使用域名
        return ProviderSettings.builder().issuer("http://localhost:" + port).build();
    }


    /**
     * OAuth2.0 客户端持久化数据库脚本初始化到内置数据库H2，生产不建议这么做
     *
     * @return the embedded database
     */
    @Bean
    public EmbeddedDatabase embeddedDatabase() {
        // @formatter:off
        return new EmbeddedDatabaseBuilder()
                .generateUniqueName(true)
                .setType(EmbeddedDatabaseType.H2)
                .setScriptEncoding("UTF-8")
                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
                .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
                .build();
        // @formatter:on
    }

}

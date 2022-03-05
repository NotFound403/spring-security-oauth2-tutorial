package cn.felord.oauth2.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.function.Predicate;

/**
 * OAuth2.0 资源服务器配置
 */
@ConditionalOnBean(JwtDecoder.class)
@Configuration(proxyBeanMethods = false)
public class OAuth2ResourceServerConfiguration {

    /**
     * Jwt security filter chain security filter chain.
     *
     * @param http the http
     * @return the security filter chain
     * @throws Exception the exception
     */
    @Bean
    SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeRequests(request -> request.anyRequest()
                        .access("@checker.check(authentication,request)"))
                .exceptionHandling()
                .accessDeniedHandler(new SimpleAccessDeniedHandler())
                .authenticationEntryPoint(new SimpleAuthenticationEntryPoint())
                .and()
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .build();
    }

    @Bean
    Checker checker() {
        return new Checker();
    }

    /**
     * 动态权限控制
     */
    public static class Checker {
        private Predicate<HttpServletRequest> whitePredicate = request -> false;
        public boolean check(Authentication authentication, HttpServletRequest request) {
            boolean test = whitePredicate.test(request);
            if (test){
                return true;
            }
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            System.out.println("authorities = " + authorities);
            String requestURI = request.getRequestURI();
            System.out.println("requestURI = " + requestURI);
            // ROLE_USER 角色才能访问 /foo/bar
            return authorities.contains(new SimpleGrantedAuthority("ROLE_USER"))
                    && requestURI.equals("/foo/bar");
        }

        /**
         * 方便实现白名单策略
         * @param whitePredicate
         */
        public void setWhitePredicate(Predicate<HttpServletRequest> whitePredicate) {
            this.whitePredicate = whitePredicate;
        }
    }


    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
//        如果不按照规范  解析权限集合Authorities 就需要自定义key
//        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("scopes");
//        OAuth2 默认前缀是 SCOPE_     Spring Security 是 ROLE_
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        // 用户名 可以放sub 中   自己以前理解错误了
        jwtAuthenticationConverter.setPrincipalClaimName(JwtClaimNames.SUB);
        return jwtAuthenticationConverter;
    }

}

package cn.felord.gateway.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
//@EnableWebFluxSecurity
public class ReactiveWebSecurityConfiguration {
    @Bean
    @ConditionalOnMissingBean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http.authorizeExchange().anyExchange().authenticated();
        http.oauth2Login();
        http.oauth2Client();
        return http.build();
    }
}

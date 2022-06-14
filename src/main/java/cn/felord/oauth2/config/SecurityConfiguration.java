package cn.felord.oauth2.config;

import cn.felord.configuers.authentication.oauth2.ClientProviders;
import cn.felord.configuers.authentication.oauth2.DelegateClientRegistrationRepository;
import cn.felord.configuers.authentication.oauth2.OAuth2ProviderConfigurer;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesRegistrationAdapter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author felord.cn
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {


    @Bean
    DelegateClientRegistrationRepository delegateClientRegistrationRepository(OAuth2ClientProperties properties) {
        DelegateClientRegistrationRepository clientRegistrationRepository = new DelegateClientRegistrationRepository();
        List<ClientRegistration> registrations = new ArrayList<>(
                OAuth2ClientPropertiesRegistrationAdapter.getClientRegistrations(properties).values());
        Set<String> set = Arrays.stream(ClientProviders.values())
                .map(ClientProviders::registrationId)
                .collect(Collectors.toSet());
        registrations.stream()
                .filter(clientRegistration -> !set.contains(clientRegistration.getRegistrationId()))
                .forEach(clientRegistrationRepository::addClientRegistration);
        return clientRegistrationRepository;
    }


    /***
     * 自定义
     *
     * @param http http
     * @return SecurityFilterChain
     * @throws Exception exception
     */
    @Bean
    SecurityFilterChain customSecurityFilterChain(HttpSecurity http,DelegateClientRegistrationRepository delegateClientRegistrationRepository) throws Exception {

        http.authorizeRequests((requests) ->
                        requests
                                .anyRequest().authenticated())
                .apply(new OAuth2ProviderConfigurer(delegateClientRegistrationRepository))
                .wechatWebclient("wxdf9033184b238e7f", "bf1306baaa0d874457db15eb02d68df5")
                .workWechatWebLoginclient("wwa70dc5b6e56936e1", "nvzGI4Alp3zS7rfOYAlFs-BZUc3TtPtKbnfTEets5W8", "1000005")
                .wechatWebLoginclient("xxxxxxxx","xxxxxxxx")
        ;
        return http.build();
    }


    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .antMatchers("/error")
                .antMatchers("/favicon.ico");
    }
}



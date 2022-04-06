package cn.felord.oauth2.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.SneakyThrows;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import java.security.KeyStore;

public class JwkResolver  {


    @SneakyThrows
    public JWK apply(ClientRegistration clientRegistration) {
        //todo clientRegistration的信息这里没有使用
        // 你可以考虑 多租户 持久化
        String path = "client.jks";
        String alias = "jose";
        String pass = "felord.cn";

        ClassPathResource resource = new ClassPathResource(path);
        KeyStore jks = KeyStore.getInstance("jks");
        char[] pin = pass.toCharArray();
        jks.load(resource.getInputStream(), pin);
        return RSAKey.load(jks, alias, pin);
    }
}

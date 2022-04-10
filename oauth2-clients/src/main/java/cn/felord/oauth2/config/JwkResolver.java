package cn.felord.oauth2.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import lombok.SneakyThrows;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class JwkResolver {

    @SneakyThrows
    public JWK apply(ClientRegistration clientRegistration) {
        ClientAuthenticationMethod method = clientRegistration.getClientAuthenticationMethod();
        Assert.isTrue(ClientAuthenticationMethod.CLIENT_SECRET_JWT.equals(method), "CLIENT_SECRET_JWT Only");
        byte[] pin = clientRegistration.getClientSecret().getBytes(StandardCharsets.UTF_8);
        String hmacAlg = "HmacSHA256";
        SecretKeySpec secretKey = new SecretKeySpec(pin, hmacAlg);
        return new OctetSequenceKey.Builder(secretKey).build();
    }
}

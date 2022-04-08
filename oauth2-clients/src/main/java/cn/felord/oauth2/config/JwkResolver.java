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
        Assert.isTrue(ClientAuthenticationMethod.CLIENT_SECRET_JWT.equals(clientRegistration.getClientAuthenticationMethod()), "CLIENT_SECRET_JWT Only");
        byte[] pin = clientRegistration.getClientSecret().getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKey = new SecretKeySpec(pin, "HmacSHA256");
        return new OctetSequenceKey.Builder(secretKey).build();
    }
}

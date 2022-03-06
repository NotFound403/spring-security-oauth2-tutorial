package cn.felord.oauth2;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyStore;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

@SpringBootTest
class SpringSecurityOauth2TutorialApplicationTests {

    /**
     * The Jwt decoder.
     */
    @Autowired
    JwtDecoder jwtDecoder;
    private final JWKSource<SecurityContext> jwkSource = jwkSource();

    /**
     * 资源服务器不应该生成JWT 但是为了测试 假设这是个认证服务器
     */
    @SneakyThrows
    @Test
    public void imitateAuthServer() {

        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
                .jwkSetUrl("https://felord.cn/oauth2/jwks")
                .type("JWT")
                .build();

        Instant issuedAt = Clock.system(ZoneId.of("Asia/Shanghai")).instant();

        long exp = 604800L;
        Instant expiresAt = issuedAt.plusSeconds(exp);
        Instant notBefore = issuedAt.minusSeconds(60);

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuer("https://felord.cn")
                .subject("felord")
                .audience(Collections.singletonList("https://resourceserver.felord.cn"))
                .expiresAt(expiresAt)
                .issuedAt(issuedAt)
                .notBefore(notBefore)
                .id(UUID.randomUUID().toString())
                .claim("scope", Arrays.asList("message.read", "message.write"))
                .build();

        JwtEncoderParameters parameters = JwtEncoderParameters
                .from(jwsHeader, jwtClaimsSet);
        Jwt jwt = jwtEncoder.encode(parameters);

        String token = jwt.getTokenValue();
        System.out.println("json web token —> "+token);
    }

    @SneakyThrows
    private JWKSource<SecurityContext> jwkSource() {
        ClassPathResource resource = new ClassPathResource("jose.jks");
        KeyStore jks = KeyStore.getInstance("jks");
        String pass = "felord.cn";
        char[] pem = pass.toCharArray();
        jks.load(resource.getInputStream(), pem);

        RSAKey rsaKey = RSAKey.load(jks, "jose", pem);
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

}

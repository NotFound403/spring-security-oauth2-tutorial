package cn.felord.spring.security.oauth2.server;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwsEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Instant;
import java.util.Arrays;

@SpringBootTest
public class JwtTests {
    @Autowired
    JWKSource<SecurityContext> jwkSource;
    @Autowired
    RegisteredClientRepository registeredClientRepository;



    @Test
    public void generate() {

        final String id = "10000";

        RegisteredClient registeredClient = registeredClientRepository.findById(id);

        JwtEncoder jwtEncoder = new NimbusJwsEncoder(jwkSource);
        JoseHeader.Builder headersBuilder =  JoseHeader.withAlgorithm(SignatureAlgorithm.RS256);

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());
        String clientId = registeredClient.getClientId();
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(Arrays.asList("http://localhost:9000/oauth2/token",
                        "http://localhost:9000/oauth2/revoke",
                        "http://localhost:9000/oauth2/introspect"))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(issuedAt)
                .claim(OAuth2ParameterNames.SCOPE, Arrays.asList("message.read", "message.write"));



        Jwt jwt = jwtEncoder.encode(headersBuilder.build(), claimsBuilder.build());
        System.out.println("jwt.getTokenValue() = " + jwt.getTokenValue());

    }

}

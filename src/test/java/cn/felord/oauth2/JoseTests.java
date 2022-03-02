package cn.felord.oauth2;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.util.Assert;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

/**
 * The type Jose tests.
 *
 * @author felord.cn
 */
@SpringBootTest
public class JoseTests {


    /**
     * 从jks文件中读取jwkSet
     * <p>
     * RSA算法
     */
    @SneakyThrows
    @Test
    public void readJwkSetFromJks() {
        KeyStore jks = KeyStore.getInstance("jks");
        // 对应keytool命令中的 alias
        String alias = "jose";
        // 对应keytool命令中的 storepass
        String storePass = "felord.cn";
        char[] pin = storePass.toCharArray();
        jks.load(new ClassPathResource("jose.jks").getInputStream(), pin);
        RSAKey rsaJwks = RSAKey.load(jks, alias, pin);
        RSAKey publicJWK = rsaJwks.toPublicJWK();
        // jwkSet
        JWKSet jwkSet = new JWKSet(Collections.singletonList(rsaJwks));

        Assertions.assertTrue(jwkSet.containsJWK(publicJWK));

    }

    /**
     * 从公钥文件中读取jwkSet
     * <p>
     * RSA算法
     */
    @SneakyThrows
    @Test
    public void readJwkSetFromPublicKey() {

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        ClassPathResource resource = new ClassPathResource("pub.cer");
        InputStream inputStream = resource.getInputStream();
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);

        RSAKey publicKey = RSAKey.parse(certificate);

        JWKSet jwkSet = new JWKSet(publicKey);

        System.out.println("jwkSet = " + jwkSet);
    }

    /**
     * 生成JWT
     */
    @SneakyThrows
    @Test
    public void jwtEncoder() {
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
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
                .audience(Arrays.asList("https://client1.felord.cn", "https://client2.felord.cn"))
                .expiresAt(expiresAt)
                .issuedAt(issuedAt)
                .notBefore(notBefore)
                .id(UUID.randomUUID().toString())
                .claim("scope", Arrays.asList("message.read", "message.write"))
                .build();

        JwtEncoderParameters parameters = JwtEncoderParameters.from(jwsHeader, jwtClaimsSet);
        Jwt jwt = jwtEncoder.encode(parameters);

        String token = jwt.getTokenValue();
        System.out.println("token = " + token);
    }

    /**
     * 解析JWT
     */
    @SneakyThrows
    @Test
    public void jwtDecode() {
       final String token = "eyJ4NXQjUzI1NiI6IlN4cXFkV1l4VDdCWnJkSC11VnBnQUhmWDJxMzRxUHl4eDRvblg2bXYtcUkiLCJqa3UiOiJodHRwczpcL1wvZmVsb3JkLmNuXC9vYXV0aDJcL2p3a3MiLCJraWQiOiJqb3NlIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ." +
                "eyJzdWIiOiJmZWxvcmQiLCJhdWQiOlsiaHR0cHM6XC9cL2NsaWVudDEuZmVsb3JkLmNuIiwiaHR0cHM6XC9cL2NsaWVudDIuZmVsb3JkLmNuIl0sIm5iZiI6MTY0NjIzNjY2Miwic2NvcGUiOlsibWVzc2FnZS5yZWFkIiwibWVzc2FnZS53cml0ZSJdLCJpc3MiOiJodHRwczpcL1wvZmVsb3JkLmNuIiwiZXhwIjoxNjQ2ODQxNTIyLCJpYXQiOjE2NDYyMzY3MjIsImp0aSI6IjQ3OGNmZmRmLTllNWYtNDlhNy1iNjlkLWI3YzFhNzY1YTNiOCJ9." +
                "BEcV65GcRqwaaaRI1TUI2s5b7K6ewyV5-7g_OTWCBuS-WzdJX4v5kS5YkK-4ABwaQWZJgNsV-zOxWvXBICSqHocs-oKd40Iiqz6DWFY8RrfqN-HwphELbPLyfrIWcJ7iVr3t-vF3NWcLZaPuv0PGEn4n4mkdQXpu59FDxUgX-XR_i-kSZwgiw_NgLd7z0UpLlD3Cm3kxnwAFAPf_V1eQWjKhZvXYto4ws-j0lZSf1LGDDRu8d5WS4hPRt6h4-x9-ZPZIoxHifhrPfVG3qQUZ0MlA1mKqfcrVUexgFqN8bcTP4krkwDbodsYVqQPHKFMWaIPHcLvHYp5_hkuzxCBT7A";
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        ClassPathResource resource = new ClassPathResource("pub.cer");
        Certificate certificate = certificateFactory.generateCertificate(resource.getInputStream());

        RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();

        // JwkController   需要远程端点支持。
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withJwkSetUri("http://localhost:8082/oauth2/jwks")
                .build();
        // 借助于公钥
        JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaPublicKey)
                .build();
        Jwt jwt = jwtDecoder.decode(token);
        Assertions.assertEquals("felord",jwt.getSubject());
        Assertions.assertEquals("https://felord.cn",jwt.getIssuer().toString());
    }


    @SneakyThrows
    private JWKSource<SecurityContext> jwkSource() {
        KeyStore jks = KeyStore.getInstance("jks");
        // 对应keytool命令中的 alias
        String alias = "jose";
        // 对应keytool命令中的 storepass
        String storePass = "felord.cn";
        char[] pin = storePass.toCharArray();
        jks.load(new ClassPathResource("jose.jks").getInputStream(), pin);

        RSAKey rsaKey = RSAKey.load(jks, alias, pin);

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }
}

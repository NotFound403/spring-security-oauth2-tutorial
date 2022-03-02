package cn.felord.oauth2;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

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
        System.out.println("privateJWK = " + rsaJwks.toJSONString());
        RSAKey publicJWK = rsaJwks.toPublicJWK();
        System.out.println("publicJWK = " + publicJWK.toJSONString());

        // jwkSet
        JWKSet jwkSet = new JWKSet(Collections.singletonList(rsaJwks));

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

}

package cn.felord.spring.security.oauth2.server;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.config.ConfigurationSettingNames;

import java.util.Collections;

@SpringBootTest
public class ProviderSettingsTests {

    @Test
    public void providerValidate() {
        // issuer is required
        Assertions.assertThrows(IllegalArgumentException.class,
                ()->ProviderSettings.builder().build());
        // issuer must be a valid URL
        Assertions.assertThrows(IllegalArgumentException.class,
                ()->ProviderSettings.builder().issuer("://localhost:9000").build());
        // issuer has no queryParams
        Assertions.assertThrows(IllegalArgumentException.class,
                ()->ProviderSettings.builder().issuer("https://localhost:9000?something=any").build());
        // issuer has no fragment
        Assertions.assertThrows(IllegalArgumentException.class,
                ()->ProviderSettings.builder().issuer("https://localhost:9000#fragment").build());
        // neither
        Assertions.assertThrows(IllegalArgumentException.class,
                ()->ProviderSettings.builder().issuer("https://localhost:9000?something=any#fragment").build());
        // authorizationEndpoint is required
        Assertions.assertThrows(IllegalArgumentException.class,
                ()->ProviderSettings.builder().issuer("https://localhost:9000").authorizationEndpoint("").build());
        // tokenEndpoint is required
        Assertions.assertThrows(IllegalArgumentException.class,
                ()->ProviderSettings.builder().issuer("https://localhost:9000").tokenEndpoint("").build());
        // test withSettings
        Assertions.assertThrows(IllegalArgumentException.class,
                ()->ProviderSettings.withSettings(Collections.singletonMap(ConfigurationSettingNames.Provider.ISSUER,
                        "https://localhost:9000?something=any#fragment")).build());

    }


    public static void main(String[] args) {

           ProviderSettings.withSettings(Collections.singletonMap(ConfigurationSettingNames.Provider.ISSUER,
                   "https://localhost:9000?something=any#fragment")).build();
    }
}

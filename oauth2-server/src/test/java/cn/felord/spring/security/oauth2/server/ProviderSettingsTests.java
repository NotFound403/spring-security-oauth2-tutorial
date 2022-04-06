package cn.felord.spring.security.oauth2.server;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.config.ConfigurationSettingNames;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;

import java.net.URI;
import java.util.Collections;

@SpringBootTest
public class ProviderSettingsTests {

    @Test
    public void providerValidate() {
        // issuer must be a valid URL
        Assertions.assertThrows(IllegalArgumentException.class,
                ()->validateProviderSettings(ProviderSettings.builder().issuer("://localhost:9000").build()));
        // issuer has no queryParams
        Assertions.assertThrows(IllegalArgumentException.class,
                ()->validateProviderSettings(ProviderSettings.builder().issuer("https://localhost:9000?").build()));
        // issuer has no fragment
        Assertions.assertThrows(IllegalArgumentException.class,
                ()->validateProviderSettings(ProviderSettings.builder().issuer("https://localhost:9000#").build()));
        // neither
        Assertions.assertThrows(IllegalArgumentException.class,
                ()->validateProviderSettings(ProviderSettings.builder().issuer("https://localhost:9000?something=any#fragment").build()));
    }

    private static void validateProviderSettings(ProviderSettings providerSettings) {
        if (providerSettings.getIssuer() != null) {
            try {
                URI issuerUri = new URI(providerSettings.getIssuer());
                issuerUri.toURL();
                String query = issuerUri.getQuery();
                String fragment = issuerUri.getFragment();
                // rfc8414 https://datatracker.ietf.org/doc/html/rfc8414#section-2
                if (query != null || fragment != null) {
                    throw new IllegalArgumentException("issuer has no query and fragment components");
                }
            } catch (Exception ex) {
                throw new IllegalArgumentException("issuer must be a valid URL", ex);
            }
        }
    }

    @SneakyThrows
    public static void main(String[] args) {

           ProviderSettings.withSettings(Collections.singletonMap(ConfigurationSettingNames.Provider.ISSUER,
                   "https://localhost:9000?something=any#fragment")).build();
    }
}

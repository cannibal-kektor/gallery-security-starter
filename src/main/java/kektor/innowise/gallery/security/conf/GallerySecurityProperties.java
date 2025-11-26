package kektor.innowise.gallery.security.conf;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.List;

@Getter
@Setter
@ConfigurationProperties("gallery.security")
public class GallerySecurityProperties {

    List<String> openEndpoints = Collections.emptyList();
    ProtectedServices protectedServices;

    public record ProtectedServices(
            String userServiceUrl,
            String authenticationServiceUrl,
            String imageServiceUrl,
            String commentServiceUrl
    ) {
    }
}

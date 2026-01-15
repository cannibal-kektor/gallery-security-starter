package kektor.innowise.gallery.security.conf;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpMethod;

import java.util.Collections;
import java.util.List;

@Getter
@Setter
@ConfigurationProperties("gallery.security")
public class GallerySecurityProperties {

    ProtectedServices protectedServices;
    List<Endpoint> openEndpoints = Collections.emptyList();
    List<Endpoint> internalEndpoints = Collections.emptyList();

    public record Endpoint(
            HttpMethod method,
            String path
    ){
    }

    public record ProtectedServices(
            String userServiceUrl,
            String authenticationServiceUrl,
            String imageServiceUrl,
            String commentServiceUrl
    ) {
    }
}

package kektor.innowise.gallery.security.conf.client;

import kektor.innowise.gallery.security.UserPrincipal;
import kektor.innowise.gallery.security.conf.GallerySecurityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.RestClient;

import static kektor.innowise.gallery.security.HeadersAuthenticationFilter.EMAIL_HEADER;
import static kektor.innowise.gallery.security.HeadersAuthenticationFilter.USERNAME_HEADER;
import static kektor.innowise.gallery.security.HeadersAuthenticationFilter.USER_ID_HEADER;

@Configuration
public class ProtectedRestClientConfig {

    private final GallerySecurityProperties.ProtectedServices protectedServices;

    @Autowired
    public ProtectedRestClientConfig(GallerySecurityProperties gallerySecurityProperties) {
        this.protectedServices = gallerySecurityProperties.getProtectedServices();
    }

    @Bean
    @ProtectedUserServiceClient
    @ConditionalOnProperty("gallery.security.protected-services.user-service-url")
    public RestClient userRestClient() {
        return RestClient.builder()
                .baseUrl(protectedServices.userServiceUrl())
                .requestInitializer(this::addAuthHeaders)
                .build();
    }

    @Bean
    @ProtectedAuthenticationServiceClient
    @ConditionalOnProperty("gallery.security.protected-services.authentication-service-url")
    public RestClient authenticationRestClient() {
        return RestClient.builder()
                .baseUrl(protectedServices.authenticationServiceUrl())
                .requestInitializer(this::addAuthHeaders)
                .build();
    }

    @Bean
    @ProtectedImageServiceClient
    @ConditionalOnProperty("gallery.security.protected-services.image-service-url")
    public RestClient imageRestClient() {
        return RestClient.builder()
                .baseUrl(protectedServices.imageServiceUrl())
                .requestInitializer(this::addAuthHeaders)
                .build();
    }

    @Bean
    @ProtectedCommentServiceClient
    @ConditionalOnProperty("gallery.security.protected-services.comment-service-url")
    public RestClient commentRestClient() {
        return RestClient.builder()
                .baseUrl(protectedServices.commentServiceUrl())
                .requestInitializer(this::addAuthHeaders)
                .build();
    }

    private void addAuthHeaders(ClientHttpRequest request) {
        HttpHeaders headers = request.getHeaders();
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() &&
                authentication.getPrincipal() instanceof UserPrincipal(Long id, String username, String email)) {
            headers.add(USER_ID_HEADER, id.toString());
            headers.add(USERNAME_HEADER, username);
            headers.add(EMAIL_HEADER, email);
        }
    }


}

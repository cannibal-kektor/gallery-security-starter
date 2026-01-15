package kektor.innowise.gallery.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Slf4j
public class HeadersAuthenticationFilter extends OncePerRequestFilter {

    public static final String SYSTEM_INTERNAL_HEADER = "X-System-Internal-Call";
    public static final String USER_ID_HEADER = "X-User-Id";
    public static final String USERNAME_HEADER = "X-User-Username";
    public static final String EMAIL_HEADER = "X-User-Email";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        createSystemToken(request)
                .or(() -> createUserToken(request))
                .ifPresent(token -> SecurityContextHolder.getContext().setAuthentication(token));

        filterChain.doFilter(request, response);
    }

    private Optional<HeaderAuthenticationToken> createUserToken(HttpServletRequest request) {

        String userIdStr = request.getHeader(USER_ID_HEADER);
        String username = request.getHeader(USERNAME_HEADER);
        String email = request.getHeader(EMAIL_HEADER);

        if (isValidHeaders(userIdStr, username, email)) {
            try {
                Long userId = Long.parseLong(userIdStr);
                UserPrincipal principal = new UserPrincipal(userId, username, email);
                return Optional.of(new HeaderAuthenticationToken(principal));
            } catch (NumberFormatException e) {
                log.warn("Invalid user id format: {}", userIdStr);
            }
        }
        return Optional.empty();
    }

    private Optional<HeaderAuthenticationToken> createSystemToken(HttpServletRequest request) {
        String systemOrigin = request.getHeader(SYSTEM_INTERNAL_HEADER);
        if (systemOrigin == null || systemOrigin.isBlank()) {
            return Optional.empty();
        }
        SystemPrincipal principal = new SystemPrincipal(systemOrigin);
        return Optional.of(new HeaderAuthenticationToken(principal));
    }


    private boolean isValidHeaders(String userId, String username, String email) {
        return userId != null && username != null && email != null &&
                !userId.isBlank() && !username.isBlank() && !email.isBlank();
    }

}

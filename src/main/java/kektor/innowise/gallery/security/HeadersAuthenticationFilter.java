package kektor.innowise.gallery.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class HeadersAuthenticationFilter extends OncePerRequestFilter {

    public static final String USER_ID_HEADER = "X-User-Id";
    public static final String USERNAME_HEADER = "X-User-Username";
    public static final String EMAIL_HEADER = "X-User-Email";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String userIdStr = getHeader(request, USER_ID_HEADER);
        String username = getHeader(request, USERNAME_HEADER);
        String email = getHeader(request, EMAIL_HEADER);

        if (isValidHeaders(userIdStr, username, email)) {
            try {
                Long userId = Long.parseLong(userIdStr);
                UserPrincipal principal = new UserPrincipal(userId, username, email);
                HeaderAuthenticationToken auth = new HeaderAuthenticationToken(principal);
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (NumberFormatException e) {
                log.warn("Invalid user id format: {}", userIdStr);
            }
        }
        filterChain.doFilter(request, response);
    }

    private String getHeader(HttpServletRequest request, String header) {
        String value = request.getHeader(header);
        return value != null && !value.isBlank() ? value : null;
    }

    private boolean isValidHeaders(String userId, String username, String email) {
        return userId != null && username != null && email != null &&
                !userId.isBlank() && !username.isBlank() && !email.isBlank();
    }

}

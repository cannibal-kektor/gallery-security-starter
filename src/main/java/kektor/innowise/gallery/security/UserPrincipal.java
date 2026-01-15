package kektor.innowise.gallery.security;

public record UserPrincipal(
        Long id,
        String username,
        String email
) {
}

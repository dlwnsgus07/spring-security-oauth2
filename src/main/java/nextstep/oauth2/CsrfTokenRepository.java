package nextstep.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.UUID;

public class CsrfTokenRepository {

    public static final String sessionAttributeName = CsrfTokenRepository.class.getName().concat(".CSRF_TOKEN");

    void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        if (token == null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(sessionAttributeName);
            }
        } else {
            HttpSession session = request.getSession();
            session.setAttribute(sessionAttributeName, token);
        }
    }

    CsrfToken loadToken(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }

         return (CsrfToken)session.getAttribute(sessionAttributeName);
    }

    CsrfToken generateToken(HttpServletRequest request) {
        return new CsrfToken("X-CSRF-TOKEN", "_csrf", UUID.randomUUID().toString());
    }
}

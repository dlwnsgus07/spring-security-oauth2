package nextstep.oauth2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpStatus;

public class AccessDeniedHandler {

    public void handle(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (response.isCommitted()) {
            return;
        }

        response.setStatus(HttpStatus.FORBIDDEN.value());
    }

}

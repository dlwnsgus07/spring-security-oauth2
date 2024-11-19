package nextstep.security.config.annotation.configurers;

import java.util.ArrayList;
import java.util.List;
import nextstep.oauth2.CsrfFilter;
import nextstep.security.access.AndRequestMatcher;
import nextstep.security.access.MvcRequestMatcher;
import nextstep.security.access.NegateRequestMatcher;
import nextstep.security.access.OrRequestMatcher;
import nextstep.security.access.RequestMatcher;
import nextstep.security.config.annotation.HttpSecurity;
import nextstep.security.config.annotation.SecurityConfigurer;

public class CsrfConfigurer implements SecurityConfigurer {
    private RequestMatcher requireCsrfProtectionMatcher = CsrfFilter.requireCsrfProtectionMatcher;

    private List<RequestMatcher> ignoredCsrfProtectionMatchers = new ArrayList<>();
    @Override
    public void init(HttpSecurity http) {

    }

    @Override
    public void configure(HttpSecurity http) {
        CsrfFilter filter = new CsrfFilter();
        RequestMatcher requireCsrfProtectionMatcher = getRequireCsrfProtectionMatcher();
        if (requireCsrfProtectionMatcher != null) {
            filter.setRequireCsrfProtectionMatcher(requireCsrfProtectionMatcher);
        }
        http.addFilter(filter);
    }

    private RequestMatcher getRequireCsrfProtectionMatcher() {
        if (this.ignoredCsrfProtectionMatchers.isEmpty()) {
            return this.requireCsrfProtectionMatcher;
        }
        return new AndRequestMatcher(this.requireCsrfProtectionMatcher, new NegateRequestMatcher(new OrRequestMatcher(this.ignoredCsrfProtectionMatchers)));
    }

    public CsrfConfigurer ignoredCsrfProtectionMatchers(String... patterns) {
        for (String pattern : patterns) {
            MvcRequestMatcher mvc = new MvcRequestMatcher(null, pattern);
            ignoredCsrfProtectionMatchers.add(mvc);
        }
        return this;
    }

}

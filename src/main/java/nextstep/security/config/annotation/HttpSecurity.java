package nextstep.security.config.annotation;

import jakarta.servlet.Filter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.config.Customizer;
import nextstep.security.config.DefaultSecurityFilterChain;
import nextstep.security.config.SecurityFilterChain;
import nextstep.security.config.annotation.configurers.CsrfConfigurer;
import nextstep.security.config.annotation.configurers.HttpBasicConfigurer;
import nextstep.security.config.annotation.configurers.SecurityContextConfigurer;

public class HttpSecurity {

    private final LinkedHashMap<Class<? extends SecurityConfigurer>, SecurityConfigurer> configurers = new LinkedHashMap<>();
    private List<Filter> filters = new ArrayList<>();
    private final Map<Class<?>, Object> sharedObjects = new HashMap<>();

    public HttpSecurity(AuthenticationManager authenticationManager, Map<Class<?>, Object> sharedObjects){
        setSharedObject(AuthenticationManager.class, authenticationManager);
        for (Map.Entry<Class<?>, Object> entry : sharedObjects.entrySet()) {
            setSharedObject((Class<Object>) entry.getKey(), entry.getValue());
        }
    }

    private <C> void setSharedObject(Class<C> sharedType, C object) {
        this.sharedObjects.put(sharedType, object);
    }

    public <C> C getSharedObject(Class<C> sharedType) {
        return (C) this.sharedObjects.get(sharedType);
    }

    public SecurityFilterChain build() {
        init();
        configurer();
        return new DefaultSecurityFilterChain(filters);
    }

    private void configurer() {
        for (SecurityConfigurer configurer : configurers.values()) {
            configurer.configure(this);
        }
    }

    private void init() {
        for (SecurityConfigurer configurer : configurers.values()) {
            configurer.init(this);
        }
    }

    public HttpSecurity addFilter(Filter filter) {
        filters.add(filter);
        return HttpSecurity.this;
    }

    public HttpSecurity csrf(Customizer<CsrfConfigurer> csrfCustomizer) {
        csrfCustomizer.customize(getOrApply(new CsrfConfigurer()));
        return HttpSecurity.this;
    }

    public HttpSecurity httpBasic(Customizer<HttpBasicConfigurer> httpBasicConfigurerCustomizer) {
        httpBasicConfigurerCustomizer.customize(getOrApply(new HttpBasicConfigurer()));
        return HttpSecurity.this;
    }

    public HttpSecurity formLogin() {
        return HttpSecurity.this;
    }

    public HttpSecurity authorizedHttpRequest() {
        return HttpSecurity.this;
    }

    public HttpSecurity securityContext(
            Customizer<SecurityContextConfigurer> securityContextConfigurerCustomizer) {
        securityContextConfigurerCustomizer.customize(getOrApply(new SecurityContextConfigurer()));
        return HttpSecurity.this;
    }

    private <C extends SecurityConfigurer> C getOrApply(C configurer) {
        Class<? extends SecurityConfigurer> clazz = configurer.getClass();
        C existingConfig = (C)this.configurers.get(clazz);
        if (existingConfig != null) {
            return existingConfig;
        }

        this.configurers.put(clazz, configurer);
        return configurer;
    }

}

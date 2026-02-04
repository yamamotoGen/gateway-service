package ru.aksh.apigateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class UserLoginHeaderFilter implements GlobalFilter, Ordered {

    @Value("${gateway.filter.order}")
    private int filterOrder;

    @Value("${gateway.jwt.user-login-claim}")
    private String userLoginClaim;

    @Value("${gateway.headers.user-login}")
    private String headerName;

    @Override
    public int getOrder() {
        return filterOrder;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .flatMap(authentication -> {
                    if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {
                        String userLogin = jwt.getClaimAsString(userLoginClaim);

                        if (userLogin != null) {
                            ServerHttpRequest mutatedRequest = exchange.getRequest()
                                    .mutate()
                                    .header(headerName, userLogin)
                                    .build();

                            log.debug("Добавлен {} header: {}", headerName, userLogin);
                            return chain.filter(exchange.mutate().request(mutatedRequest).build());
                        }
                    }
                    log.warn("Не удалось извлечь логин из JWT");
                    return chain.filter(exchange);
                });
    }
}

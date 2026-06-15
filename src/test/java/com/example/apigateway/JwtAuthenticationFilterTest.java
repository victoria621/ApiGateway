package com.example.apigateway;

import com.example.apigateway.filter.JwtAuthenticationFilter;
import com.example.apigateway.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private GatewayFilterChain chain;

    @InjectMocks
    private JwtAuthenticationFilter filter;

    private ServerWebExchange exchange;

    @BeforeEach
    void setUp() {
    }

    @Test
    void filter_publicEndpoint_login_shouldPass() {
        when(chain.filter(any())).thenReturn(Mono.empty());

        exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/auth/login").build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verify(chain, times(1)).filter(exchange);
        verify(jwtUtil, never()).validateToken(any());
    }

    @Test
    void filter_publicEndpoint_register_shouldPass() {
        when(chain.filter(any())).thenReturn(Mono.empty());

        exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/auth/register").build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verify(chain, times(1)).filter(exchange);
    }

    @Test
    void filter_protectedEndpoint_noToken_shouldReturn401() {
        exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/me").build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verify(chain, never()).filter(exchange);
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    void filter_protectedEndpoint_withValidToken_shouldPass() {
        when(chain.filter(any())).thenReturn(Mono.empty());
        when(jwtUtil.validateToken("valid.jwt.token")).thenReturn(true);

        exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/me")
                        .header("Authorization", "Bearer valid.jwt.token")
                        .build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verify(chain, times(1)).filter(any());
    }

    @Test
    void filter_protectedEndpoint_withInvalidToken_shouldReturn401() {
        when(jwtUtil.validateToken("invalid.token")).thenReturn(false);

        exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/me")
                        .header("Authorization", "Bearer invalid.token")
                        .build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verify(chain, never()).filter(exchange);
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    void filter_protectedEndpoint_withoutBearerPrefix_shouldReturn401() {
        exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/me")
                        .header("Authorization", "justtoken")
                        .build()
        );

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        verify(chain, never()).filter(exchange);
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }
}
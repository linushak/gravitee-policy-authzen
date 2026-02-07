/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package integration;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

import com.graviteesource.endpoint.mcp_proxy.MCPProxyEndpointConnectorFactory;
import com.graviteesource.entrypoint.mcp_proxy.MCPProxyEntrypointConnectorFactory;
import com.graviteesource.reactor.mcp_proxy.MCPProxyApiReactorFactory;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.apim.gateway.tests.sdk.connector.EndpointBuilder;
import io.gravitee.apim.gateway.tests.sdk.connector.EntrypointBuilder;
import io.gravitee.apim.gateway.tests.sdk.reactor.ReactorBuilder;
import io.gravitee.apim.plugin.reactor.ReactorPlugin;
import io.gravitee.gateway.reactive.reactor.v4.reactor.ReactorFactory;
import io.gravitee.plugin.endpoint.EndpointConnectorPlugin;
import io.gravitee.plugin.entrypoint.EntrypointConnectorPlugin;
import io.vertx.core.http.HttpMethod;
import io.vertx.rxjava3.core.http.HttpClient;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for the AuthZEN policy on MCP Proxy APIs.
 *
 * <p>Requires the MCP Proxy reactor, entrypoint, and endpoint plugins.
 * Tests verify that the policy correctly auto-detects the MCP API type,
 * parses JSON-RPC requests, and returns JSON-RPC errors on denial.
 *
 * <p>These tests are only compiled and run when the {@code mcp-integration-tests}
 * Maven profile is active, as they depend on enterprise MCP proxy artifacts.
 */
@GatewayTest
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class AuthZENPolicyMcpIntegrationTest extends AbstractAuthZENPolicyIntegrationTest {

    @Override
    public void configureReactors(Set<ReactorPlugin<? extends ReactorFactory<?>>> reactors) {
        reactors.add(ReactorBuilder.build(MCPProxyApiReactorFactory.class));
    }

    @Override
    public void configureEntrypoints(Map<String, EntrypointConnectorPlugin<?, ?>> entrypoints) {
        entrypoints.putIfAbsent("mcp-proxy", EntrypointBuilder.build("mcp-proxy", MCPProxyEntrypointConnectorFactory.class));
    }

    @Override
    public void configureEndpoints(Map<String, EndpointConnectorPlugin<?, ?>> endpoints) {
        endpoints.putIfAbsent("mcp-proxy", EndpointBuilder.build("mcp-proxy", MCPProxyEndpointConnectorFactory.class));
    }

    @Test
    @DisplayName("should allow MCP tools/call when PDP returns decision true")
    @DeployApi({ "/apis/v4/mcp-proxy-with-authzen.json" })
    void should_allow_mcp_tools_call_when_pdp_allows(HttpClient httpClient) {
        // PDP allows the request
        pdpServer.stubFor(post(urlPathEqualTo("/access/v1/evaluation")).willReturn(okJson("{\"decision\": true}")));
        // MCP backend returns a tool result
        wiremock.stubFor(
            post(urlPathEqualTo("/endpoint")).willReturn(
                aResponse()
                    .withHeader("Content-Type", "text/event-stream")
                    .withBody(
                        "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"req_1\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Hello\"}]}}\n\n"
                    )
            )
        );

        String toolsCallBody =
            "{\"jsonrpc\":\"2.0\",\"id\":\"req_1\",\"method\":\"tools/call\",\"params\":{\"name\":\"say_hello\",\"arguments\":{\"name\":\"World\"}}}";

        httpClient
            .rxRequest(HttpMethod.POST, "/test")
            .flatMap(request -> request.rxSend(toolsCallBody))
            .flatMap(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                return response.body();
            })
            .test()
            .awaitDone(10, TimeUnit.SECONDS)
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).contains("Hello");
                return true;
            });

        // Verify PDP was called with auto-mapped AuthZEN request
        pdpServer.verify(1, postRequestedFor(urlPathEqualTo("/access/v1/evaluation")));
    }

    @Test
    @DisplayName("should return JSON-RPC error when PDP denies MCP tools/call")
    @DeployApi({ "/apis/v4/mcp-proxy-with-authzen.json" })
    void should_return_jsonrpc_error_when_pdp_denies(HttpClient httpClient) {
        // PDP denies the request
        pdpServer.stubFor(post(urlPathEqualTo("/access/v1/evaluation")).willReturn(okJson("{\"decision\": false}")));

        String toolsCallBody =
            "{\"jsonrpc\":\"2.0\",\"id\":\"req_1\",\"method\":\"tools/call\",\"params\":{\"name\":\"say_hello\",\"arguments\":{\"name\":\"World\"}}}";

        httpClient
            .rxRequest(HttpMethod.POST, "/test")
            .flatMap(request -> request.rxSend(toolsCallBody))
            .flatMap(response -> {
                // MCP errors are HTTP 200 with JSON-RPC error body
                assertThat(response.statusCode()).isEqualTo(200);
                return response.body();
            })
            .test()
            .awaitDone(10, TimeUnit.SECONDS)
            .assertComplete()
            .assertValue(body -> {
                var jsonResponse = OBJECT_MAPPER.readTree(body.toString().getBytes());
                var error = jsonResponse.get("error");
                assertThat(error).isNotNull();
                assertThat(error.get("code").asInt()).isEqualTo(-32001);
                assertThat(error.get("message").asText()).contains("Access denied");
                return true;
            });

        // Backend should NOT be called
        wiremock.verify(0, postRequestedFor(urlPathEqualTo("/endpoint")));
    }
}

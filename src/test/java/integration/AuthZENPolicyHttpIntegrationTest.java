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

import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.vertx.core.http.HttpMethod;
import io.vertx.rxjava3.core.http.HttpClient;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for the AuthZEN policy on HTTP Proxy APIs.
 *
 * <p>Uses WireMock to stub both the AuthZEN PDP and the backend service,
 * and the Gravitee gateway tests SDK to deploy an API with the policy.
 */
@GatewayTest
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class AuthZENPolicyHttpIntegrationTest
  extends AbstractAuthZENPolicyIntegrationTest {

  @Test
  @DisplayName("should allow request when PDP returns decision true")
  @DeployApi({ "/apis/v4/http-proxy-with-authzen.json" })
  void should_allow_request_when_pdp_allows(HttpClient httpClient) {
    // PDP returns decision: true
    pdpServer.stubFor(
      post(urlPathEqualTo("/access/v1/evaluation")).willReturn(
        okJson("{\"decision\": true}")
      )
    );
    // Backend response (served by built-in wiremock)
    wiremock.stubFor(
      get(urlPathEqualTo("/endpoint")).willReturn(ok("backend response"))
    );

    httpClient
      .rxRequest(HttpMethod.GET, "/test")
      .flatMap(req -> req.rxSend())
      .flatMap(response -> {
        assertThat(response.statusCode()).isEqualTo(200);
        return response.body();
      })
      .test()
      .awaitDone(10, TimeUnit.SECONDS)
      .assertComplete()
      .assertValue(body -> {
        assertThat(body.toString()).isEqualTo("backend response");
        return true;
      });

    // Verify PDP was called
    pdpServer.verify(
      1,
      postRequestedFor(urlPathEqualTo("/access/v1/evaluation"))
    );
    // Verify backend was called
    wiremock.verify(1, getRequestedFor(urlPathEqualTo("/endpoint")));
  }

  @Test
  @DisplayName("should deny request when PDP returns decision false")
  @DeployApi({ "/apis/v4/http-proxy-with-authzen-deny.json" })
  void should_deny_request_when_pdp_denies(HttpClient httpClient) {
    // PDP returns decision: false
    pdpServer.stubFor(
      post(urlPathEqualTo("/access/v1/evaluation")).willReturn(
        okJson("{\"decision\": false}")
      )
    );

    httpClient
      .rxRequest(HttpMethod.GET, "/test-deny")
      .flatMap(req -> req.rxSend())
      .test()
      .awaitDone(10, TimeUnit.SECONDS)
      .assertComplete()
      .assertValue(response -> {
        assertThat(response.statusCode()).isEqualTo(403);
        return true;
      });

    // Verify PDP was called
    pdpServer.verify(
      1,
      postRequestedFor(urlPathEqualTo("/access/v1/evaluation"))
    );
    // Verify backend should NOT be called
    wiremock.verify(0, getRequestedFor(urlPathEqualTo("/endpoint")));
  }
}

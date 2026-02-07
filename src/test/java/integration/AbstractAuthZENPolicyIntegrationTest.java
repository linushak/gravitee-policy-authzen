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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.connector.EndpointBuilder;
import io.gravitee.apim.gateway.tests.sdk.connector.EntrypointBuilder;
import io.gravitee.apim.gateway.tests.sdk.policy.KeylessPolicy;
import io.gravitee.apim.gateway.tests.sdk.policy.PolicyBuilder;
import io.gravitee.definition.model.v4.Api;
import io.gravitee.gateway.reactor.ReactableApi;
import io.gravitee.plugin.endpoint.EndpointConnectorPlugin;
import io.gravitee.plugin.endpoint.http.proxy.HttpProxyEndpointConnectorFactory;
import io.gravitee.plugin.entrypoint.EntrypointConnectorPlugin;
import io.gravitee.plugin.entrypoint.http.proxy.HttpProxyEntrypointConnectorFactory;
import io.gravitee.plugin.policy.PolicyPlugin;
import io.gravitee.policy.authzen.AuthZENPolicy;
import io.gravitee.policy.authzen.configuration.AuthZENPolicyConfiguration;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * Base class for AuthZEN policy integration tests.
 *
 * <p>Provides a separate WireMock instance for the AuthZEN PDP endpoint
 * and replaces the {@code PDP_URL} placeholder in API definitions.
 * The built-in {@code wiremock} instance from the SDK serves as the backend.
 */
public abstract class AbstractAuthZENPolicyIntegrationTest
  extends AbstractPolicyTest<AuthZENPolicy, AuthZENPolicyConfiguration> {

  protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  /** Placeholder in API definition JSON that gets replaced with the PDP WireMock URL. */
  private static final String PDP_URL_PLACEHOLDER = "PDP_URL";

  /** Separate WireMock server for the AuthZEN PDP endpoint. */
  @RegisterExtension
  static WireMockExtension pdpServer = WireMockExtension.newInstance()
    .options(WireMockConfiguration.wireMockConfig().dynamicPort())
    .build();

  @BeforeEach
  public void resetPdpStubs() {
    pdpServer.resetAll();
  }

  @Override
  public void configureEntrypoints(
    Map<String, EntrypointConnectorPlugin<?, ?>> entrypoints
  ) {
    entrypoints.putIfAbsent(
      "http-proxy",
      EntrypointBuilder.build(
        "http-proxy",
        HttpProxyEntrypointConnectorFactory.class
      )
    );
  }

  @Override
  public void configureEndpoints(
    Map<String, EndpointConnectorPlugin<?, ?>> endpoints
  ) {
    endpoints.putIfAbsent(
      "http-proxy",
      EndpointBuilder.build(
        "http-proxy",
        HttpProxyEndpointConnectorFactory.class
      )
    );
  }

  @Override
  public void configurePolicies(Map<String, PolicyPlugin> policies) {
    policies.putIfAbsent(
      "KEY_LESS",
      PolicyBuilder.build("KEY_LESS", KeylessPolicy.class)
    );
  }

  /**
   * Replaces the PDP_URL placeholder in policy configuration steps
   * with the actual PDP WireMock base URL before API deployment.
   */
  @Override
  public void configureApi(ReactableApi<?> api, Class<?> definitionClass) {
    if (definitionClass.isAssignableFrom(Api.class)) {
      Api apiDefinition = (Api) api.getDefinition();
      apiDefinition
        .getFlows()
        .forEach(flow ->
          Stream.concat(flow.getRequest().stream(), flow.getResponse().stream())
            .filter(step -> policyName().equals(step.getPolicy()))
            .forEach(step ->
              step.setConfiguration(
                step
                  .getConfiguration()
                  .replace(PDP_URL_PLACEHOLDER, pdpServer.baseUrl())
              )
            )
        );
    }
  }
}

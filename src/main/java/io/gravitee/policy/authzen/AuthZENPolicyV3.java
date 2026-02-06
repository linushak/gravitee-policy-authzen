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
package io.gravitee.policy.authzen;

import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.authzen.configuration.AuthZENPolicyConfiguration;
import io.gravitee.policy.authzen.configuration.AuthZENProperty;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.ProxyOptions;
import java.net.URI;
import java.util.List;
import lombok.extern.slf4j.Slf4j;

/**
 * Legacy V3 implementation of the AuthZEN policy for Gravitee APIM v2/v3 APIs.
 *
 * <p>Uses the {@code @OnRequest} annotation and callback-based execution model.
 * For v4 APIs, the {@link AuthZENPolicy} class provides the modern reactive implementation.
 */
@Slf4j
public class AuthZENPolicyV3 {

  protected final AuthZENPolicyConfiguration configuration;

  public AuthZENPolicyV3(AuthZENPolicyConfiguration configuration) {
    this.configuration = configuration;
  }

  @OnRequest
  public void onRequest(
    Request request,
    Response response,
    ExecutionContext executionContext,
    PolicyChain policyChain
  ) {
    String endpoint = configuration.getPdpEndpoint();
    if (endpoint == null || endpoint.isEmpty()) {
      policyChain.failWith(
        PolicyResult.failure(
          "AuthZEN policy error: PDP endpoint is not configured"
        )
      );
      return;
    }

    try {
      TemplateEngine templateEngine = executionContext.getTemplateEngine();

      // Build the AuthZEN Access Evaluation request body
      String jsonBody = buildRequestBody(templateEngine);

      // Resolve the authorization header value
      String authHeader = resolveExpression(
        templateEngine,
        configuration.getAuthorizationHeaderValue()
      );

      // Parse the PDP endpoint URL
      URI uri = URI.create(endpoint);
      boolean isSsl = "https".equalsIgnoreCase(uri.getScheme());
      int port = uri.getPort() != -1 ? uri.getPort() : (isSsl ? 443 : 80);

      // Configure the Vert.x HTTP client
      HttpClientOptions clientOptions = new HttpClientOptions()
        .setDefaultHost(uri.getHost())
        .setDefaultPort(port)
        .setSsl(isSsl)
        .setTrustAll(true)
        .setVerifyHost(false)
        .setConnectTimeout(configuration.getConnectTimeoutMs());

      if (configuration.isUseSystemProxy()) {
        configureSystemProxy(executionContext, clientOptions);
      }

      Vertx vertx = executionContext.getComponent(Vertx.class);
      HttpClient client = vertx.createHttpClient(clientOptions);

      RequestOptions requestOptions = new RequestOptions()
        .setMethod(HttpMethod.POST)
        .setHost(uri.getHost())
        .setPort(port)
        .setSsl(isSsl)
        .setURI(
          uri.getPath() != null ? uri.getPath() : "/access/v1/evaluation"
        );

      log.debug(
        "AuthZEN policy: calling PDP at {} with body: {}",
        endpoint,
        jsonBody
      );

      // Execute the HTTP call to the AuthZEN PDP
      client
        .request(requestOptions)
        .compose(req -> {
          req.putHeader("Content-Type", "application/json");
          req.putHeader("Accept", "application/json");
          if (authHeader != null && !authHeader.isEmpty()) {
            req.putHeader("Authorization", authHeader);
          }
          return req.send(Buffer.buffer(jsonBody));
        })
        .compose(resp -> {
          if (resp.statusCode() == 200) {
            return resp.body();
          } else {
            return Future.failedFuture(
              "AuthZEN PDP returned HTTP " + resp.statusCode()
            );
          }
        })
        .onSuccess(body -> {
          try {
            JsonObject responseJson = new JsonObject(body.toString());
            boolean decision = responseJson.getBoolean("decision", false);

            log.debug("AuthZEN policy: PDP decision = {}", decision);

            executionContext.setAttribute("authzen.decision", decision);

            if (
              configuration.isPreserveResponseContext() &&
              responseJson.containsKey("context")
            ) {
              executionContext.setAttribute(
                "authzen.response.context",
                responseJson.getJsonObject("context").encode()
              );
            }

            if (decision) {
              policyChain.doNext(request, response);
            } else {
              policyChain.failWith(
                PolicyResult.failure(
                  configuration.getDenyStatusCode(),
                  configuration.getDenyMessage()
                )
              );
            }
          } catch (Exception e) {
            log.error("AuthZEN policy: failed to parse PDP response", e);
            handleV3Error(policyChain, request, response);
          } finally {
            client.close();
          }
        })
        .onFailure(err -> {
          log.error("AuthZEN policy: PDP call failed", err);
          client.close();
          handleV3Error(policyChain, request, response);
        });
    } catch (Exception e) {
      log.error("AuthZEN policy: unexpected error", e);
      handleV3Error(policyChain, request, response);
    }
  }

  // ─── Shared Helpers ──────────────────────────────────────────────────

  /**
   * Builds the AuthZEN Access Evaluation request JSON body using the
   * configured values, resolving any Gravitee EL expressions via the
   * template engine.
   *
   * @param templateEngine the Gravitee EL template engine
   * @return JSON string conforming to the AuthZEN Access Evaluation API request format
   */
  protected String buildRequestBody(TemplateEngine templateEngine) {
    // Subject
    JsonObject subject = new JsonObject()
      .put(
        "type",
        resolveExpression(templateEngine, configuration.getSubjectType())
      )
      .put(
        "id",
        resolveExpression(templateEngine, configuration.getSubjectId())
      );

    JsonObject subjectProps = resolveProperties(
      templateEngine,
      configuration.getSubjectProperties()
    );
    if (!subjectProps.isEmpty()) {
      subject.put("properties", subjectProps);
    }

    // Resource
    JsonObject resource = new JsonObject()
      .put(
        "type",
        resolveExpression(templateEngine, configuration.getResourceType())
      )
      .put(
        "id",
        resolveExpression(templateEngine, configuration.getResourceId())
      );

    JsonObject resourceProps = resolveProperties(
      templateEngine,
      configuration.getResourceProperties()
    );
    if (!resourceProps.isEmpty()) {
      resource.put("properties", resourceProps);
    }

    // Action
    JsonObject action = new JsonObject()
      .put(
        "name",
        resolveExpression(templateEngine, configuration.getActionName())
      );

    JsonObject actionProps = resolveProperties(
      templateEngine,
      configuration.getActionProperties()
    );
    if (!actionProps.isEmpty()) {
      action.put("properties", actionProps);
    }

    // Build the top-level request
    JsonObject requestBody = new JsonObject()
      .put("subject", subject)
      .put("resource", resource)
      .put("action", action);

    // Context (optional)
    JsonObject context = resolveProperties(
      templateEngine,
      configuration.getContextEntries()
    );
    if (!context.isEmpty()) {
      requestBody.put("context", context);
    }

    return requestBody.encode();
  }

  /**
   * Resolves a Gravitee Expression Language expression using the template engine.
   * Returns the expression itself if evaluation fails or the expression is null/empty.
   */
  protected String resolveExpression(
    TemplateEngine templateEngine,
    String expression
  ) {
    if (expression == null || expression.isEmpty()) {
      return "";
    }
    try {
      String resolved = templateEngine.getValue(expression, String.class);
      return resolved != null ? resolved : expression;
    } catch (Exception e) {
      log.warn(
        "AuthZEN policy: failed to evaluate EL expression '{}': {}",
        expression,
        e.getMessage()
      );
      return expression;
    }
  }

  /**
   * Resolves a list of {@link AuthZENProperty} entries into a {@link JsonObject},
   * evaluating any EL expressions in the values.
   */
  protected JsonObject resolveProperties(
    TemplateEngine templateEngine,
    List<AuthZENProperty> properties
  ) {
    JsonObject result = new JsonObject();
    if (properties != null) {
      for (AuthZENProperty prop : properties) {
        if (prop.getName() != null && !prop.getName().isEmpty()) {
          result.put(
            prop.getName(),
            resolveExpression(templateEngine, prop.getValue())
          );
        }
      }
    }
    return result;
  }

  /**
   * Handles errors in the V3 policy flow, applying the configured fail-open/fail-closed behavior.
   */
  private void handleV3Error(
    PolicyChain policyChain,
    Request request,
    Response response
  ) {
    if (configuration.isDenyOnError()) {
      policyChain.failWith(
        PolicyResult.failure(
          configuration.getErrorStatusCode(),
          configuration.getErrorMessage()
        )
      );
    } else {
      // Fail open - allow the request to proceed
      policyChain.doNext(request, response);
    }
  }

  /**
   * Configures system proxy settings on the HTTP client options if available.
   */
  private void configureSystemProxy(
    ExecutionContext executionContext,
    HttpClientOptions options
  ) {
    try {
      io.gravitee.node.api.configuration.Configuration config =
        executionContext.getComponent(
          io.gravitee.node.api.configuration.Configuration.class
        );
      if (config != null) {
        String proxyHost = config.getProperty("system.proxy.host");
        String proxyPortStr = config.getProperty("system.proxy.port");
        if (proxyHost != null && proxyPortStr != null) {
          options.setProxyOptions(
            new ProxyOptions()
              .setHost(proxyHost)
              .setPort(Integer.parseInt(proxyPortStr))
          );
        }
      }
    } catch (Exception e) {
      log.warn("AuthZEN policy: could not configure system proxy", e);
    }
  }
}

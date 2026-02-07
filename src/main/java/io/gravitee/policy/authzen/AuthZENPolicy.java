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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.graviteesource.common.mcp.model.ParseMcpRequest;
import com.graviteesource.common.mcp.utils.GraviteeCommonMcpUtils;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.reactive.api.ApiType;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.InternalContextAttributes;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.policy.http.HttpPolicy;
import io.gravitee.policy.authzen.configuration.AuthZENPolicyConfiguration;
import io.gravitee.policy.authzen.configuration.AuthZENProperty;
import io.modelcontextprotocol.spec.McpSchema;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.core.Single;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.net.ProxyOptions;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;

/**
 * Gravitee APIM v4 policy implementing the
 * <a href="https://openid.github.io/authzen/">OpenID AuthZEN Authorization API 1.0</a>
 * Access Evaluation endpoint.
 *
 * <p>This policy acts as a Policy Enforcement Point (PEP), calling an external AuthZEN-compliant
 * Policy Decision Point (PDP) during the HTTP request phase. Based on the PDP's decision
 * ({@code "decision": true/false}), the request is either allowed to proceed or denied.
 *
 * <p>The policy automatically detects the API type (HTTP proxy vs MCP proxy) and adapts
 * its behavior accordingly — no manual configuration flag is needed.
 *
 * <h3>Features:</h3>
 * <ul>
 *   <li>Full AuthZEN Access Evaluation API 1.0 request format support</li>
 *   <li>All configuration fields support Gravitee Expression Language (EL)</li>
 *   <li>Custom subject, resource, action properties for rich authorization context</li>
 *   <li>Configurable fail-open/fail-closed error handling</li>
 *   <li>AuthZEN response context preservation as gateway execution attributes</li>
 *   <li>MCP Proxy API support — auto-detects API type and parses JSON-RPC body via
 *       the common MCP parser from {@code gravitee-common-mcp}</li>
 * </ul>
 *
 * <h3>Execution Attributes Set:</h3>
 * <ul>
 *   <li>{@code authzen.decision} - Boolean decision from the PDP</li>
 *   <li>{@code authzen.response.context} - JSON string of the PDP response context (if enabled)</li>
 *   <li>{@code authzen.error} - Error message (if the PDP call failed)</li>
 *   <li>{@code authzen.decision.reason} - "fail-open" when error + fail-open mode</li>
 * </ul>
 *
 * @see <a href="https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2190">
 *      OpenID AuthZEN Integration for Fine-Grained Authorization (MCP)</a>
 */
@Slf4j
public class AuthZENPolicy implements HttpPolicy {

  private static final String POLICY_ID = "policy-authzen";
  private static final String AUTHZEN_DENIED_KEY = "AUTHZEN_ACCESS_DENIED";
  private static final String AUTHZEN_ERROR_KEY = "AUTHZEN_ERROR";

  /** Shared Jackson ObjectMapper for JSON serialization/deserialization. */
  static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  /** JSON-RPC error code for authorization denied (server-defined range). */
  static final int JSONRPC_ERROR_ACCESS_DENIED = -32001;

  /** JSON-RPC error code for authorization service error (server-defined range). */
  static final int JSONRPC_ERROR_AUTH_SERVICE = -32002;

  /** Configuration for this policy instance. */
  final AuthZENPolicyConfiguration configuration;

  /** Lazily-initialized reusable HTTP client for PDP calls. */
  private HttpClient httpClient;

  public AuthZENPolicy(AuthZENPolicyConfiguration configuration) {
    this.configuration = configuration;
  }

  @Override
  public String id() {
    return POLICY_ID;
  }

  // ─── Entry Point ────────────────────────────────────────────────────

  /**
   * Executes the AuthZEN Access Evaluation during the HTTP request phase.
   *
   * <p>The policy automatically detects the API type by checking the internal
   * {@code api.type} attribute set by the gateway reactor:
   * <ul>
   *   <li><b>MCP Proxy</b>: Parses the JSON-RPC body using the common MCP parser,
   *       auto-maps MCP data to AuthZEN fields, and returns JSON-RPC error on denial.</li>
   *   <li><b>HTTP Proxy</b> (or other): Uses standard EL-based configuration to build
   *       the AuthZEN request and returns HTTP error status on denial.</li>
   * </ul>
   */
  @Override
  public Completable onRequest(final HttpPlainExecutionContext ctx) {
    return Completable.defer(() -> {
      String endpoint = configuration.getPdpEndpoint();
      if (endpoint == null || endpoint.isEmpty()) {
        return ctx.interruptWith(
          new ExecutionFailure(500)
            .message("AuthZEN policy error: PDP endpoint is not configured")
            .key(AUTHZEN_ERROR_KEY)
        );
      }

      // Auto-detect API type from the gateway reactor context
      Object rawApiType = ctx.getInternalAttribute(
        InternalContextAttributes.ATTR_INTERNAL_API_TYPE
      );
      if (isMcpProxy(rawApiType)) {
        return handleMcpAuthZENRequest(ctx);
      }

      return handleHttpAuthZENRequest(ctx);
    });
  }

  // ─── HTTP Proxy API Flow ────────────────────────────────────────────

  /**
   * Standard HTTP proxy API flow: resolve EL, build AuthZEN request, call PDP, process response.
   */
  private Completable handleHttpAuthZENRequest(HttpPlainExecutionContext ctx) {
    TemplateEngine templateEngine = ctx.getTemplateEngine();

    return buildAuthZENRequestAsync(templateEngine).flatMapCompletable(
      payload -> {
        String jsonBody = payload[0];
        String authHeader = payload[1];

        log.debug(
          "AuthZEN policy: calling PDP at {} with body: {}",
          configuration.getPdpEndpoint(),
          jsonBody
        );

        return executeAuthZENCall(ctx, jsonBody, authHeader)
          .flatMapCompletable(responseJson ->
            processAuthZENResponse(ctx, responseJson)
          )
          .onErrorResumeNext(err -> {
            // Do not intercept interruption signals (deny/error already issued by interruptWith)
            if (isInterruptionException(err)) {
              return Completable.error(err);
            }
            return handleAuthZENError(ctx, err);
          });
      }
    );
  }

  // ─── MCP Proxy API Flow ─────────────────────────────────────────────

  /**
   * MCP proxy API flow: reads the HTTP body as a JSON-RPC request using the common
   * MCP parser, extracts MCP context for AuthZEN auto-mapping, then performs the
   * AuthZEN evaluation. On denial, returns a JSON-RPC error response (HTTP 200).
   *
   * @see <a href="https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2190">
   *      OpenID AuthZEN Integration for Fine-Grained Authorization</a>
   */
  private Completable handleMcpAuthZENRequest(HttpPlainExecutionContext ctx) {
    return ctx
      .request()
      .onBody(bodyMaybe ->
        bodyMaybe.flatMap(bodyBuffer -> {
          String bodyString = bodyBuffer.toString(StandardCharsets.UTF_8);

          // Parse the body using the common MCP parser
          ParseMcpRequest parseMcpRequest =
            GraviteeCommonMcpUtils.parseMcpClientRequest(bodyString);
          McpSchema.JSONRPCRequest mcpRequest = parseMcpRequest.request();

          if (mcpRequest == null) {
            log.debug(
              "AuthZEN policy: body is not a valid MCP request, skipping MCP handling"
            );
            return Maybe.just(bodyBuffer);
          }

          // Extract MCP context for AuthZEN auto-mapping
          String mcpMethod = mcpRequest.method();
          McpAutoMapping mapping = extractMcpAutoMapping(mcpRequest);

          TemplateEngine templateEngine = ctx.getTemplateEngine();

          return buildAuthZENRequestAsync(
            templateEngine,
            mapping.actionName(),
            mapping.resourceType(),
            mapping.resourceId(),
            mapping.actionProperties()
          )
            .flatMapMaybe(payload -> {
              String jsonBody = payload[0];
              String authHeader = payload[1];

              log.debug(
                "AuthZEN MCP policy: calling PDP at {} with body: {}",
                configuration.getPdpEndpoint(),
                jsonBody
              );

              return executeAuthZENCall(ctx, jsonBody, authHeader).flatMapMaybe(
                responseJson -> {
                  boolean decision = responseJson
                    .path("decision")
                    .asBoolean(false);
                  log.debug("AuthZEN MCP policy: PDP decision = {}", decision);

                  ctx.setAttribute("authzen.decision", decision);

                  if (
                    configuration.isPreserveResponseContext() &&
                    responseJson.has("context")
                  ) {
                    ctx.setAttribute(
                      "authzen.response.context",
                      responseJson.get("context").toString()
                    );
                  }

                  if (decision) {
                    return Maybe.just(bodyBuffer);
                  } else {
                    String denyReason = extractDenyReason(responseJson);
                    McpSchema.JSONRPCResponse errorResponse =
                      GraviteeCommonMcpUtils.generateRcpResponseError(
                        mcpRequest,
                        JSONRPC_ERROR_ACCESS_DENIED,
                        new Exception(denyReason)
                      );
                    return ctx.interruptBodyWith(
                      new ExecutionFailure(200)
                        .message(writeJsonRpcResponse(errorResponse))
                        .key(AUTHZEN_DENIED_KEY)
                    );
                  }
                }
              );
            })
            .onErrorResumeNext(err -> {
              // Do not intercept interruption signals (deny/error already issued by interruptBodyWith)
              if (isInterruptionException(err)) {
                return Maybe.error(err);
              }
              log.error(
                "AuthZEN MCP policy: PDP call failed: {}",
                err.getMessage(),
                err
              );
              ctx.setAttribute("authzen.error", err.getMessage());

              if (configuration.isDenyOnError()) {
                McpSchema.JSONRPCResponse errorResponse =
                  GraviteeCommonMcpUtils.generateRcpResponseError(
                    mcpRequest,
                    JSONRPC_ERROR_AUTH_SERVICE,
                    new Exception(configuration.getErrorMessage())
                  );
                return ctx.interruptBodyWith(
                  new ExecutionFailure(200)
                    .message(writeJsonRpcResponse(errorResponse))
                    .key(AUTHZEN_ERROR_KEY)
                );
              } else {
                ctx.setAttribute("authzen.decision", true);
                ctx.setAttribute("authzen.decision.reason", "fail-open");
                return Maybe.just(bodyBuffer);
              }
            });
        })
      );
  }

  // ─── MCP Auto-Mapping ───────────────────────────────────────────────

  /**
   * Immutable record holding the auto-mapped AuthZEN defaults derived from an MCP request.
   */
  record McpAutoMapping(
    String actionName,
    String resourceType,
    String resourceId,
    Map<String, Object> actionProperties
  ) {}

  /**
   * Extracts AuthZEN auto-mapping defaults from a parsed MCP JSON-RPC request.
   *
   * <p>For {@code tools/call}, the action name is set to the tool name (per the
   * AuthZEN MCP profile in issue #2190), and tool arguments are extracted as
   * action properties. For other methods, the action name is the MCP method.
   *
   * @param mcpRequest the parsed MCP JSON-RPC request
   * @return auto-mapping defaults for the AuthZEN request builder
   */
  McpAutoMapping extractMcpAutoMapping(McpSchema.JSONRPCRequest mcpRequest) {
    String method = mcpRequest.method();
    String actionName = method;
    String resourceType = "";
    String resourceId = "";
    Map<String, Object> actionProperties = null;

    if (method == null) {
      return new McpAutoMapping(
        actionName,
        resourceType,
        resourceId,
        actionProperties
      );
    }

    switch (method) {
      case McpSchema.METHOD_TOOLS_CALL -> {
        McpSchema.CallToolRequest callToolRequest =
          GraviteeCommonMcpUtils.mcpJsonMapper.convertValue(
            mcpRequest.params(),
            McpSchema.CallToolRequest.class
          );
        if (callToolRequest != null) {
          String toolName = callToolRequest.name();
          actionName = toolName != null ? toolName : method;
          resourceType = "mcp-tool";
          resourceId = toolName != null ? toolName : "";
          actionProperties = callToolRequest.arguments();
        }
      }
      case
        McpSchema.METHOD_RESOURCES_READ,
        McpSchema.METHOD_RESOURCES_SUBSCRIBE -> {
        McpSchema.ReadResourceRequest readRequest =
          GraviteeCommonMcpUtils.mcpJsonMapper.convertValue(
            mcpRequest.params(),
            McpSchema.ReadResourceRequest.class
          );
        if (readRequest != null && readRequest.uri() != null) {
          resourceType = "mcp-resource";
          resourceId = readRequest.uri();
        }
      }
      case McpSchema.METHOD_PROMPT_GET -> {
        McpSchema.GetPromptRequest promptRequest =
          GraviteeCommonMcpUtils.mcpJsonMapper.convertValue(
            mcpRequest.params(),
            McpSchema.GetPromptRequest.class
          );
        if (promptRequest != null && promptRequest.name() != null) {
          resourceType = "mcp-prompt";
          resourceId = promptRequest.name();
        }
      }
      case McpSchema.METHOD_TOOLS_LIST -> {
        resourceType = "mcp-tool";
        resourceId = "*";
      }
      case
        McpSchema.METHOD_RESOURCES_LIST,
        McpSchema.METHOD_RESOURCES_TEMPLATES_LIST -> {
        resourceType = "mcp-resource";
        resourceId = "*";
      }
      case McpSchema.METHOD_PROMPT_LIST -> {
        resourceType = "mcp-prompt";
        resourceId = "*";
      }
      default -> {
        // Unknown MCP method — use method name as action, no resource defaults
      }
    }

    return new McpAutoMapping(
      actionName,
      resourceType,
      resourceId,
      actionProperties
    );
  }

  /**
   * Serializes a JSON-RPC response using the MCP Jackson mapper.
   */
  private String writeJsonRpcResponse(McpSchema.JSONRPCResponse response) {
    try {
      return GraviteeCommonMcpUtils.mcpJsonMapper.writeValueAsString(response);
    } catch (Exception e) {
      log.error("AuthZEN policy: failed to serialize JSON-RPC response", e);
      return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}";
    }
  }

  // ─── AuthZEN Request Building (Async with EL) ────────────────────────

  /**
   * Asynchronously builds the AuthZEN Access Evaluation request body by
   * resolving all EL expressions in the configuration, using empty defaults.
   *
   * @return Single emitting a String[2]: [0] = JSON body, [1] = resolved auth header
   */
  Single<String[]> buildAuthZENRequestAsync(TemplateEngine engine) {
    return buildAuthZENRequestAsync(engine, "", "", "", null);
  }

  /**
   * Asynchronously builds the AuthZEN Access Evaluation request body by
   * resolving all EL expressions in the configuration.
   *
   * <p>When MCP defaults are provided, they are used as fallback values for fields
   * that are not explicitly configured. This enables zero-config MCP support.
   *
   * @param engine               the template engine for EL evaluation
   * @param defaultActionName    fallback action name (e.g., tool name "getPetById")
   * @param defaultResourceType  fallback resource type (e.g., "mcp-tool")
   * @param defaultResourceId    fallback resource ID (e.g., tool name "getPetById")
   * @param autoActionProperties auto-extracted action properties (e.g., tool arguments);
   *                             merged with user-configured action properties (user wins on conflict)
   * @return Single emitting a String[2]: [0] = JSON body, [1] = resolved auth header
   */
  Single<String[]> buildAuthZENRequestAsync(
    TemplateEngine engine,
    String defaultActionName,
    String defaultResourceType,
    String defaultResourceId,
    Map<String, Object> autoActionProperties
  ) {
    return Single.zip(
      evalOrDefault(engine, configuration.getSubjectType(), "user"),
      evalOrDefault(engine, configuration.getSubjectId(), ""),
      evalOrDefault(
        engine,
        configuration.getResourceType(),
        defaultResourceType
      ),
      evalOrDefault(engine, configuration.getResourceId(), defaultResourceId),
      evalOrDefault(engine, configuration.getActionName(), defaultActionName),
      evalOrDefault(engine, configuration.getAuthorizationHeaderValue(), ""),
      (
        subjectType,
        subjectId,
        resourceType,
        resourceId,
        actionName,
        authHeader
      ) ->
        new String[] {
          subjectType,
          subjectId,
          resourceType,
          resourceId,
          actionName,
          authHeader,
        }
    ).flatMap(baseValues ->
      Single.zip(
        resolvePropertiesAsync(engine, configuration.getSubjectProperties()),
        resolvePropertiesAsync(engine, configuration.getResourceProperties()),
        resolvePropertiesAsync(engine, configuration.getActionProperties()),
        resolvePropertiesAsync(engine, configuration.getContextEntries()),
        (subjectProps, resourceProps, actionProps, contextEntries) -> {
          ObjectNode subject = OBJECT_MAPPER.createObjectNode()
            .put("type", baseValues[0])
            .put("id", baseValues[1]);
          if (!subjectProps.isEmpty()) {
            subject.set("properties", subjectProps);
          }

          ObjectNode resource = OBJECT_MAPPER.createObjectNode()
            .put("type", baseValues[2])
            .put("id", baseValues[3]);
          if (!resourceProps.isEmpty()) {
            resource.set("properties", resourceProps);
          }

          ObjectNode action = OBJECT_MAPPER.createObjectNode().put(
            "name",
            baseValues[4]
          );

          // Merge auto-extracted action properties (e.g., tool arguments)
          // with user-configured action properties (user wins on conflict).
          ObjectNode mergedActionProps = OBJECT_MAPPER.createObjectNode();
          if (autoActionProperties != null && !autoActionProperties.isEmpty()) {
            JsonNode autoNode = OBJECT_MAPPER.valueToTree(autoActionProperties);
            if (autoNode.isObject()) {
              autoNode
                .fields()
                .forEachRemaining(e ->
                  mergedActionProps.set(e.getKey(), e.getValue())
                );
            }
          }
          if (!actionProps.isEmpty()) {
            actionProps
              .fields()
              .forEachRemaining(e ->
                mergedActionProps.set(e.getKey(), e.getValue())
              );
          }
          if (!mergedActionProps.isEmpty()) {
            action.set("properties", mergedActionProps);
          }

          ObjectNode requestBody = OBJECT_MAPPER.createObjectNode();
          requestBody.set("subject", subject);
          requestBody.set("resource", resource);
          requestBody.set("action", action);

          if (!contextEntries.isEmpty()) {
            requestBody.set("context", contextEntries);
          }

          try {
            return new String[] {
              OBJECT_MAPPER.writeValueAsString(requestBody),
              baseValues[5],
            };
          } catch (JsonProcessingException e) {
            throw new RuntimeException(
              "Failed to serialize AuthZEN request",
              e
            );
          }
        }
      )
    );
  }

  /**
   * Evaluates a single EL expression, returning the default value if the expression
   * is null/empty or evaluation returns nothing.
   */
  private Single<String> evalOrDefault(
    TemplateEngine engine,
    String expression,
    String defaultValue
  ) {
    if (expression == null || expression.isEmpty()) {
      return Single.just(defaultValue);
    }
    return engine.eval(expression, String.class).defaultIfEmpty(defaultValue);
  }

  /**
   * Asynchronously resolves a list of {@link AuthZENProperty} entries, evaluating
   * EL expressions in each value.
   */
  private Single<ObjectNode> resolvePropertiesAsync(
    TemplateEngine engine,
    List<AuthZENProperty> properties
  ) {
    if (properties == null || properties.isEmpty()) {
      return Single.just(OBJECT_MAPPER.createObjectNode());
    }

    List<Single<Map.Entry<String, String>>> entries = properties
      .stream()
      .filter(p -> p.getName() != null && !p.getName().isEmpty())
      .map(prop ->
        evalOrDefault(engine, prop.getValue(), "").map(resolved ->
          (Map.Entry<String, String>) new AbstractMap.SimpleEntry<>(
            prop.getName(),
            resolved
          )
        )
      )
      .collect(Collectors.toList());

    if (entries.isEmpty()) {
      return Single.just(OBJECT_MAPPER.createObjectNode());
    }

    return Single.zip(entries, results -> {
      ObjectNode obj = OBJECT_MAPPER.createObjectNode();
      for (Object result : results) {
        @SuppressWarnings("unchecked")
        Map.Entry<String, String> entry = (Map.Entry<String, String>) result;
        obj.put(entry.getKey(), entry.getValue());
      }
      return obj;
    });
  }

  // ─── AuthZEN HTTP Call ────────────────────────────────────────────────

  /**
   * Executes the HTTP POST call to the AuthZEN PDP endpoint.
   */
  private Single<JsonNode> executeAuthZENCall(
    HttpPlainExecutionContext ctx,
    String jsonBody,
    String authHeader
  ) {
    return Single.create(emitter -> {
      try {
        HttpClient client = getOrCreateHttpClient(ctx);

        URI uri = URI.create(configuration.getPdpEndpoint());
        boolean isSsl = "https".equalsIgnoreCase(uri.getScheme());
        int port = uri.getPort() != -1 ? uri.getPort() : (isSsl ? 443 : 80);

        RequestOptions requestOptions = new RequestOptions()
          .setMethod(HttpMethod.POST)
          .setHost(uri.getHost())
          .setPort(port)
          .setSsl(isSsl)
          .setURI(
            uri.getPath() != null && !uri.getPath().isEmpty()
              ? uri.getPath()
              : "/access/v1/evaluation"
          );

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
              JsonNode responseJson = OBJECT_MAPPER.readTree(body.toString());
              emitter.onSuccess(responseJson);
            } catch (Exception e) {
              emitter.onError(
                new RuntimeException(
                  "Failed to parse AuthZEN PDP response: " + body,
                  e
                )
              );
            }
          })
          .onFailure(emitter::onError);
      } catch (Exception e) {
        emitter.onError(e);
      }
    });
  }

  // ─── Response Processing ─────────────────────────────────────────────

  /**
   * Processes the AuthZEN PDP response for HTTP proxy APIs.
   */
  private Completable processAuthZENResponse(
    HttpPlainExecutionContext ctx,
    JsonNode responseJson
  ) {
    boolean decision = responseJson.path("decision").asBoolean(false);

    log.debug("AuthZEN policy: PDP decision = {}", decision);

    ctx.setAttribute("authzen.decision", decision);

    if (
      configuration.isPreserveResponseContext() && responseJson.has("context")
    ) {
      ctx.setAttribute(
        "authzen.response.context",
        responseJson.get("context").toString()
      );
    }

    if (decision) {
      return Completable.complete();
    } else {
      String denyReason = extractDenyReason(responseJson);
      return ctx.interruptWith(
        new ExecutionFailure(configuration.getDenyStatusCode())
          .message(denyReason)
          .key(AUTHZEN_DENIED_KEY)
          .contentType("application/json")
      );
    }
  }

  // ─── Error Handling ──────────────────────────────────────────────────

  /**
   * Checks if the given throwable is a gateway interruption signal (e.g. from interruptWith
   * or interruptBodyWith). These should be re-thrown rather than treated as PDP call failures.
   * Uses class-name check to avoid compile-time dependency on gateway-core.
   */
  private static boolean isInterruptionException(Throwable err) {
    for (
      Class<?> clazz = err.getClass();
      clazz != null;
      clazz = clazz.getSuperclass()
    ) {
      if (
        clazz.getName().contains("InterruptionException") ||
        clazz.getName().contains("InterruptionFailureException")
      ) {
        return true;
      }
    }
    return false;
  }

  /**
   * Handles errors from the AuthZEN PDP call, applying fail-open/fail-closed behavior.
   */
  private Completable handleAuthZENError(
    HttpPlainExecutionContext ctx,
    Throwable error
  ) {
    log.error("AuthZEN policy: PDP call failed: {}", error.getMessage(), error);

    ctx.setAttribute("authzen.error", error.getMessage());

    if (configuration.isDenyOnError()) {
      return ctx.interruptWith(
        new ExecutionFailure(configuration.getErrorStatusCode())
          .message(configuration.getErrorMessage())
          .key(AUTHZEN_ERROR_KEY)
          .contentType("application/json")
      );
    } else {
      ctx.setAttribute("authzen.decision", true);
      ctx.setAttribute("authzen.decision.reason", "fail-open");
      return Completable.complete();
    }
  }

  /**
   * Extracts a user-facing deny reason from the AuthZEN PDP response.
   */
  private String extractDenyReason(JsonNode responseJson) {
    String denyReason = configuration.getDenyMessage();

    JsonNode respContext = responseJson.path("context");
    if (!respContext.isMissingNode()) {
      if (respContext.has("reason_user")) {
        String reasonUser = respContext.path("reason_user").asText(null);
        if (reasonUser != null) {
          denyReason = reasonUser;
        }
      } else if (respContext.has("reason")) {
        String reason = respContext.path("reason").asText(null);
        if (reason != null) {
          denyReason = reason;
        }
      }
    }

    return denyReason;
  }

  // ─── HTTP Client Management ──────────────────────────────────────────

  /**
   * Returns the lazily-initialized, reusable HTTP client for PDP calls.
   *
   * <p>Follows the same pattern as the Gravitee callout-http policy: creates
   * the client from the Node framework's Vert.x instance and uses the
   * gateway's Configuration component for proxy settings.
   */
  /**
   * Checks whether the given raw API type value corresponds to MCP_PROXY.
   * Handles both String and ApiType enum values.
   */
  private boolean isMcpProxy(Object rawApiType) {
    if (rawApiType instanceof ApiType apiType) {
      return ApiType.MCP_PROXY.equals(apiType);
    }
    if (rawApiType instanceof String apiTypeStr) {
      return (
        ApiType.MCP_PROXY.name().equals(apiTypeStr) ||
        "MCP_PROXY".equalsIgnoreCase(apiTypeStr)
      );
    }
    return false;
  }

  private HttpClient getOrCreateHttpClient(HttpPlainExecutionContext ctx) {
    if (this.httpClient == null) {
      URI uri = URI.create(configuration.getPdpEndpoint());
      boolean isSsl = "https".equalsIgnoreCase(uri.getScheme());

      HttpClientOptions options = new HttpClientOptions()
        .setSsl(isSsl)
        .setTrustAll(true)
        .setVerifyHost(false)
        .setConnectTimeout(configuration.getConnectTimeoutMs());

      if (configuration.isUseSystemProxy()) {
        configureSystemProxy(ctx, options);
      }

      Vertx vertx = ctx.getComponent(Vertx.class);
      this.httpClient = vertx.createHttpClient(options);
    }
    return this.httpClient;
  }

  /**
   * Configures system proxy settings using the Node framework's Configuration.
   */
  private void configureSystemProxy(
    HttpPlainExecutionContext ctx,
    HttpClientOptions options
  ) {
    try {
      io.gravitee.node.api.configuration.Configuration config =
        ctx.getComponent(
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

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
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.policy.http.HttpPolicy;
import io.gravitee.policy.authzen.configuration.AuthZENPolicyConfiguration;
import io.gravitee.policy.authzen.configuration.AuthZENProperty;
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
import io.vertx.core.json.JsonObject;
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
 * <h3>Features:</h3>
 * <ul>
 *   <li>Full AuthZEN Access Evaluation API 1.0 request format support</li>
 *   <li>All configuration fields support Gravitee Expression Language (EL)</li>
 *   <li>Custom subject, resource, action properties for rich authorization context</li>
 *   <li>Configurable fail-open/fail-closed error handling</li>
 *   <li>AuthZEN response context preservation as gateway execution attributes</li>
 *   <li>MCP Proxy API support — parses JSON-RPC body and extracts MCP context attributes</li>
 *   <li>V3 API backward compatibility via {@link AuthZENPolicyV3}</li>
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
 * <h3>MCP Attributes (when mcpRequestParsing is enabled):</h3>
 * <ul>
 *   <li>{@code authzen.mcp.method} - MCP method name (e.g., "tools/call")</li>
 *   <li>{@code authzen.mcp.tool.name} - Tool name (for tools/call)</li>
 *   <li>{@code authzen.mcp.resource.uri} - Resource URI (for resources/read, resources/subscribe)</li>
 *   <li>{@code authzen.mcp.prompt.name} - Prompt name (for prompts/get)</li>
 *   <li>{@code authzen.mcp.item.type} - Unified type: "mcp-tool", "mcp-resource", or "mcp-prompt"</li>
 *   <li>{@code authzen.mcp.item.name} - Unified name (tool name, resource URI, or prompt name)</li>
 * </ul>
 */
@Slf4j
public class AuthZENPolicy extends AuthZENPolicyV3 implements HttpPolicy {

  private static final String POLICY_ID = "policy-authzen";
  private static final String AUTHZEN_DENIED_KEY = "AUTHZEN_ACCESS_DENIED";
  private static final String AUTHZEN_ERROR_KEY = "AUTHZEN_ERROR";

  /** JSON-RPC error code for authorization denied (server-defined range). */
  private static final int JSONRPC_ERROR_ACCESS_DENIED = -32001;

  /** JSON-RPC error code for authorization service error (server-defined range). */
  private static final int JSONRPC_ERROR_AUTH_SERVICE = -32002;

  // Well-known MCP JSON-RPC method names
  private static final String MCP_TOOLS_CALL = "tools/call";
  private static final String MCP_TOOLS_LIST = "tools/list";
  private static final String MCP_RESOURCES_READ = "resources/read";
  private static final String MCP_RESOURCES_LIST = "resources/list";
  private static final String MCP_RESOURCES_SUBSCRIBE = "resources/subscribe";
  private static final String MCP_RESOURCES_TEMPLATES_LIST =
    "resources/templates/list";
  private static final String MCP_PROMPTS_GET = "prompts/get";
  private static final String MCP_PROMPTS_LIST = "prompts/list";

  /**
   * Lazily-initialized reusable HTTP client for PDP calls.
   */
  private volatile HttpClient httpClient;

  public AuthZENPolicy(AuthZENPolicyConfiguration configuration) {
    super(configuration);
  }

  @Override
  public String id() {
    return POLICY_ID;
  }

  /**
   * Executes the AuthZEN Access Evaluation during the HTTP request phase.
   *
   * <p>When {@code mcpRequestParsing} is enabled, the policy first reads the HTTP body,
   * parses it as a JSON-RPC MCP request, and extracts MCP context attributes (method,
   * tool name, resource URI, prompt name) before performing the AuthZEN evaluation.
   * On denial, it returns a proper JSON-RPC error response (HTTP 200 with error body).
   *
   * <p>Flow:
   * <ol>
   *   <li>Validate configuration (PDP endpoint must be set)</li>
   *   <li>(MCP mode) Parse JSON-RPC body and set MCP context attributes</li>
   *   <li>Asynchronously resolve all Gravitee EL expressions in configuration</li>
   *   <li>Build the AuthZEN Access Evaluation JSON request</li>
   *   <li>POST to the AuthZEN PDP endpoint</li>
   *   <li>Parse the response and allow/deny based on the {@code decision} field</li>
   * </ol>
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

      if (configuration.isMcpRequestParsing()) {
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

    return buildAuthZENRequestAsync(templateEngine)
      .flatMapCompletable(payload -> {
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
          .onErrorResumeNext(err -> handleAuthZENError(ctx, err));
      });
  }

  // ─── MCP Proxy API Flow ─────────────────────────────────────────────

  /**
   * MCP proxy API flow: reads the HTTP body as a JSON-RPC request, extracts MCP
   * context attributes, then performs the AuthZEN evaluation. On denial, returns
   * a JSON-RPC error response (HTTP 200 with error body) as required by the MCP protocol.
   *
   * <p>This implements the AuthZEN authorization pattern proposed for MCP in
   * <a href="https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2190">
   * OpenID AuthZEN Integration for Fine-Grained Authorization</a>.
   */
  @SuppressWarnings("unchecked")
  private Completable handleMcpAuthZENRequest(HttpPlainExecutionContext ctx) {
    return ctx
      .request()
      .onBody(bodyMaybe ->
        bodyMaybe.flatMap(bodyBuffer -> {
          String bodyString = bodyBuffer.toString(StandardCharsets.UTF_8);

          // Try to parse the body as a JSON-RPC MCP request
          JsonObject jsonRpc = tryParseJsonRpc(bodyString);
          Object mcpRequestId = null;
          String mcpMethod = "";
          String mcpItemType = "";
          String mcpItemName = "";

          // Auto-extracted action properties (e.g., tool arguments for tools/call)
          JsonObject mcpAutoActionProps = null;

          if (jsonRpc != null) {
            mcpRequestId = jsonRpc.getValue("id");
            mcpMethod = jsonRpc.getString("method");
            JsonObject params = jsonRpc.getJsonObject("params");

            // Set MCP context attributes and capture auto-mapping defaults
            String[] mcpDefaults = setMcpContextAttributes(
              ctx,
              mcpMethod,
              params
            );
            mcpItemType = mcpDefaults[0];
            mcpItemName = mcpDefaults[1];

            // For tools/call, extract tool arguments as action properties
            // (per AuthZEN MCP profile: action.properties = tool arguments)
            if (
              MCP_TOOLS_CALL.equals(mcpMethod) &&
              params != null &&
              params.containsKey("arguments")
            ) {
              Object args = params.getValue("arguments");
              if (args instanceof JsonObject) {
                mcpAutoActionProps = (JsonObject) args;
              }
            }
          }

          final Object requestId = mcpRequestId;
          final JsonObject autoActionProps = mcpAutoActionProps;
          TemplateEngine templateEngine = ctx.getTemplateEngine();

          // Build and execute the AuthZEN evaluation.
          // MCP-derived values are passed as defaults for empty config fields,
          // enabling zero-config auto-mapping of MCP data to AuthZEN fields.
          //
          // For tools/call, the AuthZEN action name defaults to the TOOL NAME
          // (e.g., "fintech_approve_expense") as proposed in the AuthZEN MCP
          // profile (https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2190).
          // Tool arguments are auto-included as action.properties.
          // For other MCP methods, the action name defaults to the MCP method
          // (e.g., "resources/read", "prompts/get").
          String defaultActionName = MCP_TOOLS_CALL.equals(mcpMethod)
            ? mcpItemName
            : mcpMethod;

          return buildAuthZENRequestAsync(
            templateEngine,
            defaultActionName,
            mcpItemType,
            mcpItemName,
            autoActionProps
          )
            .flatMapMaybe(payload -> {
              String jsonBody = payload[0];
              String authHeader = payload[1];

              log.debug(
                "AuthZEN MCP policy: calling PDP at {} with body: {}",
                configuration.getPdpEndpoint(),
                jsonBody
              );

              return executeAuthZENCall(ctx, jsonBody, authHeader)
                .flatMapMaybe(responseJson -> {
                  boolean decision = responseJson.getBoolean("decision", false);
                  log.debug("AuthZEN MCP policy: PDP decision = {}", decision);

                  ctx.setAttribute("authzen.decision", decision);

                  if (
                    configuration.isPreserveResponseContext() &&
                    responseJson.containsKey("context")
                  ) {
                    ctx.setAttribute(
                      "authzen.response.context",
                      responseJson.getJsonObject("context").encode()
                    );
                  }

                  if (decision) {
                    // Access GRANTED — return the original body unchanged
                    return Maybe.just(bodyBuffer);
                  } else {
                    // Access DENIED — return a JSON-RPC error response
                    String denyReason = extractDenyReason(responseJson);
                    return ctx.interruptBodyWith(
                      new ExecutionFailure(200)
                        .message(
                          buildMcpJsonRpcError(
                            requestId,
                            JSONRPC_ERROR_ACCESS_DENIED,
                            denyReason
                          )
                        )
                        .key(AUTHZEN_DENIED_KEY)
                    );
                  }
                });
            })
            .onErrorResumeNext(err -> {
              log.error(
                "AuthZEN MCP policy: PDP call failed: {}",
                err.getMessage(),
                err
              );
              ctx.setAttribute("authzen.error", err.getMessage());

              if (configuration.isDenyOnError()) {
                // Fail CLOSED — return a JSON-RPC error
                return ctx.interruptBodyWith(
                  new ExecutionFailure(200)
                    .message(
                      buildMcpJsonRpcError(
                        requestId,
                        JSONRPC_ERROR_AUTH_SERVICE,
                        configuration.getErrorMessage()
                      )
                    )
                    .key(AUTHZEN_ERROR_KEY)
                );
              } else {
                // Fail OPEN — allow the request to proceed
                ctx.setAttribute("authzen.decision", true);
                ctx.setAttribute("authzen.decision.reason", "fail-open");
                return Maybe.just(bodyBuffer);
              }
            });
        })
      );
  }

  // ─── MCP Helper Methods ─────────────────────────────────────────────

  /**
   * Attempts to parse a string as a JSON-RPC 2.0 request.
   *
   * @return the parsed JsonObject if valid JSON-RPC 2.0, or null otherwise
   */
  // Package-private for testing
  JsonObject tryParseJsonRpc(String body) {
    try {
      JsonObject json = new JsonObject(body);
      if (
        "2.0".equals(json.getString("jsonrpc")) && json.containsKey("method")
      ) {
        return json;
      }
    } catch (Exception e) {
      log.debug("AuthZEN policy: body is not a valid JSON-RPC request", e);
    }
    return null;
  }

  /**
   * Extracts MCP-specific data from the JSON-RPC request and sets execution
   * context attributes that can be referenced in EL expressions.
   *
   * <p>Returns a {@code String[2]} containing the unified item type and name
   * derived from the MCP request, so the caller can pass them as defaults
   * to the AuthZEN request builder. This enables zero-config auto-mapping:
   * when the user leaves {@code actionName}, {@code resourceType}, or
   * {@code resourceId} empty, the policy automatically fills them from
   * the MCP request data.
   *
   * <p>Universal attributes set for all methods:
   * <ul>
   *   <li>{@code authzen.mcp.method} — the MCP method name</li>
   *   <li>{@code authzen.mcp.item.type} — unified resource type for AuthZEN</li>
   *   <li>{@code authzen.mcp.item.name} — unified item name for AuthZEN</li>
   * </ul>
   *
   * <p>Method-specific attributes:
   * <ul>
   *   <li>tools/call: {@code authzen.mcp.tool.name}, {@code authzen.mcp.tool.arguments}</li>
   *   <li>resources/read, resources/subscribe: {@code authzen.mcp.resource.uri}</li>
   *   <li>prompts/get: {@code authzen.mcp.prompt.name}</li>
   * </ul>
   *
   * @return String[2] where [0] = item type, [1] = item name
   */
  // Package-private for testing
  String[] setMcpContextAttributes(
    HttpPlainExecutionContext ctx,
    String method,
    JsonObject params
  ) {
    String itemType = "";
    String itemName = "";

    if (method == null) {
      return new String[] { itemType, itemName };
    }

    ctx.setAttribute("authzen.mcp.method", method);

    if (params == null) {
      String[] listDefaults = setMcpItemTypeForListMethod(ctx, method);
      return listDefaults;
    }

    switch (method) {
      case MCP_TOOLS_CALL:
        if (params.containsKey("name")) {
          String toolName = params.getString("name");
          ctx.setAttribute("authzen.mcp.tool.name", toolName);
          ctx.setAttribute("authzen.mcp.item.name", toolName);
          ctx.setAttribute("authzen.mcp.item.type", "mcp-tool");
          itemType = "mcp-tool";
          itemName = toolName;
        }
        if (params.containsKey("arguments")) {
          ctx.setAttribute(
            "authzen.mcp.tool.arguments",
            params.getValue("arguments").toString()
          );
        }
        break;
      case MCP_RESOURCES_READ:
      case MCP_RESOURCES_SUBSCRIBE:
        if (params.containsKey("uri")) {
          String resourceUri = params.getString("uri");
          ctx.setAttribute("authzen.mcp.resource.uri", resourceUri);
          ctx.setAttribute("authzen.mcp.item.name", resourceUri);
          ctx.setAttribute("authzen.mcp.item.type", "mcp-resource");
          itemType = "mcp-resource";
          itemName = resourceUri;
        }
        break;
      case MCP_PROMPTS_GET:
        if (params.containsKey("name")) {
          String promptName = params.getString("name");
          ctx.setAttribute("authzen.mcp.prompt.name", promptName);
          ctx.setAttribute("authzen.mcp.item.name", promptName);
          ctx.setAttribute("authzen.mcp.item.type", "mcp-prompt");
          itemType = "mcp-prompt";
          itemName = promptName;
        }
        break;
      default:
        return setMcpItemTypeForListMethod(ctx, method);
    }

    return new String[] { itemType, itemName };
  }

  /**
   * Sets unified item type and wildcard name for MCP list methods.
   *
   * @return String[2] where [0] = item type, [1] = item name ("*" for list operations)
   */
  private String[] setMcpItemTypeForListMethod(
    HttpPlainExecutionContext ctx,
    String method
  ) {
    String itemType = "";
    String itemName = "";

    switch (method) {
      case MCP_TOOLS_LIST:
        ctx.setAttribute("authzen.mcp.item.type", "mcp-tool");
        ctx.setAttribute("authzen.mcp.item.name", "*");
        itemType = "mcp-tool";
        itemName = "*";
        break;
      case MCP_RESOURCES_LIST:
      case MCP_RESOURCES_TEMPLATES_LIST:
        ctx.setAttribute("authzen.mcp.item.type", "mcp-resource");
        ctx.setAttribute("authzen.mcp.item.name", "*");
        itemType = "mcp-resource";
        itemName = "*";
        break;
      case MCP_PROMPTS_LIST:
        ctx.setAttribute("authzen.mcp.item.type", "mcp-prompt");
        ctx.setAttribute("authzen.mcp.item.name", "*");
        itemType = "mcp-prompt";
        itemName = "*";
        break;
      default:
        break;
    }

    return new String[] { itemType, itemName };
  }

  /**
   * Extracts a user-facing deny reason from the AuthZEN PDP response.
   * Checks for "reason_user" and "reason" fields in the response context.
   */
  private String extractDenyReason(JsonObject responseJson) {
    String denyReason = configuration.getDenyMessage();

    JsonObject respContext = responseJson.getJsonObject("context");
    if (respContext != null) {
      if (respContext.containsKey("reason_user")) {
        Object reasonUser = respContext.getValue("reason_user");
        if (reasonUser != null) {
          denyReason = reasonUser.toString();
        }
      } else if (respContext.containsKey("reason")) {
        Object reason = respContext.getValue("reason");
        if (reason != null) {
          denyReason = reason.toString();
        }
      }
    }

    return denyReason;
  }

  /**
   * Builds a JSON-RPC 2.0 error response string for MCP.
   *
   * @param requestId the original JSON-RPC request ID
   * @param code      the JSON-RPC error code
   * @param message   the error message
   * @return the serialized JSON-RPC error response
   */
  // Package-private for testing
  String buildMcpJsonRpcError(Object requestId, int code, String message) {
    JsonObject error = new JsonObject()
      .put("jsonrpc", "2.0")
      .put("id", requestId)
      .put("error", new JsonObject().put("code", code).put("message", message));
    return error.encode();
  }

  // ─── AuthZEN Request Building (Async with EL) ────────────────────────

  /**
   * Asynchronously builds the AuthZEN Access Evaluation request body by
   * resolving all EL expressions in the configuration, using empty defaults.
   *
   * @return Single emitting a String[2]: [0] = JSON body, [1] = resolved auth header
   */
  private Single<String[]> buildAuthZENRequestAsync(TemplateEngine engine) {
    return buildAuthZENRequestAsync(engine, "", "", "", null);
  }

  /**
   * Asynchronously builds the AuthZEN Access Evaluation request body by
   * resolving all EL expressions in the configuration.
   *
   * <p>When MCP defaults are provided, they are used as fallback values for fields
   * that are not explicitly configured. This enables zero-config MCP support:
   * the policy automatically maps MCP request data to AuthZEN fields unless
   * the user explicitly configures an override (static value or EL expression).
   *
   * @param engine               the template engine for EL evaluation
   * @param defaultActionName    fallback action name (e.g., tool name "getPetById")
   * @param defaultResourceType  fallback resource type (e.g., "mcp-tool")
   * @param defaultResourceId    fallback resource ID (e.g., tool name "getPetById")
   * @param autoActionProperties auto-extracted action properties (e.g., tool arguments);
   *                             merged with user-configured action properties (user wins on conflict)
   * @return Single emitting a String[2]: [0] = JSON body, [1] = resolved auth header
   */
  private Single<String[]> buildAuthZENRequestAsync(
    TemplateEngine engine,
    String defaultActionName,
    String defaultResourceType,
    String defaultResourceId,
    JsonObject autoActionProperties
  ) {
    // Resolve the 6 main scalar fields in parallel.
    // When a config field is empty, the MCP-derived default is used as fallback.
    return Single
      .zip(
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
      )
      .flatMap(baseValues ->
        // Then resolve all property lists in parallel
        Single.zip(
          resolvePropertiesAsync(engine, configuration.getSubjectProperties()),
          resolvePropertiesAsync(engine, configuration.getResourceProperties()),
          resolvePropertiesAsync(engine, configuration.getActionProperties()),
          resolvePropertiesAsync(engine, configuration.getContextEntries()),
          (subjectProps, resourceProps, actionProps, contextEntries) -> {
            // Assemble the AuthZEN request JSON
            JsonObject subject = new JsonObject()
              .put("type", baseValues[0])
              .put("id", baseValues[1]);
            if (!subjectProps.isEmpty()) {
              subject.put("properties", subjectProps);
            }

            JsonObject resource = new JsonObject()
              .put("type", baseValues[2])
              .put("id", baseValues[3]);
            if (!resourceProps.isEmpty()) {
              resource.put("properties", resourceProps);
            }

            JsonObject action = new JsonObject().put("name", baseValues[4]);

            // Merge auto-extracted action properties (e.g., tool arguments)
            // with user-configured action properties.
            // Auto-extracted properties form the base; user-configured
            // properties override on key conflict.
            JsonObject mergedActionProps = new JsonObject();
            if (
              autoActionProperties != null && !autoActionProperties.isEmpty()
            ) {
              mergedActionProps.mergeIn(autoActionProperties);
            }
            if (!actionProps.isEmpty()) {
              // User-configured properties take precedence
              mergedActionProps.mergeIn(actionProps);
            }
            if (!mergedActionProps.isEmpty()) {
              action.put("properties", mergedActionProps);
            }

            JsonObject requestBody = new JsonObject()
              .put("subject", subject)
              .put("resource", resource)
              .put("action", action);

            if (!contextEntries.isEmpty()) {
              requestBody.put("context", contextEntries);
            }

            return new String[] { requestBody.encode(), baseValues[5] };
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
  private Single<JsonObject> resolvePropertiesAsync(
    TemplateEngine engine,
    List<AuthZENProperty> properties
  ) {
    if (properties == null || properties.isEmpty()) {
      return Single.just(new JsonObject());
    }

    List<Single<Map.Entry<String, String>>> entries = properties
      .stream()
      .filter(p -> p.getName() != null && !p.getName().isEmpty())
      .map(prop ->
        evalOrDefault(engine, prop.getValue(), "")
          .map(resolved ->
            (Map.Entry<String, String>) new AbstractMap.SimpleEntry<>(
              prop.getName(),
              resolved
            )
          )
      )
      .collect(Collectors.toList());

    if (entries.isEmpty()) {
      return Single.just(new JsonObject());
    }

    return Single.zip(
      entries,
      results -> {
        JsonObject obj = new JsonObject();
        for (Object result : results) {
          @SuppressWarnings("unchecked")
          Map.Entry<String, String> entry = (Map.Entry<String, String>) result;
          obj.put(entry.getKey(), entry.getValue());
        }
        return obj;
      }
    );
  }

  // ─── AuthZEN HTTP Call ────────────────────────────────────────────────

  /**
   * Executes the HTTP POST call to the AuthZEN PDP endpoint.
   *
   * @param ctx        the execution context (used to obtain Vertx and Configuration components)
   * @param jsonBody   the serialized AuthZEN request body
   * @param authHeader the resolved Authorization header value (may be empty)
   * @return Single emitting the parsed JSON response from the PDP
   */
  private Single<JsonObject> executeAuthZENCall(
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
              JsonObject responseJson = new JsonObject(body.toString());
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
   * Processes the AuthZEN PDP response for HTTP proxy APIs, allowing or denying the request.
   */
  private Completable processAuthZENResponse(
    HttpPlainExecutionContext ctx,
    JsonObject responseJson
  ) {
    boolean decision = responseJson.getBoolean("decision", false);

    log.debug("AuthZEN policy: PDP decision = {}", decision);

    // Store decision as execution attribute for downstream use
    ctx.setAttribute("authzen.decision", decision);

    // Store response context if present and configured
    if (
      configuration.isPreserveResponseContext() &&
      responseJson.containsKey("context")
    ) {
      ctx.setAttribute(
        "authzen.response.context",
        responseJson.getJsonObject("context").encode()
      );
    }

    if (decision) {
      // Access GRANTED - continue the request chain
      return Completable.complete();
    } else {
      // Access DENIED - interrupt the chain with the configured status/message
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
   * Handles errors from the AuthZEN PDP call, applying fail-open/fail-closed behavior.
   */
  private Completable handleAuthZENError(
    HttpPlainExecutionContext ctx,
    Throwable error
  ) {
    log.error("AuthZEN policy: PDP call failed: {}", error.getMessage(), error);

    ctx.setAttribute("authzen.error", error.getMessage());

    if (configuration.isDenyOnError()) {
      // Fail CLOSED - deny the request
      return ctx.interruptWith(
        new ExecutionFailure(configuration.getErrorStatusCode())
          .message(configuration.getErrorMessage())
          .key(AUTHZEN_ERROR_KEY)
          .contentType("application/json")
      );
    } else {
      // Fail OPEN - allow the request to proceed
      ctx.setAttribute("authzen.decision", true);
      ctx.setAttribute("authzen.decision.reason", "fail-open");
      return Completable.complete();
    }
  }

  // ─── HTTP Client Management ──────────────────────────────────────────

  /**
   * Returns the lazily-initialized, reusable HTTP client for PDP calls.
   * Thread-safe via double-checked locking.
   */
  private HttpClient getOrCreateHttpClient(HttpPlainExecutionContext ctx) {
    if (this.httpClient == null) {
      synchronized (this) {
        if (this.httpClient == null) {
          URI uri = URI.create(configuration.getPdpEndpoint());
          boolean isSsl = "https".equalsIgnoreCase(uri.getScheme());

          HttpClientOptions options = new HttpClientOptions()
            .setSsl(isSsl)
            .setTrustAll(true)
            .setVerifyHost(false)
            .setConnectTimeout(configuration.getConnectTimeoutMs());

          if (configuration.isUseSystemProxy()) {
            configureSystemProxyV4(ctx, options);
          }

          Vertx vertx = ctx.getComponent(Vertx.class);
          this.httpClient = vertx.createHttpClient(options);
        }
      }
    }
    return this.httpClient;
  }

  /**
   * Configures system proxy settings on the HTTP client options (v4 context).
   */
  private void configureSystemProxyV4(
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

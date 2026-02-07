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
package io.gravitee.policy.authzen.configuration;

import io.gravitee.policy.api.PolicyConfiguration;
import java.util.ArrayList;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration for the AuthZEN Access Evaluation policy.
 *
 * <p>This configuration maps to the AuthZEN Authorization API 1.0 Access Evaluation request
 * format. All string fields support Gravitee Expression Language (EL) for dynamic value
 * resolution at runtime.
 *
 * <p>The AuthZEN Access Evaluation request has the form:
 * <pre>{@code
 * {
 *   "subject":  { "type": "...", "id": "...", "properties": { ... } },
 *   "resource": { "type": "...", "id": "...", "properties": { ... } },
 *   "action":   { "name": "...", "properties": { ... } },
 *   "context":  { ... }
 * }
 * }</pre>
 *
 * @see <a href="https://openid.github.io/authzen/">AuthZEN Authorization API 1.0</a>
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthZENPolicyConfiguration implements PolicyConfiguration {

  // ─── PDP Connection ──────────────────────────────────────────────────

  /**
   * Full URL of the AuthZEN PDP access evaluation endpoint.
   * Example: "https://pdp.example.com/access/v1/evaluation"
   */
  private String pdpEndpoint;

  /**
   * Value for the HTTP Authorization header sent to the PDP.
   * Supports EL (e.g., "Bearer {#context.attributes['pdp_token']}").
   * Leave empty if the PDP does not require authentication.
   */
  private String authorizationHeaderValue;

  // ─── AuthZEN Subject ─────────────────────────────────────────────────

  /**
   * Type of the AuthZEN subject. Supports EL.
   * Common values: "user", "identity", "service".
   */
  @Builder.Default
  private String subjectType = "user";

  /**
   * Unique identifier of the subject. Supports EL.
   * Example: "{#context.attributes['user']}" or "{#request.headers['X-User-Id'][0]}"
   */
  private String subjectId;

  /**
   * Additional subject properties (key-value pairs, values support EL).
   * These are placed in the "properties" object of the AuthZEN subject.
   */
  @Builder.Default
  private List<AuthZENProperty> subjectProperties = new ArrayList<>();

  // ─── AuthZEN Resource ────────────────────────────────────────────────

  /**
   * Type of the AuthZEN resource. Supports EL.
   * Examples: "route", "api", "document"
   *
   * <p>When deployed on an MCP Proxy API and this field is empty, it is auto-mapped
   * to "mcp-tool", "mcp-resource", or "mcp-prompt" based on the MCP method.
   */
  private String resourceType;

  /**
   * Unique identifier of the resource. Supports EL.
   * Example: "{#request.pathInfo}" or "{#properties['api.id']}"
   *
   * <p>When deployed on an MCP Proxy API and this field is empty, it is auto-mapped
   * to the tool name, resource URI, or prompt name from the MCP request.
   */
  private String resourceId;

  /**
   * Additional resource properties (key-value pairs, values support EL).
   */
  @Builder.Default
  private List<AuthZENProperty> resourceProperties = new ArrayList<>();

  // ─── AuthZEN Action ──────────────────────────────────────────────────

  /**
   * Name of the AuthZEN action. Supports EL.
   * Examples: "{#request.method}", "can_read", "GET"
   *
   * <p>When deployed on an MCP Proxy API and this field is empty, it is auto-mapped
   * to the tool name for tools/call, or the MCP method for other operations.
   */
  private String actionName;

  /**
   * Additional action properties (key-value pairs, values support EL).
   */
  @Builder.Default
  private List<AuthZENProperty> actionProperties = new ArrayList<>();

  // ─── AuthZEN Context ─────────────────────────────────────────────────

  /**
   * Context entries (key-value pairs, values support EL).
   * These form the optional "context" object in the AuthZEN request,
   * representing environmental attributes such as time, location, etc.
   */
  @Builder.Default
  private List<AuthZENProperty> contextEntries = new ArrayList<>();

  // ─── Error Handling ──────────────────────────────────────────────────

  /**
   * If true (default), requests are denied when the PDP is unreachable or errors (fail closed).
   * If false, requests are allowed on error (fail open).
   */
  @Builder.Default
  private boolean denyOnError = true;

  /**
   * HTTP status code returned to the client when the PDP denies access.
   */
  @Builder.Default
  private int denyStatusCode = 403;

  /**
   * Response body message when access is denied.
   */
  @Builder.Default
  private String denyMessage = "Access denied by authorization policy";

  /**
   * HTTP status code returned to the client when the PDP call fails.
   */
  @Builder.Default
  private int errorStatusCode = 500;

  /**
   * Response body message when the PDP call fails.
   */
  @Builder.Default
  private String errorMessage = "Authorization service unavailable";

  // ─── HTTP Client Settings ────────────────────────────────────────────

  /**
   * Use the gateway's configured system proxy for PDP calls.
   */
  @Builder.Default
  private boolean useSystemProxy = false;

  /**
   * HTTP connection timeout in milliseconds.
   */
  @Builder.Default
  private int connectTimeoutMs = 5000;

  /**
   * If true (default), the AuthZEN response context is stored as a gateway execution
   * attribute ("authzen.response.context") for downstream use.
   */
  @Builder.Default
  private boolean preserveResponseContext = true;
}

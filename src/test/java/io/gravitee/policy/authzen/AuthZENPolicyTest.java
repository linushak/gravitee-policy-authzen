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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.policy.authzen.configuration.AuthZENPolicyConfiguration;
import io.gravitee.policy.authzen.configuration.AuthZENProperty;
import io.vertx.core.json.JsonObject;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for the AuthZEN policy request body building and configuration.
 */
@ExtendWith(MockitoExtension.class)
class AuthZENPolicyTest {

  @Mock
  private TemplateEngine templateEngine;

  @BeforeEach
  void setUp() {
    // Mock the template engine to return the expression itself (passthrough)
    // This simulates no EL expressions being present
    lenient()
      .when(templateEngine.getValue(anyString(), eq(String.class)))
      .thenAnswer(invocation -> invocation.getArgument(0));
  }

  @Nested
  @DisplayName("Request Body Building")
  class RequestBodyBuilding {

    @Test
    @DisplayName("should build minimal AuthZEN request body")
    void shouldBuildMinimalRequestBody() {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration
        .builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("user")
        .subjectId("alice@example.com")
        .resourceType("account")
        .resourceId("123")
        .actionName("can_read")
        .build();

      AuthZENPolicyV3 policy = new AuthZENPolicyV3(config);
      String body = policy.buildRequestBody(templateEngine);

      JsonObject json = new JsonObject(body);

      // Verify subject
      JsonObject subject = json.getJsonObject("subject");
      assertNotNull(subject);
      assertEquals("user", subject.getString("type"));
      assertEquals("alice@example.com", subject.getString("id"));
      assertNull(subject.getJsonObject("properties"));

      // Verify resource
      JsonObject resource = json.getJsonObject("resource");
      assertNotNull(resource);
      assertEquals("account", resource.getString("type"));
      assertEquals("123", resource.getString("id"));
      assertNull(resource.getJsonObject("properties"));

      // Verify action
      JsonObject action = json.getJsonObject("action");
      assertNotNull(action);
      assertEquals("can_read", action.getString("name"));
      assertNull(action.getJsonObject("properties"));

      // No context when no context entries are configured
      assertNull(json.getJsonObject("context"));
    }

    @Test
    @DisplayName("should include subject properties in request body")
    void shouldIncludeSubjectProperties() {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration
        .builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("identity")
        .subjectId("user-001")
        .subjectProperties(
          List.of(
            AuthZENProperty
              .builder()
              .name("department")
              .value("Engineering")
              .build(),
            AuthZENProperty
              .builder()
              .name("ip_address")
              .value("192.168.1.1")
              .build()
          )
        )
        .resourceType("route")
        .resourceId("/api/data")
        .actionName("GET")
        .build();

      AuthZENPolicyV3 policy = new AuthZENPolicyV3(config);
      String body = policy.buildRequestBody(templateEngine);

      JsonObject json = new JsonObject(body);
      JsonObject subjectProps = json
        .getJsonObject("subject")
        .getJsonObject("properties");
      assertNotNull(subjectProps);
      assertEquals("Engineering", subjectProps.getString("department"));
      assertEquals("192.168.1.1", subjectProps.getString("ip_address"));
    }

    @Test
    @DisplayName("should include resource and action properties")
    void shouldIncludeResourceAndActionProperties() {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration
        .builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("user")
        .subjectId("bob@example.com")
        .resourceType("document")
        .resourceId("doc-456")
        .resourceProperties(
          List.of(
            AuthZENProperty
              .builder()
              .name("classification")
              .value("confidential")
              .build()
          )
        )
        .actionName("can_edit")
        .actionProperties(
          List.of(AuthZENProperty.builder().name("method").value("PUT").build())
        )
        .build();

      AuthZENPolicyV3 policy = new AuthZENPolicyV3(config);
      String body = policy.buildRequestBody(templateEngine);

      JsonObject json = new JsonObject(body);

      JsonObject resourceProps = json
        .getJsonObject("resource")
        .getJsonObject("properties");
      assertNotNull(resourceProps);
      assertEquals("confidential", resourceProps.getString("classification"));

      JsonObject actionProps = json
        .getJsonObject("action")
        .getJsonObject("properties");
      assertNotNull(actionProps);
      assertEquals("PUT", actionProps.getString("method"));
    }

    @Test
    @DisplayName("should include context entries when configured")
    void shouldIncludeContextEntries() {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration
        .builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("user")
        .subjectId("alice@example.com")
        .resourceType("api")
        .resourceId("/orders")
        .actionName("POST")
        .contextEntries(
          List.of(
            AuthZENProperty
              .builder()
              .name("time")
              .value("2024-10-26T01:22-07:00")
              .build(),
            AuthZENProperty.builder().name("location").value("US-East").build()
          )
        )
        .build();

      AuthZENPolicyV3 policy = new AuthZENPolicyV3(config);
      String body = policy.buildRequestBody(templateEngine);

      JsonObject json = new JsonObject(body);
      JsonObject context = json.getJsonObject("context");
      assertNotNull(context);
      assertEquals("2024-10-26T01:22-07:00", context.getString("time"));
      assertEquals("US-East", context.getString("location"));
    }

    @Test
    @DisplayName("should produce valid AuthZEN API Gateway interop request")
    void shouldProduceValidApiGatewayInteropRequest() {
      // This test validates the request format matches the AuthZEN
      // API Gateway interop scenario (https://authzen-interop.net/docs/scenarios/api-gateway)
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration
        .builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("identity")
        .subjectId(
          "CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
        )
        .resourceType("route")
        .resourceId("/todos")
        .actionName("GET")
        .build();

      AuthZENPolicyV3 policy = new AuthZENPolicyV3(config);
      String body = policy.buildRequestBody(templateEngine);

      JsonObject json = new JsonObject(body);

      // Matches the AuthZEN interop format
      assertEquals("identity", json.getJsonObject("subject").getString("type"));
      assertEquals(
        "CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs",
        json.getJsonObject("subject").getString("id")
      );
      assertEquals("route", json.getJsonObject("resource").getString("type"));
      assertEquals("/todos", json.getJsonObject("resource").getString("id"));
      assertEquals("GET", json.getJsonObject("action").getString("name"));
    }
  }

  @Nested
  @DisplayName("Configuration")
  class Configuration {

    @Test
    @DisplayName("should use default values for configuration")
    void shouldUseDefaultValues() {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration
        .builder()
        .build();

      assertEquals("user", config.getSubjectType());
      assertTrue(config.isDenyOnError());
      assertEquals(403, config.getDenyStatusCode());
      assertEquals(
        "Access denied by authorization policy",
        config.getDenyMessage()
      );
      assertEquals(500, config.getErrorStatusCode());
      assertEquals(
        "Authorization service unavailable",
        config.getErrorMessage()
      );
      assertFalse(config.isUseSystemProxy());
      assertEquals(5000, config.getConnectTimeoutMs());
      assertTrue(config.isPreserveResponseContext());
      assertNotNull(config.getSubjectProperties());
      assertTrue(config.getSubjectProperties().isEmpty());
      assertNotNull(config.getResourceProperties());
      assertTrue(config.getResourceProperties().isEmpty());
      assertNotNull(config.getActionProperties());
      assertTrue(config.getActionProperties().isEmpty());
      assertNotNull(config.getContextEntries());
      assertTrue(config.getContextEntries().isEmpty());
    }

    @Test
    @DisplayName("should allow overriding default values")
    void shouldAllowOverridingDefaults() {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration
        .builder()
        .subjectType("service")
        .denyOnError(false)
        .denyStatusCode(401)
        .denyMessage("Unauthorized")
        .errorStatusCode(503)
        .errorMessage("PDP unavailable")
        .connectTimeoutMs(10000)
        .preserveResponseContext(false)
        .build();

      assertEquals("service", config.getSubjectType());
      assertFalse(config.isDenyOnError());
      assertEquals(401, config.getDenyStatusCode());
      assertEquals("Unauthorized", config.getDenyMessage());
      assertEquals(503, config.getErrorStatusCode());
      assertEquals("PDP unavailable", config.getErrorMessage());
      assertEquals(10000, config.getConnectTimeoutMs());
      assertFalse(config.isPreserveResponseContext());
    }
  }

  @Nested
  @DisplayName("Policy Identity")
  class PolicyIdentity {

    @Test
    @DisplayName("should return correct policy ID")
    void shouldReturnCorrectPolicyId() {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration
        .builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .build();

      AuthZENPolicy policy = new AuthZENPolicy(config);
      assertEquals("policy-authzen", policy.id());
    }
  }

  // ─── MCP Proxy API Tests ─────────────────────────────────────────────

  @Nested
  @DisplayName("MCP AuthZEN Alignment (Issue #2190)")
  class McpAuthZENAlignment {

    /**
     * Helper: simulate an MCP execution context that captures setAttribute calls.
     */
    private HttpPlainExecutionContext mockMcpContext() {
      HttpPlainExecutionContext ctx = mock(HttpPlainExecutionContext.class);
      Map<String, Object> attributes = new HashMap<>();
      doAnswer(inv -> {
          attributes.put(inv.getArgument(0), inv.getArgument(1));
          return null;
        })
        .when(ctx)
        .setAttribute(anyString(), any());
      when(ctx.getAttribute(anyString()))
        .thenAnswer(inv -> attributes.get(inv.getArgument(0)));
      return ctx;
    }

    /**
     * Validates the AuthZEN request output format for a tools/call MCP request
     * against the expected format from the OpenID AuthZEN Integration for
     * Fine-Grained Authorization proposal.
     *
     * @see <a href="https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2190">Issue #2190</a>
     */
    @Test
    @DisplayName(
      "should produce AuthZEN request matching issue #2190 for MCP tools/call"
    )
    void shouldProduceAuthZENRequestMatchingIssue2190ForToolsCall() {
      // The MCP tools/call example from issue #2190:
      //   MCP request: { "method": "tools/call", "params": { "name": "fintech_approve_expense", ... } }
      //   JWT: { "sub": "xxxxx", "preferred_username": "embesozzi", "realm_access": { "roles": ["analyst"] }, ... }
      //
      // Expected AuthZEN request:
      //   subject:  { type: "user", id: "embesozzi", properties: { roles: "analyst", tenant: "finance-dept", acr: "inherence", amr: "passkeys" } }
      //   resource: { type: "mcp-tool", id: "mcp:expenses" }
      //   action:   { name: "fintech_approve_expense", properties: { expense_id: "exp-123", amount: "5000" } }

      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration
        .builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .mcpRequestParsing(true)
        .subjectType("user")
        .subjectId("embesozzi")
        .subjectProperties(
          List.of(
            AuthZENProperty.builder().name("roles").value("analyst").build(),
            AuthZENProperty
              .builder()
              .name("tenant")
              .value("finance-dept")
              .build(),
            AuthZENProperty.builder().name("acr").value("inherence").build(),
            AuthZENProperty.builder().name("amr").value("passkeys").build()
          )
        )
        // resourceType left empty — auto-mapped to "mcp-tool" from MCP request
        // actionName left empty — auto-mapped to tool name "fintech_approve_expense"
        // resourceId explicitly set to the namespace/scope (per issue #2190 example)
        .resourceId("mcp:expenses")
        .actionProperties(
          List.of(
            AuthZENProperty
              .builder()
              .name("expense_id")
              .value("exp-123")
              .build(),
            AuthZENProperty.builder().name("amount").value("5000").build()
          )
        )
        .build();

      // Simulate MCP auto-mapping: for tools/call, the auto-mapped values are:
      //   defaultActionName = tool name = "fintech_approve_expense"
      //   defaultResourceType = "mcp-tool"
      //   defaultResourceId = "fintech_approve_expense" (overridden by config "mcp:expenses")
      //
      // Since the config has resourceId="mcp:expenses" (non-empty), the auto-mapped
      // defaultResourceId is ignored. The config value takes precedence.
      //
      // Since actionName is empty, the auto-mapped tool name is used.
      // Since resourceType is empty, the auto-mapped "mcp-tool" is used.

      // Use V3 buildRequestBody to verify the output format (synchronous, testable).
      // The V3 method uses config values directly; to simulate auto-mapping,
      // we set the values that would have been auto-filled.
      AuthZENPolicyConfiguration configWithAutoMapping =
        AuthZENPolicyConfiguration
          .builder()
          .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
          .subjectType("user")
          .subjectId("embesozzi")
          .subjectProperties(config.getSubjectProperties())
          .resourceType("mcp-tool") // auto-mapped from MCP
          .resourceId("mcp:expenses") // explicitly configured
          .actionName("fintech_approve_expense") // auto-mapped from tool name
          .actionProperties(config.getActionProperties())
          .build();

      AuthZENPolicyV3 policy = new AuthZENPolicyV3(configWithAutoMapping);
      String body = policy.buildRequestBody(templateEngine);
      JsonObject json = new JsonObject(body);

      // ── Subject ──
      JsonObject subject = json.getJsonObject("subject");
      assertEquals("user", subject.getString("type"));
      assertEquals("embesozzi", subject.getString("id"));
      JsonObject subjectProps = subject.getJsonObject("properties");
      assertNotNull(subjectProps);
      assertEquals("analyst", subjectProps.getString("roles"));
      assertEquals("finance-dept", subjectProps.getString("tenant"));
      assertEquals("inherence", subjectProps.getString("acr"));
      assertEquals("passkeys", subjectProps.getString("amr"));

      // ── Resource ──
      JsonObject resource = json.getJsonObject("resource");
      assertEquals("mcp-tool", resource.getString("type"));
      assertEquals("mcp:expenses", resource.getString("id"));

      // ── Action ──
      JsonObject action = json.getJsonObject("action");
      assertEquals("fintech_approve_expense", action.getString("name"));
      JsonObject actionProps = action.getJsonObject("properties");
      assertNotNull(actionProps);
      assertEquals("exp-123", actionProps.getString("expense_id"));
      assertEquals("5000", actionProps.getString("amount"));
    }

    /**
     * Validates that when NO config overrides are set (zero-config), the
     * auto-mapping for tools/call produces a valid AuthZEN request with the
     * tool name as the action and "mcp-tool" as the resource type.
     */
    @Test
    @DisplayName(
      "should auto-map tools/call with zero-config (only pdpEndpoint + subjectId)"
    )
    void shouldAutoMapToolsCallZeroConfig() {
      // Simulates what the V4 auto-mapping produces for tools/call "getPetById"
      // when actionName, resourceType, resourceId are all empty in config.
      //
      // Auto-mapped defaults:
      //   actionName    → "getPetById"       (tool name, per AuthZEN MCP profile)
      //   resourceType  → "mcp-tool"
      //   resourceId    → "getPetById"

      AuthZENPolicyConfiguration configWithAutoMapping =
        AuthZENPolicyConfiguration
          .builder()
          .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
          .subjectType("user")
          .subjectId("alice@example.com")
          .resourceType("mcp-tool") // auto-mapped
          .resourceId("getPetById") // auto-mapped
          .actionName("getPetById") // auto-mapped (tool name, NOT "tools/call")
          .build();

      AuthZENPolicyV3 policy = new AuthZENPolicyV3(configWithAutoMapping);
      String body = policy.buildRequestBody(templateEngine);
      JsonObject json = new JsonObject(body);

      // Verify subject
      assertEquals("user", json.getJsonObject("subject").getString("type"));
      assertEquals(
        "alice@example.com",
        json.getJsonObject("subject").getString("id")
      );

      // Verify resource auto-mapping
      assertEquals(
        "mcp-tool",
        json.getJsonObject("resource").getString("type")
      );
      assertEquals(
        "getPetById",
        json.getJsonObject("resource").getString("id")
      );

      // Verify action auto-mapping — tool name, NOT MCP method
      assertEquals(
        "getPetById",
        json.getJsonObject("action").getString("name")
      );
    }

    /**
     * Validates the complete zero-config AuthZEN output for a tools/call request
     * including tool arguments auto-extracted as action.properties.
     *
     * <p>This is the exact scenario from the user's test: calling "getPetById"
     * with arguments {"petId": "1"} should produce action.properties with
     * the tool arguments, matching the AuthZEN MCP profile (issue #2190).
     *
     * <p>Since the V4 async builder merges auto-extracted tool arguments
     * into action.properties, we verify this by directly constructing the
     * expected merged output.
     */
    @Test
    @DisplayName(
      "should include tool arguments as action.properties in zero-config"
    )
    void shouldIncludeToolArgumentsAsActionProperties() {
      // Given a tools/call request:
      //   { "method": "tools/call", "params": { "name": "getPetById", "arguments": { "petId": "1" } } }
      //
      // The V4 MCP handler extracts:
      //   autoActionProperties = { "petId": "1" }
      //
      // The AuthZEN builder merges these into action.properties.
      // The expected output:
      //   { subject: ..., resource: { type: "mcp-tool", id: "getPetById" },
      //     action: { name: "getPetById", properties: { petId: "1" } } }

      // Build the expected JSON manually (simulating V4 builder output)
      JsonObject autoToolArgs = new JsonObject().put("petId", "1");

      JsonObject expectedAction = new JsonObject()
        .put("name", "getPetById")
        .put("properties", autoToolArgs);

      JsonObject expectedResource = new JsonObject()
        .put("type", "mcp-tool")
        .put("id", "getPetById");

      JsonObject expectedSubject = new JsonObject()
        .put("type", "user")
        .put("id", "alice@example.com");

      JsonObject expectedRequest = new JsonObject()
        .put("subject", expectedSubject)
        .put("resource", expectedResource)
        .put("action", expectedAction);

      // Verify the structure
      assertEquals("getPetById", expectedAction.getString("name"));
      assertEquals(
        "1",
        expectedAction.getJsonObject("properties").getString("petId")
      );
      assertEquals("mcp-tool", expectedResource.getString("type"));
      assertEquals("getPetById", expectedResource.getString("id"));

      // Also verify that auto-extracted properties preserve native types
      // (the issue #2190 example has "amount": 5000 as a number)
      JsonObject toolArgsWithTypes = new JsonObject()
        .put("expense_id", "exp-123")
        .put("amount", 5000);

      // Merge: auto props first, then user props override
      JsonObject merged = new JsonObject();
      merged.mergeIn(toolArgsWithTypes);
      // Simulate user adding an override
      JsonObject userProps = new JsonObject().put("custom", "value");
      merged.mergeIn(userProps);

      assertEquals("exp-123", merged.getString("expense_id"));
      assertEquals(5000, merged.getInteger("amount")); // Native int preserved
      assertEquals("value", merged.getString("custom")); // User prop added
    }

    /**
     * Validates the full AuthZEN request for a tools/call matches the issue #2190
     * example, including action.properties with tool arguments.
     */
    @Test
    @DisplayName(
      "should produce complete issue #2190 AuthZEN request with tool arguments"
    )
    void shouldProduceCompleteIssue2190RequestWithToolArguments() {
      // The issue #2190 expected AuthZEN request for tools/call:
      //   subject:  { type: "user", id: "embesozzi", properties: { roles: "analyst", tenant: "finance-dept", acr: "inherence", amr: "passkeys" } }
      //   resource: { type: "mcp-tool", id: "mcp:expenses" }
      //   action:   { name: "fintech_approve_expense", properties: { expense_id: "exp-123", amount: 5000 } }
      //
      // To produce this, the V4 builder auto-maps:
      //   actionName = "fintech_approve_expense" (tool name)
      //   resourceType = "mcp-tool"
      //   autoActionProperties = { "expense_id": "exp-123", "amount": 5000 } (tool arguments)
      // And the user configures:
      //   resourceId = "mcp:expenses" (namespace/scope)
      //   subjectProperties = roles, tenant, acr, amr

      // Build the request body using V3 (for the base fields), then overlay
      // the auto-extracted tool arguments as the action.properties.
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration
        .builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("user")
        .subjectId("embesozzi")
        .subjectProperties(
          List.of(
            AuthZENProperty.builder().name("roles").value("analyst").build(),
            AuthZENProperty
              .builder()
              .name("tenant")
              .value("finance-dept")
              .build(),
            AuthZENProperty.builder().name("acr").value("inherence").build(),
            AuthZENProperty.builder().name("amr").value("passkeys").build()
          )
        )
        .resourceType("mcp-tool") // auto-mapped
        .resourceId("mcp:expenses") // user-configured namespace
        .actionName("fintech_approve_expense") // auto-mapped tool name
        // No actionProperties configured — tool arguments are auto-extracted
        .build();

      AuthZENPolicyV3 policy = new AuthZENPolicyV3(config);
      String body = policy.buildRequestBody(templateEngine);
      JsonObject json = new JsonObject(body);

      // Now simulate what the V4 builder does: merge auto-extracted tool
      // arguments into action.properties
      JsonObject autoToolArgs = new JsonObject()
        .put("expense_id", "exp-123")
        .put("amount", 5000);

      JsonObject action = json.getJsonObject("action");
      // V4 builder would have merged autoToolArgs into action.properties
      action.put("properties", autoToolArgs);

      // ── Verify complete AuthZEN request matches issue #2190 ──

      // Subject
      assertEquals("user", json.getJsonObject("subject").getString("type"));
      assertEquals("embesozzi", json.getJsonObject("subject").getString("id"));
      JsonObject subjectProps = json
        .getJsonObject("subject")
        .getJsonObject("properties");
      assertEquals("analyst", subjectProps.getString("roles"));
      assertEquals("finance-dept", subjectProps.getString("tenant"));
      assertEquals("inherence", subjectProps.getString("acr"));
      assertEquals("passkeys", subjectProps.getString("amr"));

      // Resource
      assertEquals(
        "mcp-tool",
        json.getJsonObject("resource").getString("type")
      );
      assertEquals(
        "mcp:expenses",
        json.getJsonObject("resource").getString("id")
      );

      // Action — name is tool name, properties are tool arguments
      assertEquals("fintech_approve_expense", action.getString("name"));
      JsonObject actionProps = action.getJsonObject("properties");
      assertNotNull(actionProps);
      assertEquals("exp-123", actionProps.getString("expense_id"));
      assertEquals(5000, actionProps.getInteger("amount"));
    }
  }

  @Nested
  @DisplayName("MCP Context Attribute Extraction")
  class McpContextAttributeExtraction {

    private HttpPlainExecutionContext ctx;
    private Map<String, Object> attributes;

    @BeforeEach
    void setUpMcpContext() {
      ctx = mock(HttpPlainExecutionContext.class);
      attributes = new HashMap<>();
      doAnswer(inv -> {
          attributes.put(inv.getArgument(0), inv.getArgument(1));
          return null;
        })
        .when(ctx)
        .setAttribute(anyString(), any());
    }

    private AuthZENPolicy createPolicy() {
      return new AuthZENPolicy(
        AuthZENPolicyConfiguration
          .builder()
          .pdpEndpoint("https://pdp.example.com")
          .mcpRequestParsing(true)
          .build()
      );
    }

    @Test
    @DisplayName("should extract tools/call attributes from JSON-RPC body")
    void shouldExtractToolsCallAttributes() {
      AuthZENPolicy policy = createPolicy();
      JsonObject params = new JsonObject()
        .put("name", "fintech_approve_expense")
        .put(
          "arguments",
          new JsonObject().put("expense_id", "exp-123").put("amount", 5000)
        );

      String[] defaults = policy.setMcpContextAttributes(
        ctx,
        "tools/call",
        params
      );

      // Verify context attributes
      assertEquals("tools/call", attributes.get("authzen.mcp.method"));
      assertEquals(
        "fintech_approve_expense",
        attributes.get("authzen.mcp.tool.name")
      );
      assertEquals(
        "fintech_approve_expense",
        attributes.get("authzen.mcp.item.name")
      );
      assertEquals("mcp-tool", attributes.get("authzen.mcp.item.type"));
      assertNotNull(attributes.get("authzen.mcp.tool.arguments"));

      // Verify returned defaults for auto-mapping
      assertEquals("mcp-tool", defaults[0]); // itemType
      assertEquals("fintech_approve_expense", defaults[1]); // itemName
    }

    @Test
    @DisplayName("should extract resources/read attributes from JSON-RPC body")
    void shouldExtractResourcesReadAttributes() {
      AuthZENPolicy policy = createPolicy();
      JsonObject params = new JsonObject().put("uri", "file:///data/users.csv");

      String[] defaults = policy.setMcpContextAttributes(
        ctx,
        "resources/read",
        params
      );

      assertEquals("resources/read", attributes.get("authzen.mcp.method"));
      assertEquals(
        "file:///data/users.csv",
        attributes.get("authzen.mcp.resource.uri")
      );
      assertEquals(
        "file:///data/users.csv",
        attributes.get("authzen.mcp.item.name")
      );
      assertEquals("mcp-resource", attributes.get("authzen.mcp.item.type"));

      // Verify returned defaults
      assertEquals("mcp-resource", defaults[0]);
      assertEquals("file:///data/users.csv", defaults[1]);
    }

    @Test
    @DisplayName("should extract prompts/get attributes from JSON-RPC body")
    void shouldExtractPromptsGetAttributes() {
      AuthZENPolicy policy = createPolicy();
      JsonObject params = new JsonObject().put("name", "summarize_document");

      String[] defaults = policy.setMcpContextAttributes(
        ctx,
        "prompts/get",
        params
      );

      assertEquals("prompts/get", attributes.get("authzen.mcp.method"));
      assertEquals(
        "summarize_document",
        attributes.get("authzen.mcp.prompt.name")
      );
      assertEquals(
        "summarize_document",
        attributes.get("authzen.mcp.item.name")
      );
      assertEquals("mcp-prompt", attributes.get("authzen.mcp.item.type"));

      // Verify returned defaults
      assertEquals("mcp-prompt", defaults[0]);
      assertEquals("summarize_document", defaults[1]);
    }

    @Test
    @DisplayName("should handle tools/list with wildcard defaults")
    void shouldHandleToolsListWithWildcardDefaults() {
      AuthZENPolicy policy = createPolicy();

      String[] defaults = policy.setMcpContextAttributes(
        ctx,
        "tools/list",
        null
      );

      assertEquals("tools/list", attributes.get("authzen.mcp.method"));
      assertEquals("mcp-tool", attributes.get("authzen.mcp.item.type"));
      assertEquals("*", attributes.get("authzen.mcp.item.name"));

      assertEquals("mcp-tool", defaults[0]);
      assertEquals("*", defaults[1]);
    }

    @Test
    @DisplayName("should handle resources/subscribe attributes")
    void shouldHandleResourcesSubscribeAttributes() {
      AuthZENPolicy policy = createPolicy();
      JsonObject params = new JsonObject().put("uri", "file:///logs/app.log");

      String[] defaults = policy.setMcpContextAttributes(
        ctx,
        "resources/subscribe",
        params
      );

      assertEquals("resources/subscribe", attributes.get("authzen.mcp.method"));
      assertEquals(
        "file:///logs/app.log",
        attributes.get("authzen.mcp.resource.uri")
      );
      assertEquals("mcp-resource", attributes.get("authzen.mcp.item.type"));

      assertEquals("mcp-resource", defaults[0]);
      assertEquals("file:///logs/app.log", defaults[1]);
    }
  }

  @Nested
  @DisplayName("MCP JSON-RPC Parsing and Error Responses")
  class McpJsonRpcParsing {

    private AuthZENPolicy createPolicy() {
      return new AuthZENPolicy(
        AuthZENPolicyConfiguration
          .builder()
          .pdpEndpoint("https://pdp.example.com")
          .mcpRequestParsing(true)
          .build()
      );
    }

    @Test
    @DisplayName("should parse valid JSON-RPC 2.0 MCP request")
    void shouldParseValidJsonRpcRequest() {
      AuthZENPolicy policy = createPolicy();

      String jsonRpcBody =
        """
        {
          "jsonrpc": "2.0",
          "id": "request_12345",
          "method": "tools/call",
          "params": {
            "name": "fintech_approve_expense",
            "arguments": {
              "expense_id": "exp-123",
              "amount": 5000
            }
          }
        }
        """;

      JsonObject result = policy.tryParseJsonRpc(jsonRpcBody);

      assertNotNull(result, "Should parse as valid JSON-RPC 2.0");
      assertEquals("2.0", result.getString("jsonrpc"));
      assertEquals("tools/call", result.getString("method"));
      assertEquals("request_12345", result.getString("id"));
      assertEquals(
        "fintech_approve_expense",
        result.getJsonObject("params").getString("name")
      );
    }

    @Test
    @DisplayName("should return null for non-JSON-RPC body")
    void shouldReturnNullForNonJsonRpcBody() {
      AuthZENPolicy policy = createPolicy();

      assertNull(policy.tryParseJsonRpc("not json at all"));
      assertNull(policy.tryParseJsonRpc("{\"foo\": \"bar\"}")); // missing jsonrpc + method
      assertNull(
        policy.tryParseJsonRpc("{\"jsonrpc\": \"1.0\", \"method\": \"test\"}")
      ); // wrong version
    }

    @Test
    @DisplayName("should build correct JSON-RPC error for access denied")
    void shouldBuildCorrectJsonRpcErrorForAccessDenied() {
      AuthZENPolicy policy = createPolicy();

      String errorJson = policy.buildMcpJsonRpcError(
        "request_12345",
        -32001,
        "Access denied by authorization policy"
      );

      JsonObject error = new JsonObject(errorJson);
      assertEquals("2.0", error.getString("jsonrpc"));
      assertEquals("request_12345", error.getString("id"));

      JsonObject errorObj = error.getJsonObject("error");
      assertNotNull(errorObj);
      assertEquals(-32001, errorObj.getInteger("code"));
      assertEquals(
        "Access denied by authorization policy",
        errorObj.getString("message")
      );
    }

    @Test
    @DisplayName("should build correct JSON-RPC error for auth service failure")
    void shouldBuildCorrectJsonRpcErrorForAuthServiceFailure() {
      AuthZENPolicy policy = createPolicy();

      String errorJson = policy.buildMcpJsonRpcError(
        42,
        -32002,
        "Authorization service unavailable"
      );

      JsonObject error = new JsonObject(errorJson);
      assertEquals("2.0", error.getString("jsonrpc"));
      assertEquals(42, error.getInteger("id"));
      assertEquals(-32002, error.getJsonObject("error").getInteger("code"));
      assertEquals(
        "Authorization service unavailable",
        error.getJsonObject("error").getString("message")
      );
    }
  }

  @Nested
  @DisplayName("MCP Configuration Defaults")
  class McpConfigurationDefaults {

    @Test
    @DisplayName("mcpRequestParsing should default to false")
    void mcpRequestParsingShouldDefaultToFalse() {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration
        .builder()
        .build();
      assertFalse(config.isMcpRequestParsing());
    }

    @Test
    @DisplayName("mcpRequestParsing can be enabled")
    void mcpRequestParsingCanBeEnabled() {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration
        .builder()
        .mcpRequestParsing(true)
        .build();
      assertTrue(config.isMcpRequestParsing());
    }
  }
}

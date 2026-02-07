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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.graviteesource.common.mcp.utils.GraviteeCommonMcpUtils;
import io.gravitee.el.TemplateEngine;
import io.gravitee.policy.authzen.configuration.AuthZENPolicyConfiguration;
import io.gravitee.policy.authzen.configuration.AuthZENProperty;
import io.modelcontextprotocol.spec.McpSchema;
import io.reactivex.rxjava3.core.Maybe;
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
 * Unit tests for the AuthZEN policy.
 */
@ExtendWith(MockitoExtension.class)
class AuthZENPolicyTest {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  @Mock
  private TemplateEngine templateEngine;

  @BeforeEach
  void setUp() {
    // Mock the async template engine to passthrough expressions (no EL evaluation)
    lenient()
      .when(templateEngine.eval(anyString(), eq(String.class)))
      .thenAnswer(invocation ->
        Maybe.just(invocation.getArgument(0, String.class))
      );
  }

  // ─── AuthZEN Request Body Building ──────────────────────────────────

  @Nested
  @DisplayName("Request Body Building")
  class RequestBodyBuilding {

    @Test
    @DisplayName("should build minimal AuthZEN request body")
    void shouldBuildMinimalRequestBody() throws Exception {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration.builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("user")
        .subjectId("alice@example.com")
        .resourceType("account")
        .resourceId("123")
        .actionName("can_read")
        .build();

      AuthZENPolicy policy = new AuthZENPolicy(config);
      String[] result = policy
        .buildAuthZENRequestAsync(templateEngine)
        .blockingGet();
      String body = result[0];

      JsonNode json = OBJECT_MAPPER.readTree(body);

      // Verify subject
      assertThat(json.path("subject").path("type").asText()).isEqualTo("user");
      assertThat(json.path("subject").path("id").asText()).isEqualTo(
        "alice@example.com"
      );
      assertThat(json.path("subject").has("properties")).isFalse();

      // Verify resource
      assertThat(json.path("resource").path("type").asText()).isEqualTo(
        "account"
      );
      assertThat(json.path("resource").path("id").asText()).isEqualTo("123");

      // Verify action
      assertThat(json.path("action").path("name").asText()).isEqualTo(
        "can_read"
      );

      // No context when no context entries are configured
      assertThat(json.has("context")).isFalse();
    }

    @Test
    @DisplayName("should include subject properties in request body")
    void shouldIncludeSubjectProperties() throws Exception {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration.builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("identity")
        .subjectId("user-001")
        .subjectProperties(
          List.of(
            AuthZENProperty.builder()
              .name("department")
              .value("Engineering")
              .build(),
            AuthZENProperty.builder()
              .name("ip_address")
              .value("192.168.1.1")
              .build()
          )
        )
        .resourceType("route")
        .resourceId("/api/data")
        .actionName("GET")
        .build();

      AuthZENPolicy policy = new AuthZENPolicy(config);
      String[] result = policy
        .buildAuthZENRequestAsync(templateEngine)
        .blockingGet();
      JsonNode json = OBJECT_MAPPER.readTree(result[0]);

      JsonNode subjectProps = json.path("subject").path("properties");
      assertThat(subjectProps.path("department").asText()).isEqualTo(
        "Engineering"
      );
      assertThat(subjectProps.path("ip_address").asText()).isEqualTo(
        "192.168.1.1"
      );
    }

    @Test
    @DisplayName("should include resource and action properties")
    void shouldIncludeResourceAndActionProperties() throws Exception {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration.builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("user")
        .subjectId("bob@example.com")
        .resourceType("document")
        .resourceId("doc-456")
        .resourceProperties(
          List.of(
            AuthZENProperty.builder()
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

      AuthZENPolicy policy = new AuthZENPolicy(config);
      String[] result = policy
        .buildAuthZENRequestAsync(templateEngine)
        .blockingGet();
      JsonNode json = OBJECT_MAPPER.readTree(result[0]);

      assertThat(
        json.path("resource").path("properties").path("classification").asText()
      ).isEqualTo("confidential");
      assertThat(
        json.path("action").path("properties").path("method").asText()
      ).isEqualTo("PUT");
    }

    @Test
    @DisplayName("should include context entries when configured")
    void shouldIncludeContextEntries() throws Exception {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration.builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("user")
        .subjectId("alice@example.com")
        .resourceType("api")
        .resourceId("/orders")
        .actionName("POST")
        .contextEntries(
          List.of(
            AuthZENProperty.builder()
              .name("time")
              .value("2024-10-26T01:22-07:00")
              .build(),
            AuthZENProperty.builder().name("location").value("US-East").build()
          )
        )
        .build();

      AuthZENPolicy policy = new AuthZENPolicy(config);
      String[] result = policy
        .buildAuthZENRequestAsync(templateEngine)
        .blockingGet();
      JsonNode json = OBJECT_MAPPER.readTree(result[0]);

      assertThat(json.path("context").path("time").asText()).isEqualTo(
        "2024-10-26T01:22-07:00"
      );
      assertThat(json.path("context").path("location").asText()).isEqualTo(
        "US-East"
      );
    }

    @Test
    @DisplayName("should produce valid AuthZEN API Gateway interop request")
    void shouldProduceValidApiGatewayInteropRequest() throws Exception {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration.builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("identity")
        .subjectId(
          "CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
        )
        .resourceType("route")
        .resourceId("/todos")
        .actionName("GET")
        .build();

      AuthZENPolicy policy = new AuthZENPolicy(config);
      String[] result = policy
        .buildAuthZENRequestAsync(templateEngine)
        .blockingGet();
      JsonNode json = OBJECT_MAPPER.readTree(result[0]);

      assertThat(json.path("subject").path("type").asText()).isEqualTo(
        "identity"
      );
      assertThat(json.path("subject").path("id").asText()).isEqualTo(
        "CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
      );
      assertThat(json.path("resource").path("type").asText()).isEqualTo(
        "route"
      );
      assertThat(json.path("resource").path("id").asText()).isEqualTo("/todos");
      assertThat(json.path("action").path("name").asText()).isEqualTo("GET");
    }
  }

  // ─── Configuration ──────────────────────────────────────────────────

  @Nested
  @DisplayName("Configuration")
  class Configuration {

    @Test
    @DisplayName("should use default values for configuration")
    void shouldUseDefaultValues() {
      AuthZENPolicyConfiguration config =
        AuthZENPolicyConfiguration.builder().build();

      assertThat(config.getSubjectType()).isEqualTo("user");
      assertThat(config.isDenyOnError()).isTrue();
      assertThat(config.getDenyStatusCode()).isEqualTo(403);
      assertThat(config.getDenyMessage()).isEqualTo(
        "Access denied by authorization policy"
      );
      assertThat(config.getErrorStatusCode()).isEqualTo(500);
      assertThat(config.getErrorMessage()).isEqualTo(
        "Authorization service unavailable"
      );
      assertThat(config.isUseSystemProxy()).isFalse();
      assertThat(config.getConnectTimeoutMs()).isEqualTo(5000);
      assertThat(config.isPreserveResponseContext()).isTrue();
      assertThat(config.getSubjectProperties()).isEmpty();
      assertThat(config.getResourceProperties()).isEmpty();
      assertThat(config.getActionProperties()).isEmpty();
      assertThat(config.getContextEntries()).isEmpty();
    }

    @Test
    @DisplayName("should allow overriding default values")
    void shouldAllowOverridingDefaults() {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration.builder()
        .subjectType("service")
        .denyOnError(false)
        .denyStatusCode(401)
        .denyMessage("Unauthorized")
        .errorStatusCode(503)
        .errorMessage("PDP unavailable")
        .connectTimeoutMs(10000)
        .preserveResponseContext(false)
        .build();

      assertThat(config.getSubjectType()).isEqualTo("service");
      assertThat(config.isDenyOnError()).isFalse();
      assertThat(config.getDenyStatusCode()).isEqualTo(401);
      assertThat(config.getDenyMessage()).isEqualTo("Unauthorized");
      assertThat(config.getErrorStatusCode()).isEqualTo(503);
      assertThat(config.getErrorMessage()).isEqualTo("PDP unavailable");
      assertThat(config.getConnectTimeoutMs()).isEqualTo(10000);
      assertThat(config.isPreserveResponseContext()).isFalse();
    }
  }

  // ─── Policy Identity ────────────────────────────────────────────────

  @Nested
  @DisplayName("Policy Identity")
  class PolicyIdentity {

    @Test
    @DisplayName("should return correct policy ID")
    void shouldReturnCorrectPolicyId() {
      AuthZENPolicy policy = new AuthZENPolicy(
        AuthZENPolicyConfiguration.builder()
          .pdpEndpoint("https://pdp.example.com")
          .build()
      );
      assertThat(policy.id()).isEqualTo("policy-authzen");
    }
  }

  // ─── MCP Auto-Mapping ───────────────────────────────────────────────

  @Nested
  @DisplayName("MCP Auto-Mapping (extractMcpAutoMapping)")
  class McpAutoMapping {

    private AuthZENPolicy createPolicy() {
      return new AuthZENPolicy(
        AuthZENPolicyConfiguration.builder()
          .pdpEndpoint("https://pdp.example.com")
          .build()
      );
    }

    private McpSchema.JSONRPCRequest parseMcpRequest(String jsonRpcBody) {
      return GraviteeCommonMcpUtils.parseMcpClientRequest(
        jsonRpcBody
      ).request();
    }

    @Test
    @DisplayName("should auto-map tools/call to tool name and mcp-tool type")
    void shouldAutoMapToolsCall() {
      AuthZENPolicy policy = createPolicy();
      McpSchema.JSONRPCRequest request = parseMcpRequest(
        """
        {
            "jsonrpc": "2.0",
            "id": "req_1",
            "method": "tools/call",
            "params": {
                "name": "getPetById",
                "arguments": {"petId": "1"}
            }
        }
        """
      );

      AuthZENPolicy.McpAutoMapping mapping = policy.extractMcpAutoMapping(
        request
      );

      assertThat(mapping.actionName()).isEqualTo("getPetById");
      assertThat(mapping.resourceType()).isEqualTo("mcp-tool");
      assertThat(mapping.resourceId()).isEqualTo("getPetById");
      assertThat(mapping.actionProperties()).isNotNull();
      assertThat(mapping.actionProperties().get("petId")).isEqualTo("1");
    }

    @Test
    @DisplayName(
      "should auto-map resources/read to mcp-resource type and resource URI"
    )
    void shouldAutoMapResourcesRead() {
      AuthZENPolicy policy = createPolicy();
      McpSchema.JSONRPCRequest request = parseMcpRequest(
        """
        {
            "jsonrpc": "2.0",
            "id": "req_2",
            "method": "resources/read",
            "params": {"uri": "file:///data/users.csv"}
        }
        """
      );

      AuthZENPolicy.McpAutoMapping mapping = policy.extractMcpAutoMapping(
        request
      );

      assertThat(mapping.actionName()).isEqualTo("resources/read");
      assertThat(mapping.resourceType()).isEqualTo("mcp-resource");
      assertThat(mapping.resourceId()).isEqualTo("file:///data/users.csv");
      assertThat(mapping.actionProperties()).isNull();
    }

    @Test
    @DisplayName(
      "should auto-map prompts/get to mcp-prompt type and prompt name"
    )
    void shouldAutoMapPromptsGet() {
      AuthZENPolicy policy = createPolicy();
      McpSchema.JSONRPCRequest request = parseMcpRequest(
        """
        {
            "jsonrpc": "2.0",
            "id": "req_3",
            "method": "prompts/get",
            "params": {"name": "summarize_document"}
        }
        """
      );

      AuthZENPolicy.McpAutoMapping mapping = policy.extractMcpAutoMapping(
        request
      );

      assertThat(mapping.actionName()).isEqualTo("prompts/get");
      assertThat(mapping.resourceType()).isEqualTo("mcp-prompt");
      assertThat(mapping.resourceId()).isEqualTo("summarize_document");
    }

    @Test
    @DisplayName("should handle tools/list with wildcard defaults")
    void shouldHandleToolsList() {
      AuthZENPolicy policy = createPolicy();
      McpSchema.JSONRPCRequest request = parseMcpRequest(
        """
        {"jsonrpc": "2.0", "id": "req_4", "method": "tools/list"}
        """
      );

      AuthZENPolicy.McpAutoMapping mapping = policy.extractMcpAutoMapping(
        request
      );

      assertThat(mapping.actionName()).isEqualTo("tools/list");
      assertThat(mapping.resourceType()).isEqualTo("mcp-tool");
      assertThat(mapping.resourceId()).isEqualTo("*");
    }

    @Test
    @DisplayName("should preserve native types in tool arguments")
    void shouldPreserveNativeTypesInToolArguments() {
      AuthZENPolicy policy = createPolicy();
      McpSchema.JSONRPCRequest request = parseMcpRequest(
        """
        {
            "jsonrpc": "2.0",
            "id": "req_5",
            "method": "tools/call",
            "params": {
                "name": "fintech_approve_expense",
                "arguments": {
                    "expense_id": "exp-123",
                    "amount": 5000,
                    "approved": true
                }
            }
        }
        """
      );

      AuthZENPolicy.McpAutoMapping mapping = policy.extractMcpAutoMapping(
        request
      );

      assertThat(mapping.actionProperties()).containsEntry(
        "expense_id",
        "exp-123"
      );
      assertThat(mapping.actionProperties()).containsEntry("amount", 5000);
      assertThat(mapping.actionProperties()).containsEntry("approved", true);
    }
  }

  // ─── MCP AuthZEN Request Alignment (Issue #2190) ────────────────────

  @Nested
  @DisplayName("MCP AuthZEN Alignment (Issue #2190)")
  class McpAuthZENAlignment {

    @Test
    @DisplayName(
      "should produce AuthZEN request matching issue #2190 for tools/call"
    )
    void shouldProduceAuthZENRequestMatchingIssue2190() throws Exception {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration.builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("user")
        .subjectId("embesozzi")
        .subjectProperties(
          List.of(
            AuthZENProperty.builder().name("roles").value("analyst").build(),
            AuthZENProperty.builder()
              .name("tenant")
              .value("finance-dept")
              .build(),
            AuthZENProperty.builder().name("acr").value("inherence").build(),
            AuthZENProperty.builder().name("amr").value("passkeys").build()
          )
        )
        .resourceId("mcp:expenses") // explicitly configured
        // resourceType, actionName left empty — auto-mapped from MCP
        .build();

      AuthZENPolicy policy = new AuthZENPolicy(config);

      // Simulate MCP auto-mapping defaults for tools/call "fintech_approve_expense"
      Map<String, Object> toolArguments = Map.of(
        "expense_id",
        "exp-123",
        "amount",
        5000
      );

      String[] result = policy
        .buildAuthZENRequestAsync(
          templateEngine,
          "fintech_approve_expense", // defaultActionName (tool name)
          "mcp-tool", // defaultResourceType
          "fintech_approve_expense", // defaultResourceId (overridden by config)
          toolArguments
        )
        .blockingGet();

      JsonNode json = OBJECT_MAPPER.readTree(result[0]);

      // Subject
      assertThat(json.path("subject").path("type").asText()).isEqualTo("user");
      assertThat(json.path("subject").path("id").asText()).isEqualTo(
        "embesozzi"
      );
      assertThat(
        json.path("subject").path("properties").path("roles").asText()
      ).isEqualTo("analyst");
      assertThat(
        json.path("subject").path("properties").path("tenant").asText()
      ).isEqualTo("finance-dept");
      assertThat(
        json.path("subject").path("properties").path("acr").asText()
      ).isEqualTo("inherence");
      assertThat(
        json.path("subject").path("properties").path("amr").asText()
      ).isEqualTo("passkeys");

      // Resource — resourceId is overridden by config "mcp:expenses"
      assertThat(json.path("resource").path("type").asText()).isEqualTo(
        "mcp-tool"
      );
      assertThat(json.path("resource").path("id").asText()).isEqualTo(
        "mcp:expenses"
      );

      // Action — name is auto-mapped tool name, properties are tool arguments
      assertThat(json.path("action").path("name").asText()).isEqualTo(
        "fintech_approve_expense"
      );
      assertThat(
        json.path("action").path("properties").path("expense_id").asText()
      ).isEqualTo("exp-123");
      assertThat(
        json.path("action").path("properties").path("amount").asInt()
      ).isEqualTo(5000);
    }

    @Test
    @DisplayName("should auto-map tools/call with zero-config")
    void shouldAutoMapToolsCallZeroConfig() throws Exception {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration.builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("user")
        .subjectId("alice@example.com")
        // resourceType, resourceId, actionName all empty — fully auto-mapped
        .build();

      AuthZENPolicy policy = new AuthZENPolicy(config);

      Map<String, Object> toolArgs = Map.of("petId", "1");

      String[] result = policy
        .buildAuthZENRequestAsync(
          templateEngine,
          "getPetById",
          "mcp-tool",
          "getPetById",
          toolArgs
        )
        .blockingGet();

      JsonNode json = OBJECT_MAPPER.readTree(result[0]);

      assertThat(json.path("subject").path("type").asText()).isEqualTo("user");
      assertThat(json.path("subject").path("id").asText()).isEqualTo(
        "alice@example.com"
      );
      assertThat(json.path("resource").path("type").asText()).isEqualTo(
        "mcp-tool"
      );
      assertThat(json.path("resource").path("id").asText()).isEqualTo(
        "getPetById"
      );
      assertThat(json.path("action").path("name").asText()).isEqualTo(
        "getPetById"
      );
      assertThat(
        json.path("action").path("properties").path("petId").asText()
      ).isEqualTo("1");
    }

    @Test
    @DisplayName(
      "should merge auto-extracted and user-configured action properties"
    )
    void shouldMergeActionProperties() throws Exception {
      AuthZENPolicyConfiguration config = AuthZENPolicyConfiguration.builder()
        .pdpEndpoint("https://pdp.example.com/access/v1/evaluation")
        .subjectType("user")
        .subjectId("test-user")
        .actionProperties(
          List.of(
            AuthZENProperty.builder()
              .name("custom_key")
              .value("custom_value")
              .build()
          )
        )
        .build();

      AuthZENPolicy policy = new AuthZENPolicy(config);

      Map<String, Object> toolArgs = Map.of(
        "expense_id",
        "exp-123",
        "amount",
        5000
      );

      String[] result = policy
        .buildAuthZENRequestAsync(
          templateEngine,
          "fintech_approve_expense",
          "mcp-tool",
          "tool-id",
          toolArgs
        )
        .blockingGet();

      JsonNode json = OBJECT_MAPPER.readTree(result[0]);

      // Auto-extracted tool args
      assertThat(
        json.path("action").path("properties").path("expense_id").asText()
      ).isEqualTo("exp-123");
      assertThat(
        json.path("action").path("properties").path("amount").asInt()
      ).isEqualTo(5000);
      // User-configured property (merged in, takes precedence on conflict)
      assertThat(
        json.path("action").path("properties").path("custom_key").asText()
      ).isEqualTo("custom_value");
    }
  }

  // ─── MCP Common Parser Integration ──────────────────────────────────

  @Nested
  @DisplayName("MCP Common Parser")
  class McpCommonParser {

    @Test
    @DisplayName("should parse valid MCP tools/call request")
    void shouldParseValidToolsCallRequest() {
      String jsonRpcBody = """
        {
            "jsonrpc": "2.0",
            "id": "request_12345",
            "method": "tools/call",
            "params": {
                "name": "getPetById",
                "arguments": {"petId": "1"}
            }
        }
        """;

      var parsed = GraviteeCommonMcpUtils.parseMcpClientRequest(jsonRpcBody);

      assertThat(parsed.request()).isNotNull();
      assertThat(parsed.request().method()).isEqualTo("tools/call");
      assertThat(parsed.request().id()).isEqualTo("request_12345");
    }

    @Test
    @DisplayName("should return error for invalid JSON-RPC body")
    void shouldReturnErrorForInvalidBody() {
      var parsed = GraviteeCommonMcpUtils.parseMcpClientRequest(
        "not json at all"
      );

      assertThat(parsed.request()).isNull();
      assertThat(parsed.error()).isNotNull();
    }

    @Test
    @DisplayName("should generate JSON-RPC error response")
    void shouldGenerateJsonRpcErrorResponse() throws Exception {
      String jsonRpcBody = """
        {"jsonrpc": "2.0", "id": "req_1", "method": "tools/call", "params": {"name": "test"}}
        """;
      var parsed = GraviteeCommonMcpUtils.parseMcpClientRequest(jsonRpcBody);
      McpSchema.JSONRPCRequest request = parsed.request();

      McpSchema.JSONRPCResponse errorResponse =
        GraviteeCommonMcpUtils.generateRcpResponseError(
          request,
          AuthZENPolicy.JSONRPC_ERROR_ACCESS_DENIED,
          new Exception("Access denied")
        );

      assertThat(errorResponse.jsonrpc()).isEqualTo("2.0");
      assertThat(errorResponse.id()).isEqualTo("req_1");
      assertThat(errorResponse.error()).isNotNull();
      assertThat(errorResponse.error().code()).isEqualTo(-32001);
      assertThat(errorResponse.error().message()).isEqualTo("Access denied");
    }
  }
}

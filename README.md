# Gravitee AuthZEN Access Evaluation Policy

A [Gravitee APIM](https://github.com/gravitee-io/gravitee-api-management) gateway policy that implements the [OpenID AuthZEN Authorization API 1.0](https://openid.github.io/authzen/) **Access Evaluation** endpoint for externalized authorization decisions.

## Overview

This policy acts as a **Policy Enforcement Point (PEP)** within the Gravitee API Gateway. During the **request phase**, it calls an external AuthZEN-compliant **Policy Decision Point (PDP)** to determine whether a request should be permitted or denied.

The policy supports both **HTTP Proxy APIs** and **MCP Proxy APIs** (via the [Gravitee MCP Proxy Reactor](https://github.com/gravitee-io/gravitee-reactor-mcp-proxy)).

The policy sends an Access Evaluation request to the PDP containing:
- **Subject** — who is making the request (e.g., user identity)
- **Resource** — what is being accessed (e.g., API route, document)
- **Action** — what operation is being performed (e.g., GET, POST, can_read)
- **Context** — environmental attributes (e.g., time, location)

The PDP responds with a `decision` (true/false), and the policy either allows the request to proceed or rejects it.

```
┌────────────┐     ┌───────────────────┐     ┌────────────┐
│   Client    │────>│  Gravitee Gateway │────>│  Backend   │
│             │     │  ┌──────────────┐ │     │  Service   │
│             │     │  │ AuthZEN      │ │     │            │
│             │     │  │ Policy (PEP) │ │     │            │
│             │     │  └──────┬───────┘ │     │            │
│             │     │         │         │     │            │
│             │     └─────────┼─────────┘     └────────────┘
│             │               │
│             │         ┌─────▼─────┐
│             │         │  AuthZEN  │
│             │         │ PDP       │
│             │         └───────────┘
└────────────┘
```

## Features

- **AuthZEN Authorization API 1.0** compliant Access Evaluation requests
- **Gravitee Expression Language (EL)** support in all configuration fields for dynamic runtime values
- **Custom metadata** — configurable subject, resource, action properties extracted via EL from request context
- **MCP Proxy API support** — parses JSON-RPC body to extract MCP method, tool names, resource URIs, and prompt names as context attributes for use in EL expressions
- **Configurable error handling** — fail-open or fail-closed when the PDP is unreachable
- **Response context preservation** — AuthZEN response context stored as gateway execution attributes
- **V4 API support** — reactive implementation using `HttpPolicy` interface with RxJava 3
- **V3 API backward compatibility** — legacy `@OnRequest` annotation support

## AuthZEN Request Format

The policy sends a `POST` request to the configured PDP endpoint with this JSON body:

```json
{
  "subject": {
    "type": "user",
    "id": "alice@example.com",
    "properties": {
      "department": "Engineering"
    }
  },
  "resource": {
    "type": "route",
    "id": "/api/orders",
    "properties": {
      "api_id": "my-api-v2"
    }
  },
  "action": {
    "name": "POST",
    "properties": {
      "method": "POST"
    }
  },
  "context": {
    "time": "2025-01-15T10:30:00Z",
    "gateway": "gravitee"
  }
}
```

The PDP responds with:

```json
{
  "decision": true,
  "context": {
    "reason": "User has editor role"
  }
}
```

## Configuration

### PDP Connection

| Property | Description | Required | Default | EL Support |
|----------|-------------|----------|---------|------------|
| `pdpEndpoint` | Full URL of the AuthZEN PDP access evaluation endpoint | Yes | — | No |
| `authorizationHeaderValue` | Authorization header value for PDP authentication | No | — | Yes |

### AuthZEN Subject

| Property | Description | Required | Default | EL Support |
|----------|-------------|----------|---------|------------|
| `subjectType` | Type of the subject (e.g., "user", "identity", "service") | No | `user` | Yes |
| `subjectId` | Unique identifier of the subject | Yes | — | Yes |
| `subjectProperties` | Additional key-value properties for the subject | No | `[]` | Values: Yes |

### AuthZEN Resource

| Property | Description | Required | Default | EL Support |
|----------|-------------|----------|---------|------------|
| `resourceType` | Type of the resource (e.g., "route", "api", "document") | No | — | Yes |
| `resourceId` | Unique identifier of the resource | No | — | Yes |
| `resourceProperties` | Additional key-value properties for the resource | No | `[]` | Values: Yes |

### AuthZEN Action

| Property | Description | Required | Default | EL Support |
|----------|-------------|----------|---------|------------|
| `actionName` | Name of the action (e.g., "GET", "can_read") | Yes | — | Yes |
| `actionProperties` | Additional key-value properties for the action | No | `[]` | Values: Yes |

### AuthZEN Context

| Property | Description | Required | Default | EL Support |
|----------|-------------|----------|---------|------------|
| `contextEntries` | Key-value pairs for the request context | No | `[]` | Values: Yes |

### Error Handling

| Property | Description | Default |
|----------|-------------|---------|
| `denyOnError` | Deny requests when PDP is unreachable (fail closed) | `true` |
| `denyStatusCode` | HTTP status code when access is denied (HTTP APIs) | `403` |
| `denyMessage` | Response message when access is denied | `Access denied by authorization policy` |
| `errorStatusCode` | HTTP status code when PDP call fails (HTTP APIs) | `500` |
| `errorMessage` | Response message when PDP call fails | `Authorization service unavailable` |

> **Note:** When `mcpRequestParsing` is enabled, deny and error responses are returned as JSON-RPC error messages (HTTP 200) rather than HTTP error status codes.

### HTTP Client

| Property | Description | Default |
|----------|-------------|---------|
| `useSystemProxy` | Use gateway's system proxy for PDP calls | `false` |
| `connectTimeoutMs` | Connection timeout in milliseconds | `5000` |
| `preserveResponseContext` | Store PDP response context as execution attributes | `true` |

## MCP Proxy API Support

This policy supports running on [Gravitee MCP Proxy APIs](https://github.com/gravitee-io/gravitee-reactor-mcp-proxy), enabling [OpenID AuthZEN-based fine-grained authorization for MCP](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2190).

When `mcpRequestParsing` is enabled, the policy:

1. **Reads the HTTP request body** as a JSON-RPC 2.0 message (MCP uses JSON-RPC over HTTP)
2. **Extracts MCP context** — method name, tool name, resource URI, prompt name — and sets them as execution context attributes
3. **Auto-maps MCP data to AuthZEN fields** — if `actionName`, `resourceType`, or `resourceId` are left empty, they are automatically populated from the MCP request (zero-config)
4. **Evaluates EL expressions** for any explicitly configured fields (which can also reference MCP attributes via `{#context.attributes['authzen.mcp.tool.name']}`)
5. **Sends the AuthZEN evaluation request** to the PDP
6. **On denial**, returns a proper **JSON-RPC error response** (HTTP 200 with error body) as required by the MCP protocol

### Zero-Config Auto-Mapping

When MCP request parsing is enabled, the following AuthZEN fields are **automatically derived** from the MCP request if left unconfigured:

| AuthZEN Field | Auto-Mapped From | Example (`tools/call` for "getPetById") |
|---------------|------------------|----------------------------------------|
| `actionName` | Tool name (for `tools/call`) or MCP method (for other methods) | `getPetById` |
| `resourceType` | Unified item type | `mcp-tool` |
| `resourceId` | Item name (tool name, resource URI, or prompt name) | `getPetById` |

This follows the [AuthZEN MCP profile convention](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2190) where, for `tools/call`, the AuthZEN **action name is the tool name** (the specific operation being authorized), not the MCP method. For other MCP methods (`resources/read`, `prompts/get`, etc.), the action name defaults to the MCP method name.

The user only needs to configure `pdpEndpoint` and `subjectId`. If explicit overrides are needed, any configured value (static or EL) takes precedence over the auto-mapped default.

### MCP Authorization Flow

```
┌───────────┐     ┌────────────────────────┐     ┌────────────┐
│ MCP Client│────>│  Gravitee MCP Gateway  │────>│ MCP Server │
│ (Host)    │     │  ┌──────────────────┐  │     │ (Backend)  │
│           │     │  │ AuthZEN Policy   │  │     │            │
│           │     │  │ (PEP)           │  │     │            │
│           │     │  └────────┬─────────┘  │     │            │
│           │     │           │            │     │            │
│           │     └───────────┼────────────┘     └────────────┘
│           │                 │
│           │           ┌─────▼─────┐
│           │           │  AuthZEN  │
│           │           │  PDP      │
│           │           └───────────┘
└───────────┘
```

### MCP Context Attributes

When `mcpRequestParsing` is enabled, the policy sets the following execution context attributes:

| Attribute | Description | Example | MCP Methods |
|-----------|-------------|---------|-------------|
| `authzen.mcp.method` | MCP JSON-RPC method name | `tools/call` | All |
| `authzen.mcp.tool.name` | Tool name | `fintech_approve_expense` | `tools/call` |
| `authzen.mcp.tool.arguments` | Tool call arguments (JSON string) | `{"expense_id":"exp-123"}` | `tools/call` |
| `authzen.mcp.resource.uri` | Resource URI | `/data/users` | `resources/read`, `resources/subscribe` |
| `authzen.mcp.prompt.name` | Prompt name | `summarize` | `prompts/get` |
| `authzen.mcp.item.type` | Unified AuthZEN resource type | `mcp-tool`, `mcp-resource`, `mcp-prompt` | All |
| `authzen.mcp.item.name` | Unified item name (tool name, resource URI, or prompt name) | `fintech_approve_expense` | All |

### MCP Configuration Example (Minimal — Zero-Config)

To use this policy on an MCP Proxy API, just enable MCP request parsing and configure the PDP endpoint and subject. The `actionName`, `resourceType`, and `resourceId` are automatically derived from the MCP request:

| Field | Value |
|-------|-------|
| PDP Endpoint | `https://pdp.example.com/access/v1/evaluation` |
| **Enable MCP Request Parsing** | `true` |
| Subject Type | `user` |
| Subject ID | `{#context.attributes['jwt.claims.sub']}` |
| Resource Type | *(leave empty — auto-mapped to `mcp-tool`, `mcp-resource`, or `mcp-prompt`)* |
| Resource ID | *(leave empty — auto-mapped to tool name, resource URI, or prompt name)* |
| Action Name | *(leave empty — auto-mapped to tool name for `tools/call`, or MCP method for others)* |

### MCP Configuration Example (Advanced — Custom Overrides)

If you need to customize the AuthZEN mapping, you can explicitly set fields using EL expressions that reference the MCP context attributes:

| Field | Value |
|-------|-------|
| PDP Endpoint | `https://pdp.example.com/access/v1/evaluation` |
| **Enable MCP Request Parsing** | `true` |
| Subject Type | `identity` |
| Subject ID | `{#context.attributes['jwt.claims.preferred_username']}` |
| Resource Type | `mcp` |
| Resource ID | `{#context.attributes['authzen.mcp.item.name']}` |
| Action Name | `{#context.attributes['authzen.mcp.tool.name']}` |

### MCP AuthZEN Request Example

Given an MCP `tools/call` request:

```json
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
```

And a JWT with `sub: "embesozzi"`, the policy builds this AuthZEN evaluation request (aligning with the [AuthZEN MCP profile](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2190)):

```json
{
  "subject": {
    "type": "user",
    "id": "embesozzi",
    "properties": {
      "roles": "analyst",
      "tenant": "finance-dept"
    }
  },
  "resource": {
    "type": "mcp-tool",
    "id": "mcp:expenses"
  },
  "action": {
    "name": "fintech_approve_expense",
    "properties": {
      "expense_id": "exp-123",
      "amount": "5000"
    }
  }
}
```

Note: `resource.id` is set to `"mcp:expenses"` via explicit configuration (the namespace/scope cannot be derived from the MCP request). The `action.name` is auto-mapped to the tool name `"fintech_approve_expense"` as proposed in the AuthZEN MCP profile.
```

### MCP Deny Response

When the PDP denies access on an MCP Proxy API, the policy returns a **JSON-RPC error** (HTTP 200):

```json
{
  "jsonrpc": "2.0",
  "id": "request_12345",
  "error": {
    "code": -32001,
    "message": "Access denied by authorization policy"
  }
}
```

This follows the MCP protocol convention of returning errors as JSON-RPC error responses rather than HTTP error status codes.

### MCP + HTTP Dual Deployment

The same policy can be deployed on both HTTP Proxy APIs and MCP Proxy APIs:

- **HTTP Proxy API**: Set `mcpRequestParsing` to `false` (default). The policy uses standard HTTP request attributes (path, method, headers) via EL.
- **MCP Proxy API**: Set `mcpRequestParsing` to `true`. The policy parses the JSON-RPC body and exposes MCP attributes via EL.

## Expression Language Examples

All value fields support [Gravitee Expression Language](https://documentation.gravitee.io/apim/gravitee-expression-language) for dynamic resolution:

```
# Subject ID from JWT claim
{#context.attributes['user']}

# Subject ID from request header
{#request.headers['X-User-Id'][0]}

# Resource as the request path
{#request.pathInfo}

# Action as the HTTP method
{#request.method}

# API identifier from context
{#properties['api.id']}

# Bearer token from context
Bearer {#context.attributes['oauth.access_token']}
```

### Example: API Gateway Scenario (AuthZEN Interop)

This configuration matches the [AuthZEN API Gateway interop scenario](https://authzen-interop.net/docs/scenarios/api-gateway):

| Field | Value |
|-------|-------|
| PDP Endpoint | `https://pdp.example.com/access/v1/evaluation` |
| Subject Type | `identity` |
| Subject ID | `{#context.attributes['jwt.claims.sub']}` |
| Resource Type | `route` |
| Resource ID | `{#request.pathInfo}` |
| Action Name | `{#request.method}` |

## Execution Attributes

After the policy executes, the following gateway execution attributes are set:

### Common Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `authzen.decision` | `Boolean` | The PDP's decision (`true` = allow, `false` = deny) |
| `authzen.response.context` | `String` (JSON) | The PDP's response context (if `preserveResponseContext` is enabled) |
| `authzen.error` | `String` | Error message if the PDP call failed |
| `authzen.decision.reason` | `String` | Set to `"fail-open"` when error occurs in fail-open mode |

### MCP Attributes (when `mcpRequestParsing` is enabled)

| Attribute | Type | Description |
|-----------|------|-------------|
| `authzen.mcp.method` | `String` | MCP JSON-RPC method (e.g., `tools/call`, `resources/read`) |
| `authzen.mcp.tool.name` | `String` | Tool name (for `tools/call`) |
| `authzen.mcp.tool.arguments` | `String` (JSON) | Tool call arguments (for `tools/call`) |
| `authzen.mcp.resource.uri` | `String` | Resource URI (for `resources/read`, `resources/subscribe`) |
| `authzen.mcp.prompt.name` | `String` | Prompt name (for `prompts/get`) |
| `authzen.mcp.item.type` | `String` | Unified type: `mcp-tool`, `mcp-resource`, or `mcp-prompt` |
| `authzen.mcp.item.name` | `String` | Unified name (tool name, resource URI, or prompt name; `*` for list operations) |

These attributes can be used by subsequent policies in the chain:

```
# Access the PDP decision in a downstream policy
{#context.attributes['authzen.decision']}

# Access the PDP response context
{#context.attributes['authzen.response.context']}

# Access MCP method in a downstream policy
{#context.attributes['authzen.mcp.method']}

# Access the MCP item name (tool/resource/prompt)
{#context.attributes['authzen.mcp.item.name']}
```

## Building

### Prerequisites

- Java 17+
- Maven 3.8+

### Build

```bash
mvn clean package
```

This produces a ZIP file in `target/gravitee-policy-authzen-1.0.0-SNAPSHOT.zip`.

### Dependency Versions

The `pom.xml` declares Gravitee dependency versions targeting **APIM 4.x**. If you need to target a different APIM version, adjust the version properties in the POM:

```xml
<properties>
    <gravitee-gateway-api.version>4.0.0</gravitee-gateway-api.version>
    <gravitee-policy-api.version>1.11.0</gravitee-policy-api.version>
    <!-- ... -->
</properties>
```

## Deployment

1. Build the policy ZIP: `mvn clean package`
2. Copy the ZIP to your Gravitee gateway plugins directory:
   ```bash
   cp target/gravitee-policy-authzen-*.zip ${GRAVITEE_HOME}/plugins/
   ```
3. Restart the Gravitee Gateway
4. The "AuthZEN Access Evaluation" policy will appear in the **Security** category of the Policy Studio

## Architecture

### V4 API (Recommended)

The `AuthZENPolicy` class implements `HttpPolicy` from the Gravitee v4 reactive API:

- **Reactive execution** — uses RxJava 3 `Completable` for non-blocking I/O
- **Async EL resolution** — all Expression Language expressions are evaluated asynchronously via `TemplateEngine.eval()`
- **Vert.x HTTP client** — uses the Vert.x `HttpClient` for non-blocking HTTP calls to the PDP
- **Lazy client initialization** — HTTP client is created once and reused across requests
- **MCP body parsing** — when enabled, uses `ctx.request().onBody()` to buffer and parse JSON-RPC requests, extracting MCP context attributes before AuthZEN evaluation

### V3 API (Legacy)

The `AuthZENPolicyV3` class provides backward compatibility for v2/v3 APIs:

- Uses `@OnRequest` annotation
- Synchronous EL resolution via `TemplateEngine.getValue()`
- Callback-based Vert.x HTTP client usage
- Creates a new HTTP client per request (no client reuse)

## References

- [AuthZEN Authorization API 1.0 Specification](https://openid.github.io/authzen/)
- [AuthZEN Interop - API Gateway Scenario](https://authzen-interop.net/docs/scenarios/api-gateway)
- [OpenID AuthZEN Integration for MCP Fine-Grained Authorization](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2190)
- [Gravitee MCP Proxy Reactor](https://github.com/gravitee-io/gravitee-reactor-mcp-proxy)
- [Gravitee MCP ACL Policy](https://github.com/gravitee-io/gravitee-policy-mcp-acl)
- [Gravitee APIM Documentation](https://documentation.gravitee.io/apim/)
- [Gravitee Expression Language](https://documentation.gravitee.io/apim/gravitee-expression-language)
- [Gravitee API Management Repository](https://github.com/gravitee-io/gravitee-api-management)

## License

Apache License 2.0

# Gravitee AuthZEN Access Evaluation Policy

A [Gravitee APIM](https://github.com/gravitee-io/gravitee-api-management) gateway policy that implements the [OpenID AuthZEN Authorization API 1.0](https://openid.github.io/authzen/) **Access Evaluation** endpoint for externalized authorization decisions.

## Overview

This policy acts as a **Policy Enforcement Point (PEP)** within the Gravitee API Gateway. During the **request phase**, it calls an external AuthZEN-compliant **Policy Decision Point (PDP)** to determine whether a request should be permitted or denied.

The policy supports both **HTTP Proxy APIs** and **MCP Proxy APIs** (via the [Gravitee MCP Proxy Reactor](https://github.com/gravitee-io/gravitee-reactor-mcp-proxy)). The API type is **automatically detected** at runtime — no manual configuration flag is needed.

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
- **Gravitee Expression Language (EL)** support in all configuration fields
- **Custom metadata** — configurable subject, resource, action properties extracted via EL
- **Automatic API type detection** — detects HTTP Proxy vs MCP Proxy at runtime
- **MCP Proxy API support** — uses the common MCP parser (`gravitee-common-mcp`) to extract tool names, resource URIs, prompt names, and tool arguments for zero-config AuthZEN auto-mapping
- **Configurable error handling** — fail-open or fail-closed when the PDP is unreachable
- **Response context preservation** — AuthZEN response context stored as gateway execution attributes
- **Jackson-based JSON processing** — uses Jackson ObjectMapper (consistent with the Gravitee ecosystem)
- **V4 reactive API** — `HttpPolicy` interface with RxJava 3

## AuthZEN Request Format

The policy sends a `POST` request to the configured PDP endpoint:

```json
{
  "subject": {
    "type": "user",
    "id": "alice@example.com",
    "properties": { "department": "Engineering" }
  },
  "resource": {
    "type": "route",
    "id": "/api/orders"
  },
  "action": {
    "name": "POST",
    "properties": { "method": "POST" }
  },
  "context": {
    "time": "2025-01-15T10:30:00Z"
  }
}
```

The PDP responds with:

```json
{
  "decision": true,
  "context": { "reason": "User has editor role" }
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
| `subjectType` | Type of the subject (e.g., "user", "identity") | No | `user` | Yes |
| `subjectId` | Unique identifier of the subject | Yes | — | Yes |
| `subjectProperties` | Additional key-value properties | No | `[]` | Values: Yes |

### AuthZEN Resource

| Property | Description | Required | Default | EL Support |
|----------|-------------|----------|---------|------------|
| `resourceType` | Type of the resource. Auto-mapped on MCP APIs when empty. | No | — | Yes |
| `resourceId` | Unique identifier of the resource. Auto-mapped on MCP APIs when empty. | No | — | Yes |
| `resourceProperties` | Additional key-value properties | No | `[]` | Values: Yes |

### AuthZEN Action

| Property | Description | Required | Default | EL Support |
|----------|-------------|----------|---------|------------|
| `actionName` | Name of the action. Auto-mapped on MCP APIs when empty. | No | — | Yes |
| `actionProperties` | Additional key-value properties | No | `[]` | Values: Yes |

### Error Handling

| Property | Description | Default |
|----------|-------------|---------|
| `denyOnError` | Deny requests when PDP is unreachable (fail closed) | `true` |
| `denyStatusCode` | HTTP status code when access is denied (HTTP APIs only) | `403` |
| `denyMessage` | Response message when access is denied | `Access denied by authorization policy` |
| `errorStatusCode` | HTTP status code when PDP call fails (HTTP APIs only) | `500` |
| `errorMessage` | Response message when PDP call fails | `Authorization service unavailable` |

> **Note:** On MCP Proxy APIs, deny and error responses are returned as JSON-RPC error messages (HTTP 200) rather than HTTP error status codes.

### HTTP Client

| Property | Description | Default |
|----------|-------------|---------|
| `useSystemProxy` | Use gateway's system proxy for PDP calls | `false` |
| `connectTimeoutMs` | Connection timeout in milliseconds | `5000` |
| `preserveResponseContext` | Store PDP response context as execution attributes | `true` |

## MCP Proxy API Support

This policy supports [Gravitee MCP Proxy APIs](https://github.com/gravitee-io/gravitee-reactor-mcp-proxy), enabling [OpenID AuthZEN-based fine-grained authorization for MCP](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2190).

### Automatic API Type Detection

The policy detects the API type by checking the internal `api.type` attribute set by the gateway reactor (`ApiType.MCP_PROXY`). No manual toggle is required — the same policy configuration works on both HTTP and MCP Proxy APIs.

### How It Works on MCP APIs

1. **Detects MCP API type** from the gateway execution context
2. **Parses the JSON-RPC body** using the common MCP parser (`gravitee-common-mcp`)
3. **Auto-maps MCP data to AuthZEN fields** — if `actionName`, `resourceType`, or `resourceId` are left empty, they are automatically populated from the MCP request
4. **Sends the AuthZEN evaluation request** to the PDP
5. **On denial**, returns a **JSON-RPC error response** (HTTP 200 with error body)

### Zero-Config Auto-Mapping

| AuthZEN Field | Auto-Mapped From | Example (`tools/call` for "getPetById") |
|---------------|------------------|----------------------------------------|
| `actionName` | Tool name (for `tools/call`) or MCP method | `getPetById` |
| `resourceType` | Unified item type | `mcp-tool` |
| `resourceId` | Item name (tool name, resource URI, or prompt name) | `getPetById` |
| `action.properties` | Tool arguments (for `tools/call`) | `{"petId": "1"}` |

This follows the [AuthZEN MCP profile](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2190) where, for `tools/call`, the AuthZEN **action name is the tool name** and **tool arguments are included as action properties**.

### MCP Configuration Example (Minimal)

| Field | Value |
|-------|-------|
| PDP Endpoint | `https://pdp.example.com/access/v1/evaluation` |
| Subject Type | `user` |
| Subject ID | `{#context.attributes['jwt.claims.sub']}` |

All other fields are auto-mapped from the MCP request.

### MCP AuthZEN Request Example

Given an MCP `tools/call` request for "fintech_approve_expense" with arguments `{"expense_id": "exp-123", "amount": 5000}`, the policy builds:

```json
{
  "subject": {
    "type": "user",
    "id": "embesozzi",
    "properties": { "roles": "analyst", "tenant": "finance-dept" }
  },
  "resource": {
    "type": "mcp-tool",
    "id": "fintech_approve_expense"
  },
  "action": {
    "name": "fintech_approve_expense",
    "properties": { "expense_id": "exp-123", "amount": 5000 }
  }
}
```

### MCP Deny Response

When the PDP denies access, the policy returns a JSON-RPC error (HTTP 200):

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

## Execution Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `authzen.decision` | `Boolean` | The PDP's decision (`true` = allow, `false` = deny) |
| `authzen.response.context` | `String` (JSON) | The PDP's response context (if `preserveResponseContext` is enabled) |
| `authzen.error` | `String` | Error message if the PDP call failed |
| `authzen.decision.reason` | `String` | Set to `"fail-open"` when error occurs in fail-open mode |

## Building

### Prerequisites

- Java 21+
- Maven 3.8+

### Build

```bash
mvn clean package
```

This produces a ZIP file in `target/gravitee-policy-authzen-1.0.0-SNAPSHOT.zip`.

### Dependencies

The `pom.xml` uses the `gravitee-apim-bom` for dependency management, targeting APIM 4.10+. Dependency versions are inherited from the BOM — no manual version pinning needed.

## Deployment

1. Build the policy ZIP: `mvn clean package`
2. Copy the ZIP to your Gravitee gateway plugins directory:
   ```bash
   cp target/gravitee-policy-authzen-*.zip ${GRAVITEE_HOME}/plugins/
   ```
3. Restart the Gravitee Gateway
4. The "AuthZEN Access Evaluation" policy will appear in the **Security** category

## Architecture

The `AuthZENPolicy` class implements `HttpPolicy` from the Gravitee v4 reactive API:

- **Reactive execution** — uses RxJava 3 `Completable` for non-blocking I/O
- **Async EL resolution** — all Expression Language expressions are evaluated asynchronously
- **Jackson JSON processing** — uses Jackson `ObjectMapper` for JSON serialization/deserialization
- **Common MCP parser** — uses `gravitee-common-mcp` (`GraviteeCommonMcpUtils`) for JSON-RPC parsing
- **API type auto-detection** — checks `InternalContextAttributes.ATTR_INTERNAL_API_TYPE` for MCP support
- **HTTP client from Node FWK** — creates HTTP clients using the Vert.x instance from the gateway's component context, with proxy configuration from the Node Configuration API

## Testing

- **Unit tests** — test AuthZEN request building, MCP auto-mapping, configuration defaults
- **Integration tests** — test full policy execution on both HTTP Proxy and MCP Proxy APIs using the Gravitee gateway tests SDK with WireMock

```bash
mvn test          # Unit tests only
mvn verify        # Unit + integration tests
```

## References

- [AuthZEN Authorization API 1.0 Specification](https://openid.github.io/authzen/)
- [AuthZEN Interop - API Gateway Scenario](https://authzen-interop.net/docs/scenarios/api-gateway)
- [OpenID AuthZEN Integration for MCP Fine-Grained Authorization](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2190)
- [Gravitee MCP Proxy Reactor](https://github.com/gravitee-io/gravitee-reactor-mcp-proxy)
- [Gravitee MCP ACL Policy](https://github.com/gravitee-io/gravitee-policy-mcp-acl)
- [Gravitee Common MCP](https://github.com/gravitee-io/gravitee-common-mcp)
- [Gravitee APIM Documentation](https://documentation.gravitee.io/apim/)

## License

Apache License 2.0

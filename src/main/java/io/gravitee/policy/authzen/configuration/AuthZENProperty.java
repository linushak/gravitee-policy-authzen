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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Represents a key-value property for AuthZEN request entities.
 * The value field supports Gravitee Expression Language (EL) for dynamic resolution.
 *
 * <p>Examples:
 * <ul>
 *   <li>name="department", value="Sales" (static value)</li>
 *   <li>name="ip_address", value="{#request.remoteAddress}" (EL expression)</li>
 *   <li>name="method", value="{#request.method}" (EL expression)</li>
 * </ul>
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthZENProperty {

  /**
   * The property name (key in the JSON object).
   */
  private String name;

  /**
   * The property value. Supports Gravitee Expression Language for dynamic resolution.
   */
  private String value;
}

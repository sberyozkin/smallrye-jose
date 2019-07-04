/*
 *   Copyright 2019 Red Hat, Inc, and individual contributors.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
package io.smallrye.jose;

import io.smallrye.jose.jwe.Jwe;
import io.smallrye.jose.jws.Jws;

/**
 * Supports the data integrity and encryption with JOSE Signature (RFC7515) and Encryption (RFC7516)
 * and JSON Web Algorithms (RFC7518).
 */
public interface Jose extends Jws, Jwe {
}
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
package io.smallrye.jose.jwe;

import io.smallrye.jose.JoseException;

/**
 * Decrypts the data encrypted with JOSE Encryption (RFC7516) and JSON Web Algorithms (RFC7518).
 */
public interface Decryptor {
    /**
     * Decrypt the encrypted data in the JWE compact format.
     * 
     * @param jwe the JWE sequence.
     * @return decrypted data
     * @throws JoseException
     */
    String decrypt(String jwe) throws JoseException;

    /**
     * Decrypt the encrypted data in the JWE compact format.
     * 
     * @param jwe the JWE sequence.
     * @return decrypted data and verified metadata
     * @throws JoseException
     */
    DecryptionOutput decryption(String jwe) throws JoseException;
}
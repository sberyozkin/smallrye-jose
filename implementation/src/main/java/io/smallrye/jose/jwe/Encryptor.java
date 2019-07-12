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
 * Supports the data encryption with JOSE Encryption (RFC7516) and JSON Web Algorithms (RFC7518).
 */
public interface Encryptor {
    /**
     * Encrypt the custom type in the JWE compact format.
     * 
     * @param typeInstance the typeInstance to be encrypted
     * @return the encrypted data
     * @throws JoseException
     * @see TypeConverter
     */
    default <T> String encrypt(T typeInstance) throws JoseException {
        return encrypt(new EncryptionInput<T>(typeInstance));
    }

    /**
     * Encrypt the custom type in the JWE compact format.
     * 
     * @param input the custom type to be encrypted and optional metadata to be integrity-protected
     * @return the encrypted data
     * @throws JoseException
     */
    <T> String encrypt(EncryptionInput<T> input) throws JoseException;
}
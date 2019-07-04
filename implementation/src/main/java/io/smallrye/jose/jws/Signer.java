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
package io.smallrye.jose.jws;

import io.smallrye.jose.JoseException;

/**
 * Signs the data using JOSE Signature (RFC7515) and JSON Web Algorithms (RFC7518).
 */
public interface Signer {
    /**
     * Sign the data in the JWS Compact format.
     * 
     * @param data the data to be signed
     * @return the signed data in the JWS Compact format
     * @throws JoseException
     */
    String sign(String data) throws JoseException;

    /**
     * Sign the data in the JWS Compact format.
     * 
     * @param input the data and optional JWS headers which have to be integrity-protected
     * @return the signed data in the JWS Compact format
     * @throws JoseException
     */
    String sign(SignatureInput input) throws JoseException;

}
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
 * Verifies the data signed using JOSE Signature (RFC7515) and JSON Web Algorithms (RFC7518).
 */
public interface Verifier {
    /**
     * Verify the signed data in the JWS compact format.
     * 
     * @param jws the JWS sequence.
     * @return verified data
     * @throws JoseException
     */
    String verify(String jws) throws JoseException;

    /**
     * Verify the signed data in the JWS compact format.
     * 
     * @param jws the JWS sequence.
     * @return verified data and metadata
     * @throws JoseException
     */
    VerificationOutput verification(String jws) throws JoseException;

    /**
     * Verify the signed and detached data in the JWS compact format.
     * 
     * @param jws the JWS sequence.
     * @param detachedData the signed and detached data.
     * @return verified data
     * @throws JoseException
     */
    String verifyDetached(String jws, String detachedData) throws JoseException;

    /**
     * Verify the signed and detached data in the JWS compact format.
     * 
     * @param jws the JWS sequence.
     * @param detachedData the signed and detached data.
     * @return verified data and metadata
     * @throws JoseException
     */
    VerificationOutput verificationDetached(String jws, String detachedData) throws JoseException;
}
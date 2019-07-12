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
    default String verify(String jws) throws JoseException {
        return verify(jws, String.class);
    }

    /**
     * Verify the signed data in the JWS compact format and convert it to the custom type.
     * 
     * @param jws the JWS sequence.
     * @param type the type the signed data will be converted to.
     * @return verified typed data.
     * @throws JoseException
     */
    default <T> T verify(String jws, Class<T> type) throws JoseException {
        return verification(jws, type).getData();
    }

    /**
     * Verify the signed data in the JWS compact format.
     * 
     * @param jws the JWS sequence.
     * @return verified string data and metadata
     * @throws JoseException
     */
    default VerificationOutput<String> verification(String jws) throws JoseException {
        return verification(jws, String.class);
    }

    /**
     * Verify the signed data in the JWS compact format, convert it to the custom type and return with the metadata.
     * 
     * @param jws the JWS sequence.
     * @return verified data converted to the custom type and metadata
     * @throws JoseException
     */
    <T> VerificationOutput<T> verification(String jws, Class<T> type) throws JoseException;

    /**
     * Verify the detached signed data in the JWS compact format.
     * 
     * @param jws the JWS sequence.
     * @param detachedData the detached signed data.
     * @return verified data
     * @throws JoseException
     */
    default String verifyDetached(String jws, String detachedData) throws JoseException {
        return verifyDetached(jws, detachedData, String.class);
    }

    /**
     * Verify the detached signed data in the JWS compact format and convert it to the custom type.
     * 
     * @param jws the JWS sequence.
     * @param detachedData the detached signed data.
     * @param type the type the signed detached data will be converted to.
     * @return verified data
     * @throws JoseException
     */
    default <T> T verifyDetached(String jws, String detachedData, Class<T> type) throws JoseException {
        return verificationDetached(jws, detachedData, type).getData();
    }

    /**
     * Verify the detached signed data in the JWS compact format.
     * 
     * @param jws the JWS sequence.
     * @param detachedData the detached signed data.
     * @return verified string data and metadata
     * @throws JoseException
     */
    default VerificationOutput<String> verificationDetached(String jws, String detachedData) throws JoseException {
        return verificationDetached(jws, detachedData, String.class);
    }

    /**
     * Verify the detached signed data in the JWS compact format, convert it to the custom type and return with the metadata.
     * 
     * @param jws the JWS sequence.
     * @param detachedData the detached signed data.
     * @param type the type the signed detached data will be converted to.
     * @return verified typed data and metadata
     * @throws JoseException
     */
    <T> VerificationOutput<T> verificationDetached(String jws, String detachedData, Class<T> type) throws JoseException;
}
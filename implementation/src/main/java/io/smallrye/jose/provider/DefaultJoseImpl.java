/**
 * Copyright 2015-2016 Red Hat, Inc, and individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.smallrye.jose.provider;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyStore;
import java.util.Map;
import java.util.stream.Collectors;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.HeaderParameterNames;

import io.smallrye.jose.Jose;
import io.smallrye.jose.JoseException;
import io.smallrye.jose.JoseOperation;
import io.smallrye.jose.TypeConverter;
import io.smallrye.jose.jwe.DecryptionOutput;
import io.smallrye.jose.jwe.EncryptionInput;
import io.smallrye.jose.jws.SignatureInput;
import io.smallrye.jose.jws.VerificationOutput;

public class DefaultJoseImpl implements Jose {
    private String JWK_KEYSTORE_INLINE = "inline";

    private JoseConfiguration config;
    private Map<Class<?>, TypeConverter> readableTypeConverters;
    private Map<Class<?>, TypeConverter> writeableTypeConverters;

    public DefaultJoseImpl(JoseConfiguration config,
            Map<Class<?>, TypeConverter> readableTypeConverters,
            Map<Class<?>, TypeConverter> writeableTypeConverters) {
        this.config = config;
        this.readableTypeConverters = readableTypeConverters;
        this.writeableTypeConverters = writeableTypeConverters;
    }

    @Override
    public <T> String sign(SignatureInput<T> input) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(convertToString(input.getData()));
        for (Map.Entry<String, Object> entry : input.getHeaders().entrySet()) {
            jws.getHeaders().setObjectHeaderValue(entry.getKey(), entry.getValue());
        }
        jws.setAlgorithmHeaderValue(config.getSignatureAlgorithm());
        if (!config.isSignatureDataEncoding()) {
            jws.getHeaders().setObjectHeaderValue(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);
            jws.setCriticalHeaderNames(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
        }
        if (config.isIncludeSignatureKeyAlias()) {
            jws.setKeyIdHeaderValue(signatureKeyAlias());
        }
        jws.setKey(getSignatureKey(jws, JoseOperation.SIGN));
        try {
            return config.isSignatureDataDetached()
                    ? jws.getDetachedContentCompactSerialization()
                    : jws.getCompactSerialization();
        } catch (org.jose4j.lang.JoseException ex) {
            throw new JoseException(ex.getMessage(), ex);
        }
    }

    @Override
    public <T> VerificationOutput<T> verification(String compactJws, Class<T> type) throws JoseException {
        return getVerificationOutput(compactJws, null, type);
    }

    @Override
    public <T> VerificationOutput<T> verificationDetached(String compactJws, String detachedData, Class<T> type)
            throws JoseException {
        return getVerificationOutput(compactJws, detachedData, type);
    }

    protected <T> VerificationOutput<T> getVerificationOutput(String compactJws, String detached, Class<T> type)
            throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST, config.getSignatureAlgorithm()));
        jws.setKey(getSignatureKey(jws, JoseOperation.VERIFICATION));
        try {
            jws.setCompactSerialization(compactJws);
            if (detached != null) {
                if (config.isSignatureDataEncoding()) {
                    jws.setEncodedPayload(new Base64Url().base64UrlEncodeUtf8ByteRepresentation(detached));
                } else {
                    jws.setPayload(detached);
                }
            }
        } catch (org.jose4j.lang.JoseException ex) {
            throw new JoseException(ex.getMessage(), ex);
        }
        try {
            int firstDot = compactJws.indexOf(".");
            String headersJson = new Base64Url().base64UrlDecodeToUtf8String(compactJws.substring(0, firstDot));
            VerificationOutput<T> vo = new VerificationOutput<T>(convertToType(jws.getPayload(), type),
                    JsonUtil.parseJson(headersJson));
            return vo;
        } catch (org.jose4j.lang.JoseException ex) {
            throw new JoseException(ex.getMessage(), ex);
        }
    }

    @Override
    public <T> String encrypt(EncryptionInput<T> input) {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPlaintext(convertToString(input.getData()));
        for (Map.Entry<String, Object> entry : input.getHeaders().entrySet()) {
            jwe.getHeaders().setObjectHeaderValue(entry.getKey(), entry.getValue());
        }
        jwe.setAlgorithmHeaderValue(config.getKeyEncryptionAlgorithm());
        jwe.setEncryptionMethodHeaderParameter(config.getContentEncryptionAlgorithm());
        if (config.isIncludeEncryptionKeyAlias()) {
            jwe.setKeyIdHeaderValue(encryptionKeyAlias());
        }
        jwe.setKey(getEncryptionKey(jwe, JoseOperation.ENCRYPTION));
        try {
            return jwe.getCompactSerialization();
        } catch (org.jose4j.lang.JoseException ex) {
            throw new JoseException(ex.getMessage(), ex);
        }
    }

    @Override
    public <T> DecryptionOutput<T> decryption(String compactJwe, Class<T> type) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        try {
            jwe.setCompactSerialization(compactJwe);
        } catch (org.jose4j.lang.JoseException ex) {
            throw new JoseException(ex.getMessage(), ex);
        }
        jwe.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST, config.getKeyEncryptionAlgorithm()));
        jwe.setContentEncryptionAlgorithmConstraints(
                new AlgorithmConstraints(ConstraintType.WHITELIST, config.getContentEncryptionAlgorithm()));
        jwe.setKey(getEncryptionKey(jwe, JoseOperation.DECRYPTION));
        try {
            int firstDot = compactJwe.indexOf(".");
            String headersJson = new Base64Url().base64UrlDecodeToUtf8String(compactJwe.substring(0, firstDot));
            return new DecryptionOutput<T>(convertToType(jwe.getPlaintextString(), type),
                    JsonUtil.parseJson(headersJson));
        } catch (org.jose4j.lang.JoseException ex) {
            throw new JoseException(ex.getMessage(), ex);
        }
    }

    private Key getSignatureKey(JsonWebSignature jws, JoseOperation operation) {
        if ("jwk".equals(this.config.getKeystoreType())) {
            return getJwkKey((operation.equals(JoseOperation.SIGN) ? signatureKeyAlias() : verificationKeyAlias(jws)),
                    config.getSignatureAlgorithm());

        } else if (operation.equals(JoseOperation.SIGN)) {
            return getJavaStorePrivateKey(signatureKeyAlias(), config.getSignatureKeyPassword());

        } else {
            return getJavaStorePublicKey(verificationKeyAlias(jws));
        }
    }

    private Key getEncryptionKey(JsonWebEncryption jwe, JoseOperation operation) {
        if ("jwk".equals(this.config.getKeystoreType())) {
            return getJwkKey((operation.equals(JoseOperation.ENCRYPTION) ? encryptionKeyAlias() : decryptionKeyAlias(jwe)),
                    config.getContentEncryptionAlgorithm());

        } else if (operation.equals(JoseOperation.ENCRYPTION)) {
            return getJavaStorePublicKey(encryptionKeyAlias());

        } else {
            return getJavaStorePrivateKey(decryptionKeyAlias(jwe), config.getEncryptionKeyPassword());
        }
    }

    private Key getJwkKey(String kid, String keyAlgorithm) {

        String jwkSetJson = null;
        if (JWK_KEYSTORE_INLINE.equals(config.getKeystoreLocation())
                && !config.getInlinedKeystoreJwkSet().isEmpty()) {
            jwkSetJson = config.getInlinedKeystoreJwkSet();
        } else {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            try (BufferedReader is = new BufferedReader(
                    new InputStreamReader(cl.getResourceAsStream(config.getKeystoreLocation())))) {
                jwkSetJson = is.lines().collect(Collectors.joining("\n"));
            } catch (IOException ex) {
                throw new JoseException("Keystore can not be loaded", ex);
            }
        }
        JsonWebKeySet jwkSet = null;
        try {
            jwkSet = new JsonWebKeySet(jwkSetJson);
        } catch (org.jose4j.lang.JoseException ex) {
            throw new JoseException(ex.getMessage(), ex);
        }
        JsonWebKey jwk = jwkSet.findJsonWebKey(kid, null, null, keyAlgorithm);
        if (jwk != null) {
            return jwk.getKey();
        } else {
            throw new JoseException("Key is not available");
        }
    }

    private Key getJavaStorePublicKey(String kid) {
        KeyStore keyStore = getJavaKeyStore();
        try {
            return keyStore.getCertificate(kid).getPublicKey();
        } catch (Exception ex) {
            throw new JoseException("Public Java Key Store key can not be loaded", ex);
        }
    }

    private Key getJavaStorePrivateKey(String kid, String keyPassword) {
        KeyStore keyStore = getJavaKeyStore();
        try {
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(kid,
                    new KeyStore.PasswordProtection(keyPassword.toCharArray()));
            return pkEntry.getPrivateKey();
        } catch (Exception ex) {
            throw new JoseException("Private Java Key Store key can not be loaded", ex);
        }
    }

    private KeyStore getJavaKeyStore() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        try (InputStream is = cl.getResourceAsStream(config.getKeystoreLocation())) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(is, config.getKeystorePassword().toCharArray());
            return ks;
        } catch (Exception ex) {
            throw new JoseException("Java Key Store can not be loaded", ex);
        }
    }

    private String encryptionKeyAlias() {
        if (config.getEncryptionKeyAliasOut().isEmpty()) {
            return config.getEncryptionKeyAlias();
        }
        return config.getEncryptionKeyAliasOut();
    }

    private String signatureKeyAlias() {
        if (config.getSignatureKeyAliasOut().isEmpty()) {
            return config.getSignatureKeyAlias();
        }
        return config.getSignatureKeyAliasOut();
    }

    private String verificationKeyAlias(JsonWebSignature jws) {

        if (config.isAcceptSignatureAlias()) {
            return jws.getKeyIdHeaderValue();
        }

        if (config.getSignatureKeyAliasIn().isEmpty()) {
            return config.getSignatureKeyAlias();
        }
        return config.getSignatureKeyAliasIn();
    }

    private String decryptionKeyAlias(JsonWebEncryption jwe) {

        if (config.isAcceptEncryptionAlias()) {
            return jwe.getKeyIdHeaderValue();
        }
        if (config.getEncryptionKeyAliasIn().isEmpty()) {
            return config.getEncryptionKeyAlias();
        }
        return config.getEncryptionKeyAliasIn();
    }

    private String convertToString(Object data) {
        TypeConverter tc = writeableTypeConverters.get(data.getClass());
        if (tc != null) {
            return tc.toString(data);
        } else {
            throw new JoseException("Unsupported type: " + data.getClass());
        }
    }

    private <T> T convertToType(String data, Class<T> type) {
        TypeConverter tc = readableTypeConverters.get(type);
        if (tc != null) {
            return tc.fromString(data, type);
        } else {
            throw new JoseException("Unsupported type: " + data.getClass());
        }
    }

}

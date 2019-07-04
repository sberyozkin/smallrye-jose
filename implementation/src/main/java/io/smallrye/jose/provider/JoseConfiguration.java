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
package io.smallrye.jose.provider;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class JoseConfiguration {
    /**
     * Keystore type
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.keystore.type", defaultValue = "jks")
    private String keystoreType;

    /**
     * Keystore location
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.keystore.location")
    private String keystoreLocation;

    /**
     * Keystore password.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.keystore.password", defaultValue = "password")
    private String keystorePassword;

    /**
     * Inlined JSON Web Key Set
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.keystore.jwkset", defaultValue = "")
    private String inlinedKeystoreJwkSet;

    /**
     * Signature algorithm.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.signature.algorithm", defaultValue = "RS256")
    private String signatureAlgorithm;

    /**
     * Signature Data Encoding mode.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.signature.data-encoding", defaultValue = "true")
    private boolean signatureDataEncoding;

    /**
     * Signature Detached Data.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.signature.data-detached", defaultValue = "false")
    private boolean signatureDataDetached;

    /**
     * Password for the signature key.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.signature.key.password", defaultValue = "password")
    private String signatureKeyPassword;

    /**
     * Alias to the signature key entry in the keystore.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.signature.key.alias", defaultValue = "")
    private String signatureKeyAlias;

    /**
     * Alias to the signature key entry in the keystore for signing.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.signature.out.key.alias", defaultValue = "")
    private String signatureKeyAliasOut;

    /**
     * Alias to the signature key entry in the keystore for verification.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.signature.in.key.alias", defaultValue = "")
    private String signatureKeyAliasIn;

    /**
     * Include Signature Key Alias as the JOSE 'kid' Header.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.signature.include.alias", defaultValue = "true")
    private boolean includeSignatureKeyAlias;

    /**
     * Key Encryption algorithm.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.encryption.keyAlgorithm", defaultValue = "RSA-OAEP")
    private String keyEncryptionAlgorithm;

    /**
     * Content Encryption algorithm.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.encryption.contentAlgorithm", defaultValue = "A128GCM")
    private String contentEncryptionAlgorithm;

    /**
     * Password for the encryption key.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.encryption.key.password", defaultValue = "password")
    private String encryptionKeyPassword;

    /**
     * Alias to the encryption key entry in the keystore.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.encryption.key.alias", defaultValue = "")
    private String encryptionKeyAlias;

    /**
     * Include Encryption Key Alias as the JOSE 'kid' Header.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.encryption.include.alias", defaultValue = "true")
    private boolean includeEncryptionKeyAlias;

    /**
     * Encryption Key Alias in the keystore to be used for the encryption.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.encryption.out.key.alias", defaultValue = "")
    private String encryptionKeyAliasOut;

    /**
     * Decryption Key Alias in the keystore to be used for the decryption.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.encryption.in.key.alias", defaultValue = "")
    private String encryptionKeyAliasIn;

    /**
     * Accept the encryption alias for decryption.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.encryption.accept.alias", defaultValue = "false")
    private boolean acceptEncryptionAlias;

    /**
     * Accept the signature alias for verification.
     */
    @Inject
    @ConfigProperty(name = "io.smallrye.jose.signature.accept.alias", defaultValue = "false")
    private boolean acceptSignatureAlias;

    public String getKeystoreType() {
        return keystoreType;
    }

    public String getKeystoreLocation() {
        return keystoreLocation;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public String getInlinedKeystoreJwkSet() {
        return inlinedKeystoreJwkSet;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public boolean isSignatureDataEncoding() {
        return signatureDataEncoding;
    }

    public boolean isSignatureDataDetached() {
        return signatureDataDetached;
    }

    public String getSignatureKeyPassword() {
        return signatureKeyPassword;
    }

    public String getSignatureKeyAlias() {
        return signatureKeyAlias;
    }

    public String getKeyEncryptionAlgorithm() {
        return keyEncryptionAlgorithm;
    }

    public String getContentEncryptionAlgorithm() {
        return contentEncryptionAlgorithm;
    }

    public String getEncryptionKeyPassword() {
        return encryptionKeyPassword;
    }

    public String getEncryptionKeyAlias() {
        return encryptionKeyAlias;
    }

    public boolean isIncludeEncryptionKeyAlias() {
        return includeEncryptionKeyAlias;
    }

    public boolean isIncludeSignatureKeyAlias() {
        return includeSignatureKeyAlias;
    }

    public String getEncryptionKeyAliasOut() {
        return encryptionKeyAliasOut;
    }

    public String getEncryptionKeyAliasIn() {
        return encryptionKeyAliasIn;
    }

    public String getSignatureKeyAliasOut() {
        return signatureKeyAliasOut;
    }

    public String getSignatureKeyAliasIn() {
        return signatureKeyAliasIn;
    }

    public boolean isAcceptEncryptionAlias() {
        return acceptEncryptionAlias;
    }

    public boolean isAcceptSignatureAlias() {
        return acceptSignatureAlias;
    }

}
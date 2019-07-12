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

import java.util.Collections;
import java.util.Map;

public class EncryptionInput<T> {
    private Map<String, Object> headers;
    private T data;

    public EncryptionInput(T data) {
        this(data, Collections.emptyMap());
    }

    public EncryptionInput(T data, Map<String, Object> headers) {
        this.headers = headers;
        this.data = data;
    }

    public Map<String, Object> getHeaders() {
        return headers;
    }

    public T getData() {
        return data;
    }
}

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

import java.util.Collections;
import java.util.Set;

import io.smallrye.jose.TypeConverter;

public class DefaultTypeConverter implements TypeConverter {

    @Override
    public Set<Class<?>> getWriteableTypes() {
        return Collections.singleton(String.class);
    }

    @Override
    public Set<Class<?>> getReadableTypes() {
        return Collections.singleton(String.class);
    }

    @Override
    public String toString(Object typeInstance) {
        return typeInstance.toString();
    }

    @Override
    public <T> T fromString(String data, Class<T> type) {
        @SuppressWarnings("unchecked")
        T typeInstance = (T) data;
        return typeInstance;
    }

}

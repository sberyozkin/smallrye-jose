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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

import io.smallrye.jose.Jose;
import io.smallrye.jose.TypeConverter;

@ApplicationScoped
public class JoseProvider {
    private Jose jose;
    @Inject
    private JoseConfiguration config;

    @Produces
    public Jose produceJose() {
        if (jose == null) {
            // Discover all the type converters
            Set<TypeConverter> typeConverters = Collections.singleton(new DefaultTypeConverter());
            jose = new DefaultJoseImpl(config,
                    getReadableTypeConverters(typeConverters),
                    getWriteableTypeConverters(typeConverters));
        }
        return jose;
    }

    private static Map<Class<?>, TypeConverter> getReadableTypeConverters(Set<TypeConverter> typeConverters) {
        Map<Class<?>, TypeConverter> map = new HashMap<>();
        for (TypeConverter tc : typeConverters) {
            for (Class<?> type : tc.getReadableTypes()) {
                map.put(type, tc);
            }
        }
        return map;
    }

    private static Map<Class<?>, TypeConverter> getWriteableTypeConverters(Set<TypeConverter> typeConverters) {
        Map<Class<?>, TypeConverter> map = new HashMap<>();
        for (TypeConverter tc : typeConverters) {
            for (Class<?> type : tc.getWriteableTypes()) {
                map.put(type, tc);
            }
        }
        return map;
    }

}
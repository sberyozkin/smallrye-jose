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
package io.smallrye.jose;

import java.util.Set;

/**
 * A custom type to/from String converter.
 * The string created after the custom type to string conversion will be signed or encrypted.
 * The string which will be used to create a custom type has been already verified or decrypted.
 */
public interface TypeConverter {

    /**
     * Return a set of the types supported by this type converter
     * 
     * @return a set of types
     */
    Set<Class<?>> getSupportedTypes();

    /**
     * Convert a type to string
     * 
     * @param typeInstance the type instance to be converted to string
     * @return the type string representation
     */
    String toString(Object typeInstance);

    /**
     * Convert a string to type
     * 
     * @param data the type string representation
     * @param type the expected type
     * @return the type instance
     */
    <T> T fromString(String data, Class<T> type);

}
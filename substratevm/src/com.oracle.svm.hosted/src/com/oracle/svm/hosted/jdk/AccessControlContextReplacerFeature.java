/*
 * Copyright (c) 2021, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package com.oracle.svm.hosted.jdk;

import com.oracle.svm.core.annotate.AutomaticFeature;
import com.oracle.svm.core.jdk.AccessControllerUtil;
import com.oracle.svm.core.util.VMError;
import com.oracle.svm.util.ReflectionUtil;
import org.graalvm.compiler.serviceprovider.JavaVersionUtil;
import org.graalvm.nativeimage.hosted.Feature;

import java.security.AccessControlContext;
import java.util.HashMap;
import java.util.Map;

@AutomaticFeature
@SuppressWarnings({"unused"})
class AccessControlContextReplacerFeature implements Feature {

    static Map<String, AccessControlContext> allowedContexts = new HashMap<>();

    static void allowContextIfExists(String className, String fieldName) {
        try {
            // Checkstyle: stop
            Class<?> clazz = Class.forName(className);
            // Checkstyle: resume
            String description = className + "." + fieldName;
            try {
                AccessControlContext acc = ReflectionUtil.readStaticField(clazz, fieldName);
                allowedContexts.put(description, acc);
            } catch (ReflectionUtil.ReflectionUtilError e) {
                throw VMError.shouldNotReachHere("Following field isn't present in JDK" + JavaVersionUtil.JAVA_SPEC + ": " + description);
            }

        } catch (ReflectiveOperationException e) {
            throw VMError.shouldNotReachHere("Following class isn't present in JDK" + JavaVersionUtil.JAVA_SPEC + ": " + className);
        }
    }

    @Override
    public void duringSetup(DuringSetupAccess access) {
        // Following AccessControlContexts are allowed in the image heap since they cannot leak
        // sensitive information.
        // They mostly originate from JDK's static final fields, and they do not feature
        // CodeSources, DomainCombiners etc.
        // New JDK versions can feature new or remove old contexts, so this method should be kept
        // up-to-date.
        allowContextIfExists("java.util.Calendar$CalendarAccessControlContext", "INSTANCE");
        allowContextIfExists("javax.management.monitor.Monitor", "noPermissionsACC");

        if (JavaVersionUtil.JAVA_SPEC < 9) {
            allowContextIfExists("sun.misc.InnocuousThread", "ACC");
        }
        if (JavaVersionUtil.JAVA_SPEC >= 9) {
            allowContextIfExists("java.security.AccessController$AccHolder", "innocuousAcc");
            allowContextIfExists("java.util.concurrent.ForkJoinPool$DefaultForkJoinWorkerThreadFactory", "ACC");
        }
        if (JavaVersionUtil.JAVA_SPEC < 17) {
            allowContextIfExists("java.util.concurrent.ForkJoinWorkerThread", "INNOCUOUS_ACC");
        }
        if (JavaVersionUtil.JAVA_SPEC >= 9 && JavaVersionUtil.JAVA_SPEC < 17) {
            allowContextIfExists("java.util.concurrent.ForkJoinPool$InnocuousForkJoinWorkerThreadFactory", "ACC");
        }
        if (JavaVersionUtil.JAVA_SPEC >= 17) {
            allowContextIfExists("java.util.concurrent.ForkJoinPool$WorkQueue", "INNOCUOUS_ACC");
            allowContextIfExists("java.util.concurrent.ForkJoinPool$DefaultCommonPoolForkJoinWorkerThreadFactory", "ACC");
        }
        access.registerObjectReplacer(AccessControlContextReplacerFeature::replaceAccessControlContext);
    }

    private static Object replaceAccessControlContext(Object obj) {
        if (obj instanceof AccessControlContext && obj != AccessControllerUtil.DISALLOWED_CONTEXT_MARKER) {
            if (allowedContexts.containsValue(obj)) {
                return obj;
            } else {
                return AccessControllerUtil.DISALLOWED_CONTEXT_MARKER;
            }
        }
        return obj;
    }
}

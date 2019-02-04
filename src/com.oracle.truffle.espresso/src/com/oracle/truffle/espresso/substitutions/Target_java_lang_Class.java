/*
 * Copyright (c) 2018, 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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

package com.oracle.truffle.espresso.substitutions;

import java.lang.reflect.Constructor;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.function.IntFunction;
import java.util.function.Predicate;

import com.oracle.truffle.espresso.EspressoLanguage;
import com.oracle.truffle.espresso.classfile.EnclosingMethodAttribute;
import com.oracle.truffle.espresso.descriptors.Types;
import com.oracle.truffle.espresso.impl.ByteString.Name;
import com.oracle.truffle.espresso.impl.ByteString.Type;
import com.oracle.truffle.espresso.impl.Field;
import com.oracle.truffle.espresso.impl.Klass;
import com.oracle.truffle.espresso.impl.Method;
import com.oracle.truffle.espresso.impl.ObjectKlass;
import com.oracle.truffle.espresso.meta.EspressoError;
import com.oracle.truffle.espresso.meta.JavaKind;
import com.oracle.truffle.espresso.meta.Meta;
import com.oracle.truffle.espresso.meta.MetaUtil;
import com.oracle.truffle.espresso.runtime.Attribute;
import com.oracle.truffle.espresso.runtime.EspressoContext;
import com.oracle.truffle.espresso.runtime.EspressoException;
import com.oracle.truffle.espresso.runtime.StaticObject;
import com.oracle.truffle.espresso.runtime.StaticObjectArray;
import com.oracle.truffle.espresso.runtime.StaticObjectClass;
import com.oracle.truffle.espresso.runtime.StaticObjectImpl;
import com.oracle.truffle.espresso.vm.InterpreterToVM;

@EspressoSubstitutions
public final class Target_java_lang_Class {

    public static final String HIDDEN_METHOD_KEY = "$$method_info";
    public static final String HIDDEN_FIELD_KEY = "$$field_info";

    @Substitution
    public static @Host(Class.class) StaticObject getPrimitiveClass(
                    @Host(String.class) StaticObject name) {

        String hostName = MetaUtil.toInternalName(Meta.toHostString(name));
        return EspressoLanguage.getCurrentContext().getRegistries().loadKlassWithBootClassLoader(Types.forPrimitive(JavaKind.fromTypeString(hostName))).mirror();
    }

    @Substitution(hasReceiver = true)
    public static boolean desiredAssertionStatus(@SuppressWarnings("unused") Object self) {
        return false;
    }

    @Substitution
    public static @Host(Class.class) StaticObject forName0(
                    @Host(String.class) StaticObject name,
                    boolean initialize,
                    @Host(ClassLoader.class) StaticObject loader,
                    @SuppressWarnings("unused") @Host(Class.class) StaticObject caller) {

        assert loader != null;

        EspressoContext context = EspressoLanguage.getCurrentContext();
        Meta meta = context.getMeta();

        String typeDesc = "L" + Meta.toHostString(name).replace('.', '/') + ";";
//        if (typeDesc.contains(".")) {
//            // Normalize
//            // Ljava/lang/InterruptedException;
//            // sun.nio.cs.UTF_8
//            typeDesc = .fromJavaName(typeDesc);
//        }

        Klass klass = meta.getRegistries().loadKlass(context.getTypes().make(Types.fromJavaString(typeDesc)), loader);

        if (klass == null) {
            // Klass classNotFoundExceptionKlass =
            // context.getMeta().throwableKlass(ClassNotFoundException.class);
            StaticObject instance = meta.ClassNotFoundException.allocateInstance();
            meta.ClassNotFoundException.lookupDeclaredMethod(Name.INIT, meta.getSignatures().makeRaw(Type._void)).invokeDirect(instance);
            // TODO(peterssen): Add class name to exception message.
            throw new EspressoException(instance);
        }

        if (initialize) {
            klass.safeInitialize();
        }
        return klass.mirror();
    }

    @Substitution(hasReceiver = true)
    public static @Host(String.class) StaticObject getName0(@Host(Class.class) StaticObjectClass self) {
        String name = self.getMirror().getType().toString();
        // Conversion from internal form.
        return EspressoLanguage.getCurrentContext().getMeta().toGuestString(MetaUtil.internalNameToJava(name, true, true));
    }

    @Substitution(hasReceiver = true)
    public static @Host(ClassLoader.class) StaticObject getClassLoader0(@Host(Class.class) StaticObjectClass self) {
        return self.getMirror().getDefiningClassLoader();
    }

    @Substitution(hasReceiver = true)
    public static @Host(java.lang.reflect.Field[].class) StaticObject getDeclaredFields0(@Host(Class.class) StaticObjectClass self, boolean publicOnly) {

        // TODO(peterssen): From Hostpot: 4496456 We need to filter out
        // java.lang.Throwable.backtrace.

        final Field[] fields = Arrays.stream(self.getMirror().getDeclaredFields()).filter(new Predicate<Field>() {
            @Override
            public boolean test(Field f) {
                return (!publicOnly || f.isPublic());
            }
        }).toArray(new IntFunction<Field[]>() {
            @Override
            public Field[] apply(int value) {
                return new Field[value];
            }
        });

        Meta meta = self.getKlass().getMeta();

        // TODO(peterssen): Cache guest j.l.reflect.Field constructor.
        // Calling the constructor is just for validation, manually setting the fields would be
        // faster.
        Method fieldInit = meta.Field.lookupDeclaredMethod(Name.INIT, meta.getSignatures().makeRaw(Type._void,
                        /* declaringClass */ Type.Class,
                        /* name */ Type.String,
                        /* type */ Type.Class,
                        /* modifiers */ Type._int,
                        /* slot */ Type._int,
                        /* signature */ Type.String,
                        /* annotations */ Type._byte_array));

        StaticObject fieldsArray = (StaticObject) meta.Field.allocateArray(fields.length, new IntFunction<StaticObject>() {
            @Override
            public StaticObject apply(int i) {
                final Field f = fields[i];
                StaticObjectImpl instance = (StaticObjectImpl) meta.Field.allocateInstance();
                fieldInit.invokeDirect(
                                /* this */ instance,
                                /* declaringKlass */ f.getHolder().mirror(),
                                /* name */ meta.getStrings().intern(f.getName()),
                                /* type */ f.resolveTypeKlass().mirror(),
                                /* modifiers */ f.getModifiers(),
                                /* slot */ f.getSlot(),
                                /* signature */ meta.toGuestString(f.getType()),
                                // FIXME(peterssen): Fill annotations bytes.
                                /* annotations */ StaticObject.NULL);
                instance.setHiddenField(HIDDEN_FIELD_KEY, f);
                return instance;
            }
        });

        return fieldsArray;
    }

    @Substitution(hasReceiver = true)
    public static @Host(Constructor[].class) StaticObject getDeclaredConstructors0(@Host(Class.class) StaticObjectClass self, boolean publicOnly) {
        final Method[] constructors = Arrays.stream(self.getMirror().getDeclaredConstructors()).filter(new Predicate<Method>() {
            @Override
            public boolean test(Method m) {
                return Name.INIT.equals(m.getName()) && (!publicOnly || m.isPublic());
            }
        }).toArray(new IntFunction<Method[]>() {
            @Override
            public Method[] apply(int value) {
                return new Method[value];
            }
        });

        Meta meta = self.getKlass().getMeta();

        // TODO(peterssen): Cache guest j.l.reflect.Constructor constructor.
        // Calling the constructor is just for validation, manually setting the fields would be
        // faster.
        Method constructorInit = meta.Constructor.lookupDeclaredMethod(Name.INIT, meta.getSignatures().makeRaw(Type._void,
                        /* declaringClass */ Type.Class,
                        /* parameterTypes */ Type.Class_array,
                        /* checkedExceptions */ Type.Class_array,
                        /* modifiers */ Type._int,
                        /* slot */ Type._int,
                        /* signature */ Type.String,
                        /* annotations */ Type._byte_array,
                        /* parameterAnnotations */ Type._byte_array));

        StaticObject arr = (StaticObject) meta.Constructor.allocateArray(constructors.length, new IntFunction<StaticObject>() {
            @Override
            public StaticObject apply(int i) {
                final Method m = constructors[i];

                final Klass[] rawParameterKlasses = m.resolveParameterKlasses();
                StaticObject parameterTypes = (StaticObject) meta.Class.allocateArray(
                                m.getParameterCount(),
                                new IntFunction<StaticObject>() {
                                    @Override
                                    public StaticObject apply(int j) {
                                        return rawParameterKlasses[j].mirror();
                                    }
                                });

                final Klass[] rawCheckedExceptions = m.getCheckedExceptions();
                StaticObjectArray checkedExceptions = (StaticObjectArray) meta.Class.allocateArray(rawCheckedExceptions.length, new IntFunction<StaticObject>() {
                    @Override
                    public StaticObject apply(int j) {
                        return rawCheckedExceptions[j].mirror();
                    }
                });

                StaticObjectImpl instance = (StaticObjectImpl) meta.Constructor.allocateInstance();
                constructorInit.invokeDirect(
                                /* this */ instance,
                                /* declaringKlass */ m.getDeclaringKlass().mirror(),
                                /* parameterTypes */ parameterTypes,
                                /* checkedExceptions */ checkedExceptions,
                                /* modifiers */ m.getModifiers(),
                                /* slot */ i, // TODO(peterssen): Fill method slot.
                                /* signature */ meta.toGuestString(m.getRawSignature().toString()),

                                // FIXME(peterssen): Fill annotations bytes.
                                /* annotations */ StaticObject.NULL,
                                /* parameterAnnotations */ StaticObject.NULL);

                instance.setHiddenField(HIDDEN_METHOD_KEY, m);

                return instance;
            }
        });

        return arr;
    }

    @Substitution(hasReceiver = true)
    public static @Host(java.lang.reflect.Method[].class) StaticObject getDeclaredMethods0(@Host(Class.class) StaticObjectClass self, boolean publicOnly) {
        final Method[] methods = Arrays.stream(self.getMirror().getDeclaredMethods()).filter(new Predicate<Method>() {
            @Override
            public boolean test(Method m) {
                return !publicOnly || m.isPublic();
            }
        }).toArray(
                        new IntFunction<Method[]>() {
                            @Override
                            public Method[] apply(int value) {
                                return new Method[value];
                            }
                        });

        EspressoContext context = EspressoLanguage.getCurrentContext();
        Meta meta = context.getMeta();

        // TODO(peterssen): Cache guest j.l.reflect.Method constructor.
        // Calling the constructor is just for validation, manually setting the fields would
        // be faster.
        Method methodInit = meta.Method.lookupDeclaredMethod(Name.INIT, meta.getSignatures().makeRaw(Type._void,
                        /* declaringClass */ Type.Class,
                        /* name */ Type.String,
                        /* parameterTypes */ Type.Class_array,
                        /* returnType */ Type.Class,
                        /* checkedExceptions */ Type.Class_array,
                        /* modifiers */ Type._int,
                        /* slot */ Type._int,
                        /* signature */ Type.String,
                        /* annotations */ Type._byte_array,
                        /* parameterAnnotations */ Type._byte_array,
                        /* annotationDefault */ Type._byte_array));

        StaticObject arr = (StaticObject) meta.Method.allocateArray(methods.length, new IntFunction<StaticObject>() {
            @Override
            public StaticObject apply(int i) {
                Method m = methods[i];

                final Klass[] rawParameterKlasses = m.resolveParameterKlasses();
                StaticObject parameterTypes = (StaticObject) meta.Class.allocateArray(
                                m.getParameterCount(),
                                new IntFunction<StaticObject>() {
                                    @Override
                                    public StaticObject apply(int j) {
                                        return rawParameterKlasses[j].mirror();
                                    }
                                });

                final Klass[] rawCheckedExceptions = m.getCheckedExceptions();
                StaticObjectArray checkedExceptions = (StaticObjectArray) meta.Class.allocateArray(rawCheckedExceptions.length, new IntFunction<StaticObject>() {
                    @Override
                    public StaticObject apply(int j) {
                        return rawCheckedExceptions[j].mirror();
                    }
                });

                Meta meta = self.getKlass().getMeta();

                StaticObjectImpl instance = (StaticObjectImpl) meta.Method.allocateInstance();
                methodInit.invokeDirect(
                                /* this */ instance,
                                /* declaringClass */ m.getDeclaringKlass().mirror(),
                                /* name */ meta.getStrings().intern(m.getName()),
                                /* parameterTypes */ parameterTypes,
                                /* returnType */ m.resolveReturnKlass().mirror(),
                                /* checkedExceptions */ checkedExceptions,
                                /* modifiers */ m.getModifiers(),
                                /* slot */ i, // TODO(peterssen): Fill method slot.
                                /* signature */ meta.toGuestString(m.getRawSignature().toString()),

                                // FIXME(peterssen): Fill annotations bytes.
                                /* annotations */ StaticObject.NULL,
                                /* parameterAnnotations */ StaticObject.NULL,
                                /* annotationDefault */ StaticObject.NULL);

                instance.setHiddenField(HIDDEN_METHOD_KEY, m);

                return instance;
            }
        });

        return arr;
    }

    @Substitution(hasReceiver = true)
    public static @Host(Class[].class) StaticObject getInterfaces0(StaticObjectClass self) {
        final Klass[] superInterfaces = self.getMirror().getInterfaces();

        Meta meta = self.getKlass().getMeta();
        StaticObject instance = (StaticObject) meta.Class.allocateArray(superInterfaces.length, new IntFunction<StaticObject>() {
            @Override
            public StaticObject apply(int i) {
                return superInterfaces[i].mirror();
            }
        });

        return instance;
    }

    @Substitution(hasReceiver = true)
    public static boolean isPrimitive(@Host(Class.class) StaticObjectClass self) {
        return self.getMirror().isPrimitive();
    }

    @Substitution(hasReceiver = true)
    public static boolean isInterface(@Host(Class.class) StaticObjectClass self) {
        return self.getMirror().isInterface();
    }

    @Substitution(hasReceiver = true)
    public static int getModifiers(@Host(Class.class) StaticObjectClass self) {
        return self.getMirror().getModifiers();
    }

    @Substitution(hasReceiver = true)
    public static @Host(Class.class) StaticObject getSuperclass(@Host(Class.class) StaticObjectClass self) {
        if (self.getMirror().isInterface()) {
            return StaticObject.NULL;
        }
        Klass superclass = self.getMirror().getSuperclass();
        if (superclass == null) {
            return StaticObject.NULL;
        }
        return superclass.mirror();
    }

    @Substitution(hasReceiver = true)
    public static boolean isArray(@Host(Class.class) StaticObjectClass self) {
        return self.getMirror().isArray();
    }

    @Substitution(hasReceiver = true)
    public static @Host(Class.class) StaticObject getComponentType(@Host(Class.class) StaticObjectClass self) {
        Klass comp = self.getMirror().getComponentType();
        if (comp == null) {
            return StaticObject.NULL;
        }
        return comp.mirror();
    }

    @Substitution(hasReceiver = true)
    public static @Host(Object[].class) StaticObject getEnclosingMethod0(StaticObjectClass self) {
        throw EspressoError.unimplemented();
//        Meta meta = EspressoLanguage.getCurrentContext().getMeta();
//        InterpreterToVM vm = EspressoLanguage.getCurrentContext().getInterpreterToVM();
//        if (self.getMirror() instanceof ObjectKlass) {
//            EnclosingMethodAttribute enclosingMethodAttr = ((ObjectKlass) self.getMirror()).getEnclosingMethod();
//            if (enclosingMethodAttr == null) {
//                return StaticObject.NULL;
//            }
//            StaticObjectArray arr = (StaticObjectArray) meta.Object.allocateArray(3);
//
//            Klass enclosingKlass = self.getMirror().getConstantPool().classAt(enclosingMethodAttr.getClassIndex()).resolve(self.getMirror().getConstantPool(), enclosingMethodAttr.getClassIndex());
//
//            vm.setArrayObject(enclosingKlass.mirror(), 0, arr);
//
//            if (enclosingMethodAttr.getMethodIndex() != 0) {
//
//                Method enclosingMethod = self.getMirror().getConstantPool().methodAt(enclosingMethodAttr.getMethodIndex()).resolve(self.getMirror().getConstantPool(),
//                                enclosingMethodAttr.getMethodIndex());
//
//                vm.setArrayObject(meta.toGuestString(enclosingMethod.getName().toString()), 1, arr);
//                vm.setArrayObject(meta.toGuestString(enclosingMethod.getRawSignature().toString()), 2, arr);
//            } else {
//                assert vm.getArrayObject(1, arr) == StaticObject.NULL;
//                assert vm.getArrayObject(2, arr) == StaticObject.NULL;
//            }
//        }
//        return StaticObject.NULL;
    }

    @Substitution(hasReceiver = true)
    public static @Host(Class.class) StaticObject getDeclaringClass0(StaticObjectClass self) {
        // Primitives and arrays are not "enclosed".
        if (!(self.getMirror() instanceof ObjectKlass)) {
            return StaticObject.NULL;
        }
        ObjectKlass k = (ObjectKlass) self.getMirror();
        Klass outerKlass = computeEnclosingClass(k);
        if (outerKlass == null) {
            return StaticObject.NULL;
        }
        return outerKlass.mirror();
    }

    /**
     * Return the enclosing class; or null for: primitives, arrays, anonymous classes (declared
     * inside methods).
     */
    private static Klass computeEnclosingClass(ObjectKlass klass) {
        throw EspressoError.unimplemented();

//        InnerClassesAttribute innerClasses = klass.getInnerClasses();
//        if (innerClasses == null) {
//            return null;
//        }
//
//        ConstantPool pool = klass.getConstantPool();
//
//        boolean found = false;
//        Klass outerKlass = null;
//
//        for (InnerClassesAttribute.Entry entry : innerClasses.entries()) {
//            if (entry.innerClassIndex != 0) {
//                ClassConstant innerClassConst = pool.classAt(entry.innerClassIndex);
//                ByteString<Type> innersDecriptor = innerClassConst.getType(pool);
//
//                // Check decriptors/names before resolving.
//                if (innersDecriptor.equals(klass.getType())) {
//                    Klass innerKlass = innerClassConst.resolve(pool, entry.innerClassIndex);
//                    found = (innerKlass == klass);
//                    if (found && entry.outerClassIndex != 0) {
//                        outerKlass = pool.classAt(entry.outerClassIndex).resolve(pool, entry.outerClassIndex);
//                    }
//                }
//            }
//            if (found)
//                break;
//        }
//
//        // TODO(peterssen): Follow HotSpot implementation described below.
//        // Throws an exception if outer klass has not declared k as an inner klass
//        // We need evidence that each klass knows about the other, or else
//        // the system could allow a spoof of an inner class to gain access rights.
//        return outerKlass;
    }

    /**
     * Determines if the specified {@code Object} is assignment-compatible with the object
     * represented by this {@code Class}. This method is the dynamic equivalent of the Java language
     * {@code instanceof} operator. The method returns {@code true} if the specified {@code Object}
     * argument is non-null and can be cast to the reference type represented by this {@code Class}
     * object without raising a {@code ClassCastException.} It returns {@code false} otherwise.
     *
     * <p>
     * Specifically, if this {@code Class} object represents a declared class, this method returns
     * {@code true} if the specified {@code Object} argument is an instance of the represented class
     * (or of any of its subclasses); it returns {@code false} otherwise. If this {@code Class}
     * object represents an array class, this method returns {@code true} if the specified
     * {@code Object} argument can be converted to an object of the array class by an identity
     * conversion or by a widening reference conversion; it returns {@code false} otherwise. If this
     * {@code Class} object represents an interface, this method returns {@code true} if the class
     * or any superclass of the specified {@code Object} argument implements this interface; it
     * returns {@code false} otherwise. If this {@code Class} object represents a primitive type,
     * this method returns {@code false}.
     *
     * @param obj the object to check
     * @return true if {@code obj} is an instance of this class
     *
     * @since JDK1.1
     */
    @Substitution(hasReceiver = true)
    public static boolean isInstance(StaticObjectClass self, StaticObject obj) {
        return EspressoLanguage.getCurrentContext().getInterpreterToVM().instanceOf(obj, self.getMirror());
    }

    @Substitution
    public static void registerNatives() {
        /* nop */
    }

    @Substitution(hasReceiver = true)
    public static @Host(ProtectionDomain.class) StaticObject getProtectionDomain0(@SuppressWarnings("unused") StaticObject self) {
        return StaticObject.NULL;
    }

    @Substitution(hasReceiver = true)
    public static @Host(byte[].class) StaticObject getRawAnnotations(StaticObjectClass self) {
        Klass klass = self.getMirror();
        if (klass instanceof ObjectKlass) {
            Attribute annotations = ((ObjectKlass) klass).getRuntimeVisibleAnnotations();
            if (annotations != null) {
                return StaticObjectArray.wrap(annotations.getData());
            }
        }
        return StaticObject.NULL;
    }

    @Substitution(hasReceiver = true)
    public static @Host(sun.reflect.ConstantPool.class) StaticObject getConstantPool(@Host(Class.class) StaticObject self) {
        Klass klass = ((StaticObjectClass) self).getMirror();
        if (klass instanceof ObjectKlass) {
            Klass cpKlass = klass.getMeta().knownKlass(sun.reflect.ConstantPool.class);
            Field constantPoolOop = cpKlass.lookupDeclaredField(Name.constantPoolOop, Type.Object);
            StaticObject cp = cpKlass.allocateInstance();
            constantPoolOop.set(cp, self);
            return cp;
        }
        // No constant pool for arrays and primitives.
        return StaticObject.NULL;
    }
}

package com.zscope.runtime;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

public class RuntimeEntry {
    public Object reflect(String className, String methodName) throws Exception {
        Class<?> clazz = Class.forName(className);
        Method method = clazz.getMethod(methodName);
        return method.invoke(null);
    }

    public Class<?> loadPlugin(URL[] urls, String className) throws Exception {
        URLClassLoader loader = new URLClassLoader(urls);
        return loader.loadClass(className);
    }

    public InputStream resource(String name) {
        return getClass().getResourceAsStream(name);
    }
}

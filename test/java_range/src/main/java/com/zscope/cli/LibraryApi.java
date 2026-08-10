package com.zscope.cli;

public class LibraryApi {
    private final Loader loader;

    public LibraryApi(Loader loader) {
        this.loader = loader;
    }

    public String load(String path) throws Exception {
        return loader.read(path);
    }
}

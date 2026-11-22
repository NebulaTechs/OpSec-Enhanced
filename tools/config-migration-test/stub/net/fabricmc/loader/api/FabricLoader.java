package net.fabricmc.loader.api;

import java.nio.file.Path;

/** Stand-in for the loader: the config model only asks where the config directory is. */
public final class FabricLoader {

    private static FabricLoader instance;

    private final Path configDir;

    private FabricLoader(Path configDir) {
        this.configDir = configDir;
    }

    public static FabricLoader getInstance() {
        if (instance == null) {
            instance = new FabricLoader(Path.of(System.getProperty("opsec.test.configDir", "/tmp/opencode/harness/config")));
        }
        return instance;
    }

    public Path getConfigDir() {
        return configDir;
    }

    public boolean isModLoaded(String id) {
        return false;
    }
}

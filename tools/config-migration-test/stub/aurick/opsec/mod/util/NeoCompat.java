package aurick.opsec.mod.util;

import java.nio.file.Path;

/** Stand-in for the loader-specific helpers: the config model only asks where the config lives. */
public final class NeoCompat {

    private NeoCompat() {
    }

    public static Path getConfigDir() {
        return Path.of(System.getProperty("opsec.test.configDir", "/tmp/opencode/harness/config"));
    }

    public static boolean isModLoaded(String id) {
        return false;
    }
}

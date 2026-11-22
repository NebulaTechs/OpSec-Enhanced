package aurick.opsec.mod.tracking;

/** Stand-in for the mod-dependency registry: the config model only asks it to rebuild. */
public final class ModRegistry {

    private ModRegistry() {
    }

    public static void rebuildDependencyClosure() {
    }
}

package aurick.opsec.mod.config;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Feeds the config loader shapes it should never see and checks that none of them
 * take the client down.
 *
 * <p>The loader runs from the config constructor, so anything it lets escape is a
 * crash on client start — with the user's settings still on disk, still unreadable.
 * A malformed file must degrade to the defaults, never to a stack trace.</p>
 */
public final class HostileInputHarness {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws IOException {
        Path configDir = Path.of(System.getProperty("opsec.test.configDir", "/tmp/opencode/harness/config"));
        Files.createDirectories(configDir);
        Path configFile = configDir.resolve("opsec.json");

        OpsecConfig config = OpsecConfig.getInstance();

        // The version is read as a number before anything else is validated.
        survives(config, configFile, "a version that is not a number",
                "{\"version\": \"abc\"}");
        survives(config, configFile, "a version that is an object",
                "{\"version\": {}}");
        survives(config, configFile, "a version that is an array",
                "{\"version\": []}");
        survives(config, configFile, "a version that is a boolean",
                "{\"version\": true}");
        survives(config, configFile, "a null version",
                "{\"version\": null}");

        // The global settings block is read outside the per-rule guard.
        survives(config, configFile, "a settings block that is an array",
                "{\"version\": 3, \"settings\": []}");
        survives(config, configFile, "a settings block with a non-boolean toggle",
                "{\"version\": 3, \"settings\": {\"spoofAsVanilla\": {}}}");
        survives(config, configFile, "a settings block with a non-string HUD text",
                "{\"version\": 3, \"settings\": {\"hudText\": {}}}");
        survives(config, configFile, "a settings block with a non-array brand history",
                "{\"version\": 3, \"settings\": {\"lunarBrandHistory\": {}}}");
        survives(config, configFile, "a settings block with a non-object accent colour",
                "{\"version\": 3, \"settings\": {\"accentColor\": {}}}");
        survives(config, configFile, "a settings block with a non-boolean HUD switch",
                "{\"version\": 3, \"settings\": {\"showHudIndicator\": {}}}");

        // The rule list.
        survives(config, configFile, "a rule list that is an object",
                "{\"version\": 3, \"serverRules\": {}}");
        survives(config, configFile, "a rule list of strings",
                "{\"version\": 3, \"serverRules\": [\"nope\"]}");
        survives(config, configFile, "a rule with a non-object settings block",
                "{\"version\": 3, \"serverRules\": [{\"matchType\": \"EXACT\", \"pattern\": \"a\", \"settings\": []}]}");
        survives(config, configFile, "a rule with a non-string match type",
                "{\"version\": 3, \"serverRules\": [{\"matchType\": {}, \"pattern\": \"a\"}]}");
        survives(config, configFile, "a rule with a non-string pattern",
                "{\"version\": 3, \"serverRules\": [{\"matchType\": \"EXACT\", \"pattern\": {}}]}");
        survives(config, configFile, "a rule with a non-boolean enabled flag",
                "{\"version\": 3, \"serverRules\": [{\"matchType\": \"EXACT\", \"pattern\": \"a\", \"enabled\": {}}]}");

        // The legacy profile map.
        survives(config, configFile, "a profile map that is an array",
                "{\"version\": 1, \"serverProfiles\": []}");
        survives(config, configFile, "a profile map with an array value",
                "{\"version\": 1, \"serverProfiles\": {\"a.example.com\": []}}");

        // The trusted-server list.
        survives(config, configFile, "a trusted-server list that is an object",
                "{\"version\": 3, \"packCacheTrustedServers\": {}}");
        survives(config, configFile, "a trusted-server list with an object in it",
                "{\"version\": 3, \"packCacheTrustedServers\": [{}]}");
        survives(config, configFile, "a trusted-server list with a null in it",
                "{\"version\": 3, \"packCacheTrustedServers\": [null]}");

        // The file itself.
        survives(config, configFile, "a file that is only whitespace",
                "   \n\t  ");
        survives(config, configFile, "a file that is a JSON array",
                "[]");
        survives(config, configFile, "a file that is a JSON string",
                "\"hello\"");
        survives(config, configFile, "a file that is a bare number",
                "42");
        survives(config, configFile, "a file with a duplicate rule list",
                "{\"version\": 3, \"serverRules\": [], \"serverProfiles\": {\"a\": {}}}");

        System.out.println();
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0) {
            System.exit(1);
        }
    }

    private static void survives(OpsecConfig config, Path file, String what, String content)
            throws IOException {
        Files.writeString(file, content);
        try {
            config.load();
            passed++;
            System.out.println("  ok   " + what + " -> loads without throwing");
        } catch (Throwable t) {
            failed++;
            System.out.println("  FAIL " + what + " -> " + t.getClass().getSimpleName()
                    + ": " + t.getMessage());
        }
    }
}

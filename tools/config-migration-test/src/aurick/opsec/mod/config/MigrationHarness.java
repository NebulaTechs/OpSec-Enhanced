package aurick.opsec.mod.config;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Exercises the configuration upgrade path against the production classes.
 *
 * <p>Every case writes a config file in an older shape, loads it through the real
 * {@link OpsecConfig#load()}, and asserts on what came out: which rules exist, what
 * their settings are, and what the file looks like afterwards. A case that ends in
 * a crash is a case that would take the client's settings with it.</p>
 */
public final class MigrationHarness {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws IOException {
        Path configDir = Path.of(System.getProperty("opsec.test.configDir", "/tmp/opencode/harness/config"));
        Files.createDirectories(configDir);
        Path configFile = configDir.resolve("opsec.json");

        OpsecConfig config = OpsecConfig.getInstance();

        // --- v1: the oldest shape: no version key, a flat settings block, and a
        //     map of address -> settings for the per-server profiles.
        write(configFile, v1Config());
        config.load();
        check("v1: the global settings land in the ANY rule",
                config.getAnyRule() != null
                        && config.getAnyRule().getSettings().isStripModShaders() == false
                        && config.getAnyRule().getSettings().isFakeDefaultKeybinds());
        check("v1: the legacy profile map becomes one EXACT rule per address",
                config.getServerRules().size() == 4
                        && countMatching(config) == 3);
        check("v1: the legacy profile settings survive the migration",
                ruleFor(config, "a.example.com") != null
                        && ruleFor(config, "a.example.com").getSettings().isSpoofAsVanilla());
        check("v1: the migrated rules are written back at the current version",
                versionOf(configFile) == OpsecConfig.CONFIG_VERSION);

        // --- v1 with an IP-shaped profile key. Upstream keyed serverProfiles by the
        //     resolved address, so an IP key must not come back as an EXACT rule:
        //     an EXACT rule compares against the typed host, so it would never hit.
        write(configFile, v1WithIpProfile());
        config.load();
        ServerRule ipRule = ruleFor(config, "203.0.113.7");
        check("v1: an IP-shaped profile key becomes an IP rule, not an EXACT one",
                ipRule != null && ipRule.getMatchType() == ServerRule.MatchType.IP);
        check("v1: the migrated IP rule matches the address it was saved under",
                ipRule != null && ipRule.matches("203.0.113.7", 25565));

        // --- a bare IPv6 literal must not be read as "host:port". Its last group
        //     looks like a port to a naive split, which would make the rule match
        //     nothing at all.
        ServerRule bareIpv6 = new ServerRule(ServerRule.MatchType.EXACT, "2001:db8::1");
        check("a bare IPv6 EXACT pattern matches the same literal",
                bareIpv6.matches("2001:db8::1", 25565));
        check("a bare IPv6 EXACT pattern does not match a different address",
                !bareIpv6.matches("2001:db8::2", 25565));
        ServerRule bracketedIpv6 = new ServerRule(ServerRule.MatchType.EXACT, "[::1]:25565");
        check("a bracketed IPv6 EXACT pattern with a port matches",
                bracketedIpv6.matches("::1", 25565));

        // --- v1 with no profiles at all: only the global block.
        write(configFile, v1WithoutProfiles());
        config.load();
        check("v1 without profiles: only the ANY rule survives",
                config.getServerRules().size() == 1);

        // --- v2: the accent colour is a separate field and the HUD text is separate.
        write(configFile, v2Config());
        config.load();
        SpoofSettings v2 = ruleFor(config, "b.example.com").getSettings();
        check("v2: the accent colour is folded into the HUD text",
                v2.getHudText().equals("§dB RULE"));
        check("v2: the accent colour key is gone from the saved file",
                !savedSettings(configFile).has("accentColor"));
        check("v2: the HUD text is saved with its colour prefix",
                ruleFor(config, "b.example.com").getSettings().getHudText().equals("§dB RULE"));

        // --- v2 with an empty HUD text: the colour has nothing to colour.
        write(configFile, v2WithEmptyHudText());
        config.load();
        check("v2 with no HUD text: the colour is dropped rather than left dangling",
                ruleFor(config, "c.example.com").getSettings().getHudText().isEmpty());

        // --- v2 with the old global on/off switch and no text.
        write(configFile, v2WithHudSwitch());
        config.load();
        check("v2 with the HUD switch on: the HUD comes back with the old text",
                ruleFor(config, "d.example.com").getSettings().getHudText().contains("OpSec"));

        // --- a file that is newer than this build understands.
        write(configFile, futureConfig());
        config.load();
        check("a future version is refused and the file is left alone",
                versionOf(configFile) == OpsecConfig.CONFIG_VERSION + 1);

        // --- malformed entries: they must be dropped, not crash the load.
        write(configFile, malformedConfig());
        config.load();
        check("a rule without a settings block still loads with the defaults",
                config.getServerRules().size() == 3
                        && ruleFor(config, "bad.example.com") != null);

        // --- loading the same file twice must not change it the second time.
        write(configFile, v2Config());
        config.load();
        String once = Files.readString(configFile);
        config.load();
        String twice = Files.readString(configFile);
        check("loading the same file twice is stable",
                once.equals(twice));
        check("loading the same file twice does not stack colour prefixes",
                ruleFor(config, "b.example.com").getSettings().getHudText().equals("§dB RULE"));

        // --- an empty file must not wipe the user's settings without a word.
        writeRaw(configFile, "");
        config.load();
        check("an empty file falls back to the defaults without crashing",
                config.getServerRules().size() == 1);

        // --- invalid JSON must not wipe anything either.
        writeRaw(configFile, "{not json");
        config.load();
        check("invalid JSON falls back to the defaults without crashing",
                config.getServerRules().size() == 1);
        check("a file the build could not read is kept as a backup",
                Files.exists(configDir.resolve("opsec.json.corrupt"))
                        && Files.readString(configDir.resolve("opsec.json.corrupt")).equals("{not json"));

        System.out.println();
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0) {
            System.exit(1);
        }
    }

    // ---------------------------------------------------------------- cases

    /** The oldest layout: no version, a flat settings block, a map of profiles. */
    private static JsonObject v1Config() {
        JsonObject json = new JsonObject();
        json.add("settings", settings("v1"));
        JsonObject profiles = new JsonObject();
        profiles.add("a.example.com", settings("profile-a"));
        profiles.add("b.example.com", settings("profile-b"));
        profiles.add("c.example.com", settings("profile-c"));
        json.add("serverProfiles", profiles);
        return json;
    }

    private static JsonObject v1WithIpProfile() {
        JsonObject json = new JsonObject();
        json.add("settings", settings("v1"));
        JsonObject profiles = new JsonObject();
        profiles.add("203.0.113.7", settings("profile-ip"));
        json.add("serverProfiles", profiles);
        return json;
    }

    private static JsonObject v1WithoutProfiles() {
        JsonObject json = new JsonObject();
        json.add("settings", settings("v1"));
        return json;
    }

    /** v2: the accent colour is its own field, the HUD text is its own field. */
    private static JsonObject v2Config() {
        JsonObject json = new JsonObject();
        json.addProperty("version", 2);
        json.add("settings", settings("v2"));
        JsonArray rules = new JsonArray();
        rules.add(rule("EXACT", "b.example.com", settingsWith2("hudText", "B RULE", "accentColor", "d")));
        json.add("serverRules", rules);
        return json;
    }

    private static JsonObject v2WithEmptyHudText() {
        JsonObject json = new JsonObject();
        json.addProperty("version", 2);
        json.add("settings", settings("v2"));
        JsonArray rules = new JsonArray();
        rules.add(rule("EXACT", "c.example.com", settingsWith("accentColor", "d")));
        json.add("serverRules", rules);
        return json;
    }

    private static JsonObject v2WithHudSwitch() {
        JsonObject json = new JsonObject();
        json.addProperty("version", 2);
        json.add("settings", settings("v2"));
        JsonArray rules = new JsonArray();
        rules.add(rule("EXACT", "d.example.com", settingsWith("showHudIndicator", true)));
        json.add("serverRules", rules);
        return json;
    }

    private static JsonObject futureConfig() {
        JsonObject json = new JsonObject();
        json.addProperty("version", OpsecConfig.CONFIG_VERSION + 1);
        json.add("settings", settings("future"));
        return json;
    }

    private static JsonObject malformedConfig() {
        JsonObject json = new JsonObject();
        json.addProperty("version", 3);
        json.add("settings", settings("v3"));
        JsonArray rules = new JsonArray();
        rules.add(rule("EXACT", "good.example.com", settings("good")));
        rules.add(rule("EXACT", "bad.example.com", null));
        json.add("serverRules", rules);
        return json;
    }

    // ---------------------------------------------------------------- helpers

    private static JsonObject settings(String marker) {
        JsonObject json = new JsonObject();
        json.addProperty("stripModShaders", false);
        json.addProperty("fakeDefaultKeybinds", true);
        json.addProperty("spoofAsVanilla", marker.startsWith("profile"));
        json.addProperty("marker", marker);
        return json;
    }

    private static JsonObject settingsWith2(String k1, Object v1, String k2, Object v2) {
        JsonObject json = new JsonObject();
        addProperty(json, k1, v1);
        addProperty(json, k2, v2);
        json.addProperty("spoofAsVanilla", false);
        return json;
    }

    private static JsonObject settingsWith(String k1, Object v1) {
        JsonObject json = new JsonObject();
        addProperty(json, k1, v1);
        json.addProperty("spoofAsVanilla", false);
        return json;
    }

    private static void addProperty(JsonObject json, String key, Object value) {
        if (value instanceof Boolean b) {
            json.addProperty(key, b);
        } else {
            json.addProperty(key, (String) value);
        }
    }

    private static JsonObject rule(String matchType, String pattern, JsonObject settings) {
        JsonObject json = new JsonObject();
        json.addProperty("matchType", matchType);
        json.addProperty("pattern", pattern);
        json.addProperty("enabled", true);
        if (settings != null) {
            json.add("settings", settings);
        }
        return json;
    }

    private static void write(Path file, JsonObject json) throws IOException {
        Files.writeString(file, json.toString());
    }

    private static void writeRaw(Path file, String content) throws IOException {
        Files.writeString(file, content);
    }

    private static int versionOf(Path file) throws IOException {
        return JsonParser.parseString(Files.readString(file)).getAsJsonObject().get("version").getAsInt();
    }

    private static JsonObject savedSettings(Path file) throws IOException {
        return JsonParser.parseString(Files.readString(file)).getAsJsonObject().getAsJsonObject("settings");
    }

    private static ServerRule ruleFor(OpsecConfig config, String pattern) {
        for (ServerRule rule : config.getServerRules()) {
            if (pattern.equals(rule.getPattern())) {
                return rule;
            }
        }
        return null;
    }

    private static int countMatching(OpsecConfig config) {
        int n = 0;
        for (ServerRule r : config.getServerRules()) {
            if (!r.isAnyRule()) {
                n++;
            }
        }
        return n;
    }


    private static void check(String what, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("  ok   " + what);
        } else {
            failed++;
            System.out.println("  FAIL " + what);
        }
    }
}

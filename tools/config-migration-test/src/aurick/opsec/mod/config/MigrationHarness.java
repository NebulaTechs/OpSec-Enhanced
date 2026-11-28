package aurick.opsec.mod.config;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

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
        //     resolved address, and a rule matches the typed host, so this profile
        //     only applies to a literal-IP connection — a different behaviour than
        //     the profile had. The user decides what happens to it, and until they
        //     have, nothing is written.
        write(configFile, v1WithIpProfile());
        String originalFile = Files.readString(configFile);
        config.load();
        check("v1 with an IP-shaped profile key: the decision waits for the user",
                config.hasPendingLegacyMigration());
        check("v1 with an IP-shaped profile key: the address is listed for the warning",
                config.getPendingLegacyProfileAddresses().equals(List.of("203.0.113.7")));
        check("v1 with an IP-shaped profile key: no rule exists before the decision",
                ruleFor(config, "203.0.113.7") == null);
        check("v1 with an IP-shaped profile key: the original file is left untouched",
                Files.readString(configFile).equals(originalFile));
        config.save();
        check("v1 with an IP-shaped profile key: an incidental save writes nothing",
                Files.readString(configFile).equals(originalFile));

        // --- the user chooses to upgrade: the held profile becomes an IP rule.
        write(configFile, v1WithIpProfile());
        config.load();
        config.acceptLegacyProfileUpgrade();
        ServerRule ipRule = ruleFor(config, "203.0.113.7");
        check("upgrade: the held profile becomes an IP rule",
                ipRule != null && ipRule.getMatchType() == ServerRule.MatchType.IP);
        check("upgrade: the IP rule matches the address it was saved under",
                ipRule != null && ipRule.matches("203.0.113.7", 25565));
        check("upgrade: the IP rule does not match a hostname that resolves to it",
                ipRule != null && !ipRule.matches("play.example.com", 25565));
        check("upgrade: the ANY rule stays last",
                config.getServerRules().get(config.getServerRules().size() - 1).isAnyRule());
        check("upgrade: the config is written at the current version",
                versionOf(configFile) == OpsecConfig.CONFIG_VERSION);
        check("upgrade: the decision no longer waits",
                !config.hasPendingLegacyMigration());
        config.load();
        check("upgrade: the warning does not come back on the next load",
                !config.hasPendingLegacyMigration());

        // --- the user chooses to back up: the original file is kept and the held
        //     profile is left out of the new config.
        write(configFile, v1WithIpProfile());
        String profileFile = Files.readString(configFile);
        config.load();
        config.acceptLegacyProfileBackup();
        check("backup: no rule is created for the held profile",
                ruleFor(config, "203.0.113.7") == null);
        check("backup: the original file is kept next to the config",
                Files.exists(configDir.resolve("opsec.json.v1.bak"))
                        && Files.readString(configDir.resolve("opsec.json.v1.bak")).equals(profileFile));
        check("backup: the config is written at the current version",
                versionOf(configFile) == OpsecConfig.CONFIG_VERSION);
        check("backup: the decision no longer waits",
                !config.hasPendingLegacyMigration());

        // --- the backup cannot be written. The file on disk is the only copy of the
        //     old profiles, so a failed copy has to leave it alone and keep the
        //     decision open - otherwise the next save would destroy the profiles.
        write(configFile, v1WithIpProfile());
        String originalBeforeFailure = Files.readString(configFile);
        config.load();
        Path backupPath = configDir.resolve("opsec.json.v1.bak");
        Files.deleteIfExists(backupPath);
        Files.createDirectory(backupPath);
        Path keepFile = backupPath.resolve("keep.txt");
        Files.writeString(keepFile, "x");
        boolean backupApplied = config.acceptLegacyProfileBackup();
        check("a backup that could not be written reports that nothing was applied",
                !backupApplied);
        check("a backup that could not be written leaves the original file untouched",
                Files.readString(configFile).equals(originalBeforeFailure));
        check("a backup that could not be written leaves the decision open",
                config.hasPendingLegacyMigration());
        check("a backup that could not be written keeps the profile listed",
                config.getPendingLegacyProfileAddresses().equals(List.of("203.0.113.7")));
        config.save();
        check("a backup that could not be written still stops an incidental save",
                Files.readString(configFile).equals(originalBeforeFailure));
        Files.delete(keepFile);
        Files.delete(backupPath);

        // --- a setting the user changes while the decision is open cannot be
        //     written yet, and the original file stays the copy of the old profiles.
        write(configFile, v1WithIpProfile());
        String beforeChange = Files.readString(configFile);
        config.load();
        config.getAnyRule().getSettings().setSpoofAsVanilla(true);
        config.save();
        check("a setting changed while the decision is open is not written",
                Files.readString(configFile).equals(beforeChange));
        check("the decision is still open after the change",
                config.hasPendingLegacyMigration());

        // --- the user can leave the prompt without choosing. The prompt keeps no
        //     state of its own: the decision lives in the file, so the next load
        //     offers the prompt again and the old profiles are still there.
        write(configFile, v1WithIpProfile());
        String beforeDismissal = Files.readString(configFile);
        config.load();
        check("leaving the prompt without a choice leaves the decision open",
                config.hasPendingLegacyMigration());
        check("leaving the prompt without a choice leaves the original file untouched",
                Files.readString(configFile).equals(beforeDismissal));
        config.load();
        check("the prompt is offered again on the next load",
                config.hasPendingLegacyMigration());
        check("the original file is still untouched after the next load",
                Files.readString(configFile).equals(beforeDismissal));
        check("the profile is still listed after the next load",
                config.getPendingLegacyProfileAddresses().equals(List.of("203.0.113.7")));

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

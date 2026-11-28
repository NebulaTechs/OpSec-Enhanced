package aurick.opsec.mod.config;

import aurick.opsec.mod.Opsec;
import aurick.opsec.mod.tracking.ModRegistry;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import aurick.opsec.mod.util.NeoCompat;

/**
 * Main configuration manager for OpSec mod.
 * Handles loading, saving, and validating configuration settings.
 * Uses thread-safe singleton pattern with double-checked locking.
 */
public class OpsecConfig {

    private static final Gson GSON = new GsonBuilder()
        .setPrettyPrinting()
        .create();
    private static final Path CONFIG_PATH = NeoCompat.getConfigDir()
        .resolve("opsec.json");

    public static final boolean EXPLOIT_PREVENTER_LOADED =
        NeoCompat.isModLoaded("exploitpreventer");

    /** Current config schema version. A file without a {@code version} key is v1 and is
     *  migrated on load; a file newer than this is refused and left untouched.
     *  v3 dropped the separate accent-color field in favour of a color code at the
     *  front of the HUD text. */
    public static final int CONFIG_VERSION = 3;

    // Chat signing and telemetry blocking overlap with dedicated mods. When one is
    // present OpSec stands down on the shared feature (greys the control out) rather
    // than double-stripping signatures / double-disabling telemetry. Unlike EP this is
    // per-feature: No Chat Reports only covers signing; No Prying Eyes covers both.
    public static final boolean NO_CHAT_REPORTS_LOADED =
        NeoCompat.isModLoaded("nochatreports");
    public static final boolean NO_PRYING_EYES_LOADED =
        NeoCompat.isModLoaded("nopryingeyes");

    /** Chat signing is handled by an external mod (No Chat Reports or No Prying Eyes). */
    public static final boolean CHAT_SIGNING_MANAGED_EXTERNALLY =
        NO_CHAT_REPORTS_LOADED || NO_PRYING_EYES_LOADED;

    /** Telemetry blocking is handled by an external mod (No Chat Reports or No Prying Eyes). */
    public static final boolean TELEMETRY_MANAGED_EXTERNALLY =
        NO_CHAT_REPORTS_LOADED || NO_PRYING_EYES_LOADED;

    // Per-MC-version feature gate: DownloadQueue + multi-pack stacking arrived 1.20.3.
    // 1.20.1/1.20.2 isolate the pack cache via LegacyDownloadedPackSourceMixin instead.
    //? if >=1.20.3 {
    public static final boolean MC_VERSION_HAS_MULTI_PACK = true;
    //?} else {
    /*public static final boolean MC_VERSION_HAS_MULTI_PACK = false;
    *///?}

    // Block Local URLs: 1.20.1's HttpUtil lambda targeting was unreliable in practice; off there.
    //? if >=1.20.2 {
    public static final boolean MC_VERSION_HAS_BLOCK_LOCAL_URLS = true;
    //?} else {
    /*public static final boolean MC_VERSION_HAS_BLOCK_LOCAL_URLS = false;
    *///?}

    // HUD Indicator is offered on every version now: 1.20.1-1.21.11 render it via
    // a direct Mixin (see GuiHudMixin), and 26.1+ via Fabric API's HudElementRegistry
    // (see OpsecHud's javadoc — that path is less battle-tested here than the
    // mixin one, so it's still worth a real in-game check on 26.x after this change).
    public static final boolean MC_VERSION_HAS_HUD_INDICATOR = true;

    private static volatile OpsecConfig INSTANCE;
    private static final Object LOCK = new Object();

    // The active settings pointer. It points at the ANY rule's settings — the global
    // baseline — unless a server rule is currently active (see setCurrentServer). Every
    // existing settings.xxx() call site in this class and elsewhere in the mod keeps
    // working unmodified either way, since it's always reading through the same field.
    private volatile SpoofSettings settings = new SpoofSettings();

    // Ordered server rules. List order IS the priority: the first rule whose matcher
    // accepts the address the player typed wins, and its settings become the active
    // ones for that connection.
    private final List<ServerRule> serverRules = new CopyOnWriteArrayList<>();

    private volatile ServerRule activeRule = null;

    // The rule picked for the connection attempt that is currently being set up. It is
    // deliberately kept apart from the rule of the server the client is connected to:
    // an attempt that fails or is cancelled has to be discarded without touching the
    // connected server's rule, and the rule of an in-flight attempt has to be
    // re-resolved once the address it resolves to is known -- an IP rule cannot be
    // matched from the typed hostname alone.
    private volatile ServerRule pendingRule = null;

    // The rule a server-initiated transfer is pinned to, and the address that transfer
    // names. Set just before the old connection is closed (closing it drops that
    // server's rule) and consumed by the rule lookup for that one address.
    private volatile ServerRule pinnedRule = null;
    private volatile String pinnedHost = null;
    private volatile int pinnedPort = 0;
    private volatile boolean pinConsumed = false;

    // Servers explicitly exempted from Auto-Purge Pack Cache On Exit (issue #23).
    // Deliberately a separate, lightweight set rather than a SpoofSettings field on
    // a full server profile: a per-server profile overrides every spoof setting for
    // that server and gets reverted to the global baseline on disconnect (setCurrentServer),
    // so it's gone again well before CLIENT_STOPPING's purge check ever runs. This set
    // is checked directly by address at purge time instead, independent of whether
    // anything is still "connected" by then -- see ResourcePackGuard.clearAllCaches.
    private final Set<String> packCacheTrustedServers = ConcurrentHashMap.newKeySet();

    private volatile String currentServer = null;
    private volatile String currentServerIp = null;
    private volatile int currentServerPort = 0;
    private volatile boolean serverConnected = false;

    /** Set when a load-time correction changed something, so the file is rewritten once at the end. */
    private boolean dirty = false;

    /** True when the config file is newer than this build understands; it is then never written. */
    private boolean readOnly = false;

    /**
     * Legacy v1 profiles whose key was a resolved IP address. Per-server rules match
     * the address the player types, so an IP-keyed profile only ever applies to a
     * literal-IP connection. Whether to convert it or leave it out is the user's
     * call, so it is held here until they decide.
     */
    private final List<ServerRule> pendingLegacyProfiles = new ArrayList<>();

    /** True while the legacy-profile decision is outstanding; the file is not written then. */
    private boolean legacyMigrationPending = false;

    private OpsecConfig() {
        load();
        if (EXPLOIT_PREVENTER_LOADED) {
            Opsec.LOGGER.info(
                "[OpSec] ExploitPreventer detected - compatibility mode active."
            );
        }
        if (NO_CHAT_REPORTS_LOADED) {
            Opsec.LOGGER.info(
                "[OpSec] No Chat Reports detected - deferring chat signing and telemetry to it."
            );
        }
        if (NO_PRYING_EYES_LOADED) {
            Opsec.LOGGER.info(
                "[OpSec] No Prying Eyes detected - deferring chat signing and telemetry to it."
            );
        }
    }

    /** Display name of the mod managing chat signing, or {@code null} if OpSec manages it. */
    public static String chatSigningManagerName() {
        if (NO_CHAT_REPORTS_LOADED) return "No Chat Reports";
        if (NO_PRYING_EYES_LOADED) return "No Prying Eyes";
        return null;
    }

    /** Display name of the mod managing telemetry, or {@code null} if OpSec manages it. */
    public static String telemetryManagerName() {
        if (NO_CHAT_REPORTS_LOADED) return "No Chat Reports";
        if (NO_PRYING_EYES_LOADED) return "No Prying Eyes";
        return null;
    }

    public static OpsecConfig getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new OpsecConfig();
                }
            }
        }
        return INSTANCE;
    }

    /**
     * The directory the config file lives in. Loader-neutral on purpose: the UI uses it
     * for its import/export files, and a loader-specific call here would break the
     * NeoForge port.
     */
    public static Path getConfigDir() {
        return CONFIG_PATH.getParent();
    }

    public void load() {
        readOnly = false;
        pendingLegacyProfiles.clear();
        legacyMigrationPending = false;
        if (!Files.exists(CONFIG_PATH)) {
            Opsec.LOGGER.info("[OpSec] Creating default config");
            // The file must be written with the invariant already satisfied: exactly one
            // ANY rule, last in the list. Saving without it would produce a v2 file that
            // only becomes valid on the next load.
            resetToDefaults();
            save();
            return;
        }

        try {
            String content = Files.readString(CONFIG_PATH);
            if (content == null || content.trim().isEmpty()) {
                Opsec.LOGGER.warn(
                    "[OpSec] Config file is empty, using defaults"
                );
                resetToDefaults();
                save();
                return;
            }

            JsonObject json = JsonParser.parseString(content).getAsJsonObject();

            // The version decides how the rest of the file is read, so a version that
            // is not a plain number means the file is not one this build can interpret
            // — refusing it is safer than guessing a version and migrating wrongly.
            int version;
            if (json.has("version")) {
                com.google.gson.JsonElement versionElement = json.get("version");
                if (!versionElement.isJsonPrimitive()
                        || !versionElement.getAsJsonPrimitive().isNumber()) {
                    readOnly = true;
                    Opsec.LOGGER.error(
                        "[OpSec] Config file has a non-numeric version - refusing to load it and leaving the file untouched"
                    );
                    resetToDefaults();
                    return;
                }
                version = versionElement.getAsInt();
            } else {
                version = 1;
            }
            if (version > CONFIG_VERSION) {
                readOnly = true;
                Opsec.LOGGER.error(
                    "[OpSec] Config file is version {} but this build only understands version {} - refusing to load it and leaving the file untouched",
                    version, CONFIG_VERSION
                );
                resetToDefaults();
                return;
            }

            // v1 kept the global baseline in a top-level key; v2 keeps it in the ANY rule
            // and mirrors it back into "settings" so downgrades keep working.
            SpoofSettings legacyGlobal = null;
            JsonObject legacySettings = JsonSafe.obj(json, "settings");
            if (legacySettings == null) {
                legacySettings = JsonSafe.obj(json, "defaultSettings");
            }
            if (legacySettings != null) {
                legacyGlobal = SpoofSettings.fromJson(legacySettings);
            }

            serverRules.clear();
            JsonArray rulesArray = JsonSafe.arr(json, "serverRules");
            if (rulesArray != null) {
                for (JsonElement element : rulesArray) {
                    if (!element.isJsonObject()) {
                        Opsec.LOGGER.warn("[OpSec] Dropping malformed server rule: not an object");
                        continue;
                    }
                    try {
                        ServerRule rule = ServerRule.fromJson(element.getAsJsonObject());
                        validateAndCorrectSettings(rule.getSettings());
                        serverRules.add(rule);
                    } catch (Exception e) {
                        Opsec.LOGGER.warn("[OpSec] Dropping malformed server rule: {}", e.getMessage());
                    }
                }
            } else {
                // Legacy layout: a map of address -> settings. Every entry becomes a rule
                // for that address, sorted by address so the migrated order is stable.
                JsonObject profiles = JsonSafe.obj(json, "serverProfiles");
                if (profiles != null) {
                    List<String> addresses = new ArrayList<>(profiles.keySet());
                    Collections.sort(addresses);
                    for (String address : addresses) {
                        JsonObject profileJson = JsonSafe.obj(profiles, address);
                        if (profileJson == null) {
                            Opsec.LOGGER.warn("[OpSec] Dropping malformed server profile for '{}': not an object", address);
                            continue;
                        }
                        try {
                            SpoofSettings profile = SpoofSettings.fromJson(profileJson);
                            validateAndCorrectSettings(profile);
                            ServerRule rule = new ServerRule(
                                    ServerRule.isIpLiteral(address)
                                            ? ServerRule.MatchType.IP
                                            : ServerRule.MatchType.EXACT,
                                    address
                            );
                            rule.copySettingsFrom(profile);
                            if (rule.getMatchType() == ServerRule.MatchType.IP) {
                                pendingLegacyProfiles.add(rule);
                            } else {
                                serverRules.add(rule);
                            }
                        } catch (Exception e) {
                            Opsec.LOGGER.warn("[OpSec] Dropping malformed server profile for '{}': {}", address, e.getMessage());
                        }
                    }
                    if (!pendingLegacyProfiles.isEmpty()) {
                        legacyMigrationPending = true;
                        Opsec.LOGGER.warn(
                            "[OpSec] {} legacy server profile(s) were saved under a resolved IP address. Per-server rules now match the address the player types, so these only apply to literal-IP connections - waiting for the user's choice.",
                            pendingLegacyProfiles.size()
                        );
                    }
                    Opsec.LOGGER.info("[OpSec] Migrated {} legacy server profile(s) into server rules", serverRules.size());
                }
            }

            packCacheTrustedServers.clear();
            packCacheTrustedServers.addAll(JsonSafe.stringList(json, "packCacheTrustedServers"));

            boolean createdAny = ensureAnyRule();
            ServerRule anyRule = getAnyRule();
            if (legacyGlobal != null && (version < CONFIG_VERSION || createdAny)) {
                anyRule.copySettingsFrom(legacyGlobal);
            }
            if (version < CONFIG_VERSION) {
                // A rule with no pattern can never match, so it is dead weight. Drop
                // those during the v1 migration only — in a v2 file an empty pattern can
                // be a rule the user is in the middle of filling in.
                serverRules.removeIf(rule ->
                    !rule.isAnyRule() && ServerRule.splitPatterns(rule.getPattern()).isEmpty());
                Opsec.LOGGER.info(
                    "[OpSec] Migrated config from version {} to version {}", version, CONFIG_VERSION
                );
                dirty = true;
            }

            if (!validateAndCorrectSettings(anyRule.getSettings())) {
                Opsec.LOGGER.warn(
                    "[OpSec] Config validation failed, resetting to defaults"
                );
                resetToDefaults();
                save();
                return;
            }

            settings = anyRule.getSettings();

            Opsec.LOGGER.info(
                "[OpSec] Loaded config - spoofAsVanilla: {}, {} server rule(s)",
                anyRule.getSettings().isSpoofAsVanilla(), serverRules.size()
            );

            if (dirty && !readOnly && !legacyMigrationPending) {
                save();
            }
        } catch (IOException e) {
            Opsec.LOGGER.error(
                "[OpSec] Failed to read config file: {}",
                e.getMessage()
            );
            resetToDefaults();
            save();
        } catch (
            com.google.gson.JsonSyntaxException
            | IllegalStateException e
        ) {
            Opsec.LOGGER.error(
                "[OpSec] Invalid JSON in config file: {}",
                e.getMessage()
            );
            backupUnreadableFile();
            resetToDefaults();
            save();
        } catch (RuntimeException e) {
            // Fall back to the defaults but leave the file alone — a file the build
            // could not read may still be repairable by hand.
            Opsec.LOGGER.error(
                "[OpSec] Could not read config file, falling back to defaults: {}",
                e.toString()
            );
            backupUnreadableFile();
            resetToDefaults();
        }
    }

    /**
     * Copies a config file the build could not read to a sibling file, so the
     * settings it still holds are not lost when the loader falls back to the
     * defaults and writes them over the original.
     */
    private void backupUnreadableFile() {
        try {
            Path backup = CONFIG_PATH.resolveSibling(CONFIG_PATH.getFileName() + ".corrupt");
            Files.copy(CONFIG_PATH, backup, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            Opsec.LOGGER.warn(
                "[OpSec] Kept a copy of the unreadable config file at {}",
                backup
            );
        } catch (IOException e) {
            Opsec.LOGGER.warn(
                "[OpSec] Could not keep a copy of the unreadable config file: {}",
                e.getMessage()
            );
        }
    }

    /** Resets the config to a single ANY rule with fresh defaults and drops every other rule. */
    private void resetToDefaults() {
        serverRules.clear();
        activeRule = null;
        pendingRule = null;
        pendingLegacyProfiles.clear();
        legacyMigrationPending = false;
        packCacheTrustedServers.clear();
        ServerRule any = new ServerRule(ServerRule.MatchType.ANY, "");
        serverRules.add(any);
        settings = any.getSettings();
    }

    /**
     * Validates and auto-corrects settings if necessary.
     * This method modifies invalid settings to valid defaults.
     *
     * @param settings The settings to validate
     * @return true if settings were valid or have been corrected, false if settings is null
     */
    private boolean validateAndCorrectSettings(SpoofSettings settings) {
        if (settings == null) {
            Opsec.LOGGER.error("[OpSec] Validation failed: settings is null");
            return false;
        }

        boolean modified = false;

        if (settings.getSigningMode() == null) {
            Opsec.LOGGER.warn(
                "[OpSec] Invalid signing mode, resetting to SIGN"
            );
            settings.setSigningMode(SpoofSettings.SigningMode.SIGN);
            modified = true;
        }

        if (settings.getWhitelistMode() == null) {
            Opsec.LOGGER.warn(
                "[OpSec] Invalid whitelist mode, resetting to AUTO"
            );
            settings.setWhitelistMode(SpoofSettings.WhitelistMode.AUTO);
            modified = true;
        }

        // Spoof-as-vanilla is the master mode: it implies "block ALL custom payloads",
        // so an active whitelist (Auto/Custom) would be moot. Force the whitelist to
        // OFF (block all) whenever spoofAsVanilla is on. setSpoofAsVanilla normally
        // handles the swap, but hand-edited configs can still land here inconsistent.
        if (settings.isSpoofAsVanilla() && settings.getWhitelistMode() != SpoofSettings.WhitelistMode.OFF) {
            Opsec.LOGGER.warn(
                "[OpSec] active whitelist incompatible with spoofAsVanilla; forcing whitelist OFF (block all)"
            );
            settings.setWhitelistMode(SpoofSettings.WhitelistMode.OFF);
            modified = true;
        }

        // Block-All is no longer user-selectable: when spoof-vanilla is off, migrate
        // any leftover OFF mode (from older configs that exposed it as a tri-state)
        // back to AUTO so the user isn't stuck in an unreachable state.
        if (!settings.isSpoofAsVanilla() && settings.getWhitelistMode() == SpoofSettings.WhitelistMode.OFF) {
            Opsec.LOGGER.info(
                "[OpSec] Migrating legacy whitelist OFF (block all) to AUTO — option is no longer user-selectable"
            );
            settings.setWhitelistMode(SpoofSettings.WhitelistMode.AUTO);
            modified = true;
        }

        if (modified) {
            // Not saved here: this runs while the config file is still being read, and a
            // save() in the middle of load() would write a half-populated rule list.
            // load() persists the file once, at the end, when dirty is set.
            dirty = true;
        }

        return true;
    }

    public void save() {
        if (readOnly) {
            Opsec.LOGGER.warn(
                "[OpSec] Config is read-only (file is newer than this build) - not writing"
            );
            return;
        }
        if (legacyMigrationPending) {
            Opsec.LOGGER.warn(
                "[OpSec] Config is waiting for a decision on the legacy server profiles - not writing"
            );
            return;
        }
        try {
            JsonObject json = new JsonObject();
            json.addProperty("version", CONFIG_VERSION);

            // The ANY rule is the global baseline. It is mirrored into the top-level
            // "settings" key so a build older than v2 still finds the baseline it reads.
            ServerRule any = getAnyRule();
            SpoofSettings global = any != null ? any.getSettings() : settings;
            json.add("settings", global.toJson());

            JsonArray rulesJson = new JsonArray();
            for (ServerRule rule : serverRules) {
                rulesJson.add(rule.toJson());
            }
            json.add("serverRules", rulesJson);

            com.google.gson.JsonArray trustedServersJson = new com.google.gson.JsonArray();
            for (String address : packCacheTrustedServers) {
                trustedServersJson.add(address);
            }
            json.add("packCacheTrustedServers", trustedServersJson);

            Files.createDirectories(CONFIG_PATH.getParent());

            Path tempFile = CONFIG_PATH.resolveSibling(
                CONFIG_PATH.getFileName() + ".tmp"
            );
            Files.writeString(tempFile, GSON.toJson(json));
            Files.move(
                tempFile,
                CONFIG_PATH,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE
            );
        } catch (IOException e) {
            Opsec.LOGGER.error(
                "[OpSec] Failed to save config to {}: {}",
                CONFIG_PATH,
                e.getMessage()
            );
        }
        // Null-guard avoids constructor's save→getInstance recursion; OpsecClient seeds the first build.
        if (INSTANCE != null) {
            ModRegistry.rebuildDependencyClosure();
        }
    }

    public SpoofSettings getSettings() {
        return settings;
    }

    /**
     * Recomputes the settings the whole mod reads through {@link #getSettings()}.
     *
     * <p>An attempt that is being set up wins over the server the client is connected
     * to: the consumers that run while a connection is opening must see the rule of the
     * server that is being opened. Once the attempt is over the connected server's rule
     * takes over again, and with no server at all the global baseline applies.</p>
     */
    private void refreshEffectiveSettings() {
        ServerRule pending = pendingRule;
        if (pending != null) {
            this.settings = pending.getSettings();
            return;
        }
        ServerRule active = activeRule;
        this.settings = active != null ? active.getSettings() : getGlobalSettings();
    }

    /** The mandatory global fallback rule, or null when the rule list holds none. */
    public ServerRule getAnyRule() {
        for (ServerRule rule : serverRules) {
            if (rule.isAnyRule()) {
                return rule;
            }
        }
        return null;
    }

    /** The global baseline settings — the ANY rule's settings. */
    public SpoofSettings getGlobalSettings() {
        ServerRule any = getAnyRule();
        if (any == null) {
            ensureAnyRule();
            any = getAnyRule();
        }
        return any.getSettings();
    }

    /** The rules the user can edit — every rule except the mandatory ANY fallback. */
    public List<ServerRule> getEditableRules() {
        List<ServerRule> editable = new ArrayList<>();
        for (ServerRule rule : serverRules) {
            if (!rule.isAnyRule()) {
                editable.add(rule);
            }
        }
        return editable;
    }

    /** True when the config file is newer than this build understands and is never written. */
    public boolean isReadOnly() {
        return readOnly;
    }

    /**
     * True while a legacy per-server profile waits for the user's decision.
     *
     * <p>While this holds the config file is not written: the file on disk is the only
     * copy of the old profiles, and it has to survive until the user has said what
     * should happen to them.</p>
     */
    public boolean hasPendingLegacyMigration() {
        return legacyMigrationPending;
    }

    /** The addresses of the legacy profiles that are waiting for a decision. */
    public List<String> getPendingLegacyProfileAddresses() {
        List<String> addresses = new ArrayList<>();
        for (ServerRule rule : pendingLegacyProfiles) {
            addresses.add(rule.getPattern());
        }
        return addresses;
    }

    /**
     * Converts the held legacy profiles into IP rules and writes the new config.
     *
     * <p>The rules only apply when the player connects by typing the IP literal.</p>
     */
    public void acceptLegacyProfileUpgrade() {
        if (!legacyMigrationPending) {
            return;
        }
        int anyIndex = indexOfAnyRule();
        for (ServerRule rule : pendingLegacyProfiles) {
            if (anyIndex >= 0) {
                serverRules.add(anyIndex++, rule);
            } else {
                serverRules.add(rule);
            }
        }
        int count = pendingLegacyProfiles.size();
        pendingLegacyProfiles.clear();
        legacyMigrationPending = false;
        Opsec.LOGGER.info("[OpSec] Converted {} legacy server profile(s) into IP rules", count);
        save();
    }

    /**
     * Keeps the original file as a backup and writes a config without the held profiles.
     *
     * <p>The backup has to be in place before the original is replaced: the file on disk
     * is the only copy of the old profiles, so a failed copy leaves everything as it was
     * and the decision stays open.</p>
     *
     * @return true when the backup was written and the decision was applied
     */
    public boolean acceptLegacyProfileBackup() {
        if (!legacyMigrationPending) {
            return true;
        }
        if (!backupLegacyFile()) {
            Opsec.LOGGER.error(
                "[OpSec] Could not keep a copy of the original config file - the legacy server profiles stay where they are"
            );
            return false;
        }
        int count = pendingLegacyProfiles.size();
        pendingLegacyProfiles.clear();
        legacyMigrationPending = false;
        Opsec.LOGGER.info(
            "[OpSec] Left {} legacy server profile(s) out of the config and kept the original file",
            count
        );
        save();
        return true;
    }

    /**
     * Copies the config file the build just read to a sibling file, keeping the legacy profiles it holds.
     *
     * @return true when the copy was written
     */
    private boolean backupLegacyFile() {
        try {
            Path backup = CONFIG_PATH.resolveSibling(CONFIG_PATH.getFileName() + ".v1.bak");
            Files.copy(CONFIG_PATH, backup, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            Opsec.LOGGER.info("[OpSec] Kept the original config file at {}", backup);
            return true;
        } catch (IOException e) {
            Opsec.LOGGER.warn(
                "[OpSec] Could not keep a copy of the original config file: {}",
                e.getMessage()
            );
            return false;
        }
    }

    /**
     * Records the active server and swaps the active {@link #settings} to the settings of
     * the first rule that matches it (falls back to {@link #getGlobalSettings()} when no rule
     * matches).
     *
     * @param host the address the player typed, {@code null} when disconnected
     * @param port the port that was connected to, {@code 0} when unknown
     * @param ip   the address the connection resolved to, may be {@code null}
     */
    public void setCurrentServer(String host, int port, String ip) {
        this.serverConnected = host != null || ip != null;
        if (!serverConnected) {
            this.currentServer = null;
            this.currentServerIp = null;
            this.currentServerPort = 0;
            this.activeRule = null;
            // The pending rule is deliberately left alone here: a new attempt may already
            // be under way while the previous connection is still closing, and discarding
            // the new attempt's rule would hand the wrong settings to the packets of the
            // connection that is being opened.
            refreshEffectiveSettings();
            return;
        }
        this.currentServer = host != null ? host : ip;
        this.currentServerIp = ip;
        this.currentServerPort = port;
        ServerRule matched = findMatchingRule(host, port);
        this.activeRule = matched;
        // The login succeeded, so the attempt is over: the connected server's rule is
        // the one that applies from here on.
        this.pendingRule = null;
        this.pinnedRule = null;
        this.pinnedHost = null;
        this.pinnedPort = 0;
        this.pinConsumed = false;
        refreshEffectiveSettings();
        if (matched != null) {
            Opsec.LOGGER.info("[OpSec] Server rule matched: {} {}", matched.getMatchType(), matched.getPattern());
        }
    }

    /** The first rule whose matcher accepts the given address, falling back to the ANY rule. */
    public ServerRule findMatchingRule(String host, int port) {
        if (isPinnedFor(host, port)) {
            return pinnedRule;
        }
        for (ServerRule rule : serverRules) {
            if (rule.isAnyRule()) {
                continue;
            }
            if (rule.matches(host, port)) {
                return rule;
            }
        }
        return getAnyRule();
    }

    /**
     * The settings that apply to one address, without touching the active settings.
     *
     * <p>Used by the consumers that run while a connection is being set up: they must see
     * the rule of the server that is being opened, not the rule of the server that was
     * connected before. The ANY rule is the fallback when the address matches nothing.</p>
     */
    public SpoofSettings settingsForTarget(String host, int port) {
        ServerRule matched = findMatchingRule(host, port);
        return matched != null ? matched.getSettings() : getGlobalSettings();
    }

    /**
     * Selects the rule that matches an address the player is about to connect to.
     *
     * <p>The rule has to be picked before the connection is opened: the game proxy and the
     * client-information normalizer both run while the connection is still being set up,
     * and they would otherwise read the global baseline instead of the server's own rule.
     * Unlike {@link #setCurrentServer(String, int, String)} this does not record the
     * server as connected -- that only happens once the login succeeds -- and it only
     * fills the pending slot, so a failed or cancelled attempt can be discarded again
     * without disturbing the connected server's rule.</p>
     *
     * <p>Called twice per attempt: first with the address the player typed, then again
     * with the address that address resolved to. The second call is what lets a rule
     * that matches the resolved IP apply to the packets that go out during the
     * handshake.</p>
     */
    public void selectRuleFor(String host, int port) {
        ServerRule matched = findMatchingRule(host, port);
        if (matched == null) {
            return;
        }
        this.pendingRule = matched;
        refreshEffectiveSettings();
        Opsec.LOGGER.info("[OpSec] Server rule selected: {} {}", matched.getMatchType(), matched.getPattern());
    }

    /**
     * Starts a connection attempt and selects the rule that applies to it.
     *
     * <p>A transfer keeps the pin that was set for it, so the target is matched against
     * the rule of the server that sent it. Every other attempt drops it: a pin only
     * ever describes one transfer, and a stale one would otherwise hand the rule of
     * some earlier server to a later connection.</p>
     *
     * @param host the address the player typed
     * @param port the port that is being connected to
     * @param transferred true when the attempt is the target of a server-initiated transfer
     */
    public void beginConnectionAttempt(String host, int port, boolean transferred) {
        if (transferred && isPinFor(host, port)) {
            this.pinConsumed = true;
        } else {
            this.pinnedRule = null;
            this.pinnedHost = null;
            this.pinnedPort = 0;
            this.pinConsumed = false;
        }
        selectRuleFor(host, port);
    }

    /**
     * Pins the current rule for the connection attempt that a server-initiated transfer
     * is about to start.
     *
     * <p>Called just before the transfer is carried out, because by the time the new
     * connection is being set up the rule of the server that handed the player over is
     * already gone -- the old connection is closed first, and closing it drops that
     * server's rule. The pin is bound to the address the transfer names, so a
     * background ping of some other server is not affected by it.</p>
     *
     * <p>Does nothing when the rule in effect asks for the new target to be matched on
     * its own, which is the default.</p>
     */
    public void pinRuleForTransfer(String host, int port) {
        ServerRule current = activeRule;
        if (current == null) {
            return;
        }
        if (current.getSettings().isReselectRuleOnTransfer()) {
            return;
        }
        this.pinnedRule = current;
        this.pinnedHost = asciiHost(host);
        this.pinnedPort = port;
        this.pinConsumed = false;
        Opsec.LOGGER.info("[OpSec] Transfer: keeping the rule {} {} for {}",
                current.getMatchType(), current.getPattern(), host);
    }

    private boolean isPinFor(String host, int port) {
        String pinned = pinnedHost;
        if (pinnedRule == null || pinned == null || host == null) {
            return false;
        }
        if (!pinned.equals(asciiHost(host))) {
            return false;
        }
        return pinnedPort <= 0 || port <= 0 || pinnedPort == port;
    }

    /**
     * The address in the form the client dials it in.
     *
     * <p>A transfer names its target as a raw string, while the address the connection
     * starts with goes through {@code ServerAddress}, which converts an international
     * domain name to its ASCII form. Both sides of the pin have to be reduced the same
     * way, or a transfer to an international name would not find its own pin.</p>
     */
    private static String asciiHost(String host) {
        if (host == null) {
            return null;
        }
        String trimmed = host.trim();
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1);
        }
        try {
            return java.net.IDN.toASCII(trimmed).toLowerCase(java.util.Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    private boolean isPinnedFor(String host, int port) {
        return pinConsumed && isPinFor(host, port);
    }

    /**
     * Discards the rule that was selected for a connection attempt that never reached
     * the login stage -- the attempt failed, timed out or was cancelled by the player.
     *
     * <p>Without this the rule of the server the player tried to join would stay in
     * effect while the client sits on the multiplayer screen, and a background
     * server-list ping would read it as if it belonged to the pinged server.</p>
     */
    public void clearPendingRule() {
        if (pendingRule == null) {
            return;
        }
        this.pendingRule = null;
        refreshEffectiveSettings();
        Opsec.LOGGER.info("[OpSec] Connection attempt ended; pending rule discarded");
    }

    public String getCurrentServer() {
        return currentServer;
    }

    /**
     * The current server in its normalized form (lower-case, default port removed) — the
     * key the pack-cache buckets and the trust list are keyed by, so that the same server
     * always lands in the same bucket regardless of how its address was typed.
     */
    public String getCurrentServerKey() {
        return currentServer == null ? null : normalizeAddress(currentServer);
    }

    /** The address the current connection resolved to, or null when unknown. */
    public String getCurrentServerIp() {
        return currentServerIp;
    }

    /** The port of the current connection, or 0 when unknown. */
    public int getCurrentServerPort() {
        return currentServerPort;
    }

    /** True while actually connected to a server. */
    public boolean hasActiveServer() {
        return serverConnected;
    }

    /** The rule that matched the current connection, or null when none did. */
    public ServerRule getActiveRule() {
        return pendingRule != null ? pendingRule : activeRule;
    }

    /** True when an EXACT rule exists for the address of the current connection. */
    public boolean hasServerRule() {
        if (!serverConnected || currentServer == null) {
            return false;
        }
        for (ServerRule rule : serverRules) {
            if (rule.getMatchType() == ServerRule.MatchType.EXACT
                    && rule.getPattern().equalsIgnoreCase(currentServer)) {
                return true;
            }
        }
        return false;
    }

    /** The rules in priority order — the first entry is evaluated first. */
    public List<ServerRule> getServerRules() {
        return List.copyOf(serverRules);
    }

    /** Inserts a rule just above the ANY fallback and persists the config. */
    public void addServerRule(ServerRule rule) {
        if (rule == null) {
            return;
        }
        if (rule.isAnyRule()) {
            rule.setMatchType(ServerRule.MatchType.EXACT);
        }
        int anyIndex = indexOfAnyRule();
        if (anyIndex < 0) {
            serverRules.add(rule);
        } else {
            serverRules.add(anyIndex, rule);
        }
        save();
    }

    public void removeServerRule(ServerRule rule) {
        if (rule == null || rule.isAnyRule()) {
            return;
        }
        serverRules.remove(rule);
        if (pendingRule == rule) {
            pendingRule = null;
        }
        if (activeRule == rule) {
            activeRule = null;
        }
        if (pinnedRule == rule) {
            pinnedRule = null;
            pinnedHost = null;
            pinnedPort = 0;
            pinConsumed = false;
        }
        refreshEffectiveSettings();
        save();
    }

    /** Moves a rule by {@code delta} positions, keeping the list order meaningful. */
    public void moveServerRule(int index, int delta) {
        int target = index + delta;
        if (index < 0 || index >= serverRules.size() || target < 0 || target >= serverRules.size()) {
            return;
        }
        if (serverRules.get(index).isAnyRule()) {
            return;
        }
        int anyIndex = indexOfAnyRule();
        if (anyIndex >= 0 && target >= anyIndex) {
            return;
        }
        ServerRule rule = serverRules.get(index);
        serverRules.remove(index);
        serverRules.add(target, rule);
        save();
    }

    /**
     * Repairs the "exactly one ANY rule, always last and always enabled" invariant.
     *
     * @return true when a new ANY rule had to be created
     */
    private boolean ensureAnyRule() {
        ServerRule any = null;
        for (ServerRule rule : serverRules) {
            if (!rule.isAnyRule()) {
                continue;
            }
            if (any == null) {
                any = rule;
            } else {
                rule.setMatchType(ServerRule.MatchType.EXACT);
                Opsec.LOGGER.warn(
                    "[OpSec] Found more than one ANY rule - demoting the surplus to an EXACT rule with an empty pattern"
                );
            }
        }
        boolean created = false;
        if (any == null) {
            any = new ServerRule(ServerRule.MatchType.ANY, "");
            created = true;
        }
        any.setEnabled(true);
        any.setPattern("");
        serverRules.remove(any);
        serverRules.add(any);
        return created;
    }

    private int indexOfAnyRule() {
        for (int i = 0; i < serverRules.size(); i++) {
            if (serverRules.get(i).isAnyRule()) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Snapshots whatever settings are currently active into an EXACT rule for the address
     * of the current connection, and makes that snapshot the active settings going forward.
     */
    public void saveCurrentAsServerRule() {
        if (!serverConnected || currentServer == null) {
            return;
        }
        for (ServerRule rule : serverRules) {
            if (rule.getMatchType() == ServerRule.MatchType.EXACT
                    && rule.getPattern().equalsIgnoreCase(currentServer)) {
                rule.copySettingsFrom(this.settings);
                this.activeRule = rule;
                refreshEffectiveSettings();
                save();
                return;
            }
        }
        ServerRule rule = new ServerRule(ServerRule.MatchType.EXACT, currentServer);
        rule.copySettingsFrom(this.settings);
        int anyIndex = indexOfAnyRule();
        if (anyIndex < 0) {
            serverRules.add(rule);
        } else {
            serverRules.add(anyIndex, rule);
        }
        this.activeRule = rule;
        refreshEffectiveSettings();
        save();
    }

    public void removeServerRuleForCurrentServer() {
        if (!serverConnected || currentServer == null) {
            return;
        }
        for (ServerRule rule : serverRules) {
            if (rule.getMatchType() == ServerRule.MatchType.EXACT
                    && rule.getPattern().equalsIgnoreCase(currentServer)) {
                serverRules.remove(rule);
                if (pendingRule == rule) {
                    pendingRule = null;
                }
                if (activeRule == rule) {
                    activeRule = null;
                }
                if (pinnedRule == rule) {
                    pinnedRule = null;
                    pinnedHost = null;
                    pinnedPort = 0;
                    pinConsumed = false;
                }
                refreshEffectiveSettings();
                save();
                return;
            }
        }
    }

    /** True when the currently-connected server is exempted from Auto-Purge Pack Cache On Exit. */
    public boolean isCurrentServerPackCacheTrusted() {
        return serverConnected && packCacheTrustedServers.contains(getCurrentServerKey());
    }

    /** Adds or removes the connected server from the pack-cache purge exemption list. */
    public void setCurrentServerPackCacheTrusted(boolean trusted) {
        if (!serverConnected) return;
        String key = getCurrentServerKey();
        if (key == null) return;
        if (trusted) {
            packCacheTrustedServers.add(key);
        } else {
            packCacheTrustedServers.remove(key);
        }
        save();
    }

    /** Snapshot of every server address currently exempted from Auto-Purge Pack Cache On Exit. */
    public Set<String> getPackCacheTrustedServers() {
        return Set.copyOf(packCacheTrustedServers);
    }

    // Identity protection
    /**
     * Whether the brand string should be overridden to "vanilla". Only true when
     * the user opted in via the UI toggle and ExploitPreventer isn't loaded.
     */
    public boolean shouldSpoofBrand() {
        return !EXPLOIT_PREVENTER_LOADED && settings.isSpoofAsVanilla();
    }

    /**
     * Whether channel spoofing/filtering should be active. Independent of brand —
     * channel filtering happens whenever OpSec is in charge (i.e., EP not loaded).
     * The filter mode (block-all vs whitelist) is chosen by isVanillaMode/
     * isFabricMode in SpoofSettings, which read directly from spoofAsVanilla.
     */
    public boolean shouldSpoofChannels() {
        return !EXPLOIT_PREVENTER_LOADED;
    }

    /** Same EP gate as {@link #shouldSpoofChannels()} — kept distinct so the two can diverge without churn. */
    public boolean shouldSpoofKnownPacks() {
        return !EXPLOIT_PREVENTER_LOADED;
    }

    public String getEffectiveBrand() {
        return settings.getEffectiveBrand();
    }

    // Resource pack protection
    public boolean shouldIsolatePackCache() {
        return !EXPLOIT_PREVENTER_LOADED && settings.isIsolatePackCache();
    }

    public boolean shouldBlockLocalPackUrls() {
        return !EXPLOIT_PREVENTER_LOADED && settings.isBlockLocalPackUrls();
    }

    /** Per-mod shader strip. Not EP-gated — EP lacks this defense, so OpSec keeps it active under EP. */
    public boolean shouldStripModShaders() {
        return settings.isStripModShaders();
    }

    /** True when any server-pack wrapping feature is active (whole-pack strip or per-mod shader strip). */
    public boolean shouldWrapServerPacks() {
        return shouldStripPack() || shouldStripModShaders();
    }

    // Key resolution protection
    public boolean isTranslationProtectionEnabled() {
        return (
            !EXPLOIT_PREVENTER_LOADED &&
            settings.isTranslationProtectionEnabled()
        );
    }

    public boolean isMeteorFix() {
        return settings.isMeteorFix();
    }

    // Bypass Server Pack Requirement
    public SpoofSettings.StripMode getPackStripMode() {
        return settings.getPackStripMode();
    }

    public boolean shouldStripPack() {
        return !EXPLOIT_PREVENTER_LOADED;
    }

    /** The consent overlay prompt should show for an incoming push. */
    public boolean shouldShowPackOverlay() {
        return (
            !EXPLOIT_PREVENTER_LOADED &&
            settings.getPackStripMode() == SpoofSettings.StripMode.ASK
        );
    }

    // Alerts and logging
    public boolean shouldShowAlerts() {
        return settings.isShowAlerts();
    }

    public boolean shouldShowToasts() {
        return settings.isShowToasts();
    }

    public boolean isLogDetections() {
        return settings.isLogDetections();
    }

    public boolean isDebugAlerts() {
        return settings.isDebugAlerts();
    }

    // Chat signing
    public SpoofSettings.SigningMode getSigningMode() {
        return settings.getSigningMode();
    }

    public boolean shouldNotSign() {
        return !CHAT_SIGNING_MANAGED_EXTERNALLY && settings.shouldNotSign();
    }

    // Privacy
    public boolean shouldDisableTelemetry() {
        return !TELEMETRY_MANAGED_EXTERNALLY && settings.isDisableTelemetry();
    }

    /** Whether clicking a server-sent copy-to-clipboard/run-command text should require confirmation first. */
    public boolean shouldGuardChatLinks() {
        return settings.isGuardChatLinks();
    }

    /**
     * Normalizes a server address by converting to lowercase and removing default port.
     * @param address The server address to normalize
     * @return Normalized address or "unknown" if null
     */
    public static String normalizeAddress(String address) {
        if (address == null) return "unknown";
        String normalized = address.toLowerCase().trim();
        if (normalized.endsWith(":25565")) {
            normalized = normalized.substring(0, normalized.length() - 6);
        }
        return normalized;
    }
}

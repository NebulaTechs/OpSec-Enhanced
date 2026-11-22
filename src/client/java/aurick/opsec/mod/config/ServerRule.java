package aurick.opsec.mod.config;

import com.google.gson.JsonObject;

import aurick.opsec.mod.Opsec;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * One entry of the ordered server-rule list.
 *
 * <p>A rule binds a <em>matcher</em> (the address the player typed) to a full set of
 * {@link SpoofSettings}. Rules are evaluated in list order and the first match wins, so
 * list position <em>is</em> the priority — there is no separate priority field to keep
 * out of sync with the order the user sees in the UI.</p>
 *
 * <p>The matcher input is the address the player typed (the hostname or IP literal they
 * entered in the connect screen), <strong>not</strong> whatever the connection ended up
 * resolving to. A player typing {@code mc.example.com} matches a rule for that domain
 * even when the connection goes through a proxy, is redirected by the server, or resolves
 * to a different address than it did yesterday. The resolved address is not an input at
 * all, so a rule for one IP cannot take over an unrelated hostname that happens to
 * resolve to it.</p>
 */
public class ServerRule {

    /** How a rule compares itself against the address the player typed. */
    public enum MatchType {
        /** The typed address must equal the pattern (optionally with {@code :port}). */
        EXACT,
        /** The pattern is a Java regex that must fully match the typed address. */
        REGEX,
        /** The pattern is an IP literal that must equal the typed address. */
        IP,
        /**
         * The mandatory global fallback rule. It matches every server, carries the
         * baseline settings used when no other rule hits, is always enabled, always
         * evaluated last and can never be deleted or reordered by the user.
         */
        ANY
    }

    private MatchType matchType = MatchType.EXACT;
    private String pattern = "";
    private boolean enabled = true;
    private final SpoofSettings settings = new SpoofSettings();

    public ServerRule() {
    }

    public ServerRule(MatchType matchType, String pattern) {
        this.matchType = matchType == null ? MatchType.EXACT : matchType;
        this.pattern = pattern == null ? "" : pattern.trim();
    }

    public MatchType getMatchType() {
        return matchType;
    }

    public void setMatchType(MatchType matchType) {
        this.matchType = matchType == null ? MatchType.EXACT : matchType;
        if (this.matchType == MatchType.ANY) {
            this.pattern = "";
        }
    }

    /** True when this rule is the global fallback rule. */
    public boolean isAnyRule() {
        return matchType == MatchType.ANY;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern == null ? "" : pattern.trim();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /** The settings this rule applies when it matches. */
    public SpoofSettings getSettings() {
        return settings;
    }

    /** Copies {@code source} into this rule's settings. */
    public void copySettingsFrom(SpoofSettings source) {
        if (source != null) {
            settings.copyFrom(source);
        }
    }

    /**
     * Tests this rule against one connection.
     *
     * <p>The comparison is made against the address the player typed, and against nothing
     * else. The resolved IP is deliberately not an input: a rule therefore describes
     * <em>the name the player connected to</em>, not the machine behind it. A hostname
     * the player typed keeps its own rule even when the connection is dialled through a
     * proxy, is redirected by the server, or resolves to a different address than it did
     * yesterday — and a rule written for one IP cannot silently take over an unrelated
     * hostname that happens to resolve to it.</p>
     *
     * @param host the address the player typed (hostname or IP literal), may be null
     * @param port the port the player connected to, {@code 0} when unknown
     * @return true when this rule applies to that connection
     */
    public boolean matches(String host, int port) {
        if (!enabled) {
            return false;
        }
        if (matchType == MatchType.ANY) {
            return true;
        }
        for (String p : splitPatterns(pattern)) {
            boolean hit = switch (matchType) {
                case EXACT -> matchesExact(p, host, port);
                case REGEX -> matchesRegex(p, host);
                case IP -> matchesIp(p, host);
                case ANY -> true;
            };
            if (hit) {
                return true;
            }
        }
        return false;
    }

    /**
     * Splits a comma-separated pattern field into the individual patterns it holds.
     *
     * <p>Commas at brace/paren/bracket depth zero separate patterns; commas nested in a
     * regex quantifier such as {@code a{1,3}} do not. A literal comma inside a regex is
     * written {@code \x2c} — the Java-regex escape for {@code ,} — which contains no
     * literal comma and therefore never acts as a separator.</p>
     */
    public static List<String> splitPatterns(String raw) {
        List<String> out = new ArrayList<>();
        if (raw == null) {
            return out;
        }
        int depth = 0;
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\\' && i + 1 < raw.length()) {
                current.append(c).append(raw.charAt(++i));
                continue;
            }
            if (c == '{' || c == '(' || c == '[') {
                depth++;
            } else if ((c == '}' || c == ')' || c == ']') && depth > 0) {
                depth--;
            }
            if (c == ',' && depth == 0) {
                addPattern(out, current);
            } else {
                current.append(c);
            }
        }
        addPattern(out, current);
        return out;
    }

    private static void addPattern(List<String> out, StringBuilder current) {
        String value = current.toString().trim();
        current.setLength(0);
        if (!value.isEmpty()) {
            out.add(value);
        }
    }

    private static boolean matchesExact(String p, String host, int port) {
        String wantHost = p;
        int wantPort = -1;
        int colon = p.lastIndexOf(':');
        // "host:port" — but not the colons inside a bare IPv6 literal, and not the
        // colon of a bracketed IPv6 literal ("[::1]:25565" splits after the bracket).
        boolean bracketed = p.indexOf(']') >= 0;
        boolean bareIpv6 = !bracketed && isIpv6Literal(p);
        if (colon > 0 && !bareIpv6 && (!bracketed || p.indexOf(']') < colon)) {
            String portPart = p.substring(colon + 1);
            try {
                wantPort = Integer.parseInt(portPart);
                wantHost = p.substring(0, colon);
            } catch (NumberFormatException ignored) {
                // Not a port — treat the whole pattern as the host.
            }
        }
        if (wantHost.startsWith("[") && wantHost.endsWith("]")) {
            wantHost = wantHost.substring(1, wantHost.length() - 1);
        }
        if (wantPort > 0 && port > 0 && wantPort != port) {
            return false;
        }
        String typed = normalize(host);
        return !typed.isEmpty() && typed.equalsIgnoreCase(wantHost);
    }

    private static boolean matchesRegex(String p, String host) {
        Pattern compiled;
        try {
            compiled = Pattern.compile(p);
        } catch (PatternSyntaxException e) {
            // A broken pattern must not take the whole rule list down — it simply
            // never matches. The UI surfaces the compile error when the user edits it.
            return false;
        }
        String typed = normalize(host);
        return !typed.isEmpty() && compiled.matcher(typed).matches();
    }

    /**
     * Matches an IP-literal pattern against the address the player typed.
     *
     * <p>No fallback to the resolved address: a rule written for one IP must not take
     * over a hostname that happens to resolve to it.</p>
     */
    private static boolean matchesIp(String p, String host) {
        String want = normalize(p);
        if (want.isEmpty()) {
            return false;
        }
        String typed = normalize(host);
        return !typed.isEmpty() && typed.equals(want);
    }

    /** Lower-cases and strips the brackets of an IPv6 literal; returns "" for null/blank. */
    private static String normalize(String value) {
        if (value == null) {
            return "";
        }
        String v = value.trim().toLowerCase(Locale.ROOT);
        if (v.startsWith("[") && v.endsWith("]")) {
            v = v.substring(1, v.length() - 1);
        }
        return v;
    }

    /**
     * Tests whether a value is an IP literal rather than a hostname.
     *
     * <p>Used when migrating the legacy per-server profile map, whose keys were the
     * resolved address of the server: an IP-shaped key has to become an IP rule,
     * because an EXACT rule compares against the name the player typed and would
     * never see the address the profile was saved under.</p>
     */
    public static boolean isIpLiteral(String value) {
        String v = normalize(value);
        if (v.isEmpty()) {
            return false;
        }
        return isIpv4Literal(v) || isIpv6Literal(v);
    }

    /** True for a dotted-quad IPv4 address. */
    private static boolean isIpv4Literal(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            int octet = 0;
            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);
                if (c < '0' || c > '9') {
                    return false;
                }
                octet = octet * 10 + (c - '0');
            }
            if (octet > 255) {
                return false;
            }
        }
        return true;
    }

    /**
     * True for a bare IPv6 literal such as {@code 2001:db8::1}.
     *
     * <p>A {@code host:port} pattern carries exactly one colon, so a second colon is
     * what separates the two forms. The remaining characters are restricted to the
     * ones an IPv6 literal may contain, which keeps a malformed pattern such as
     * {@code example.com:25565:99} from being mistaken for an address.</p>
     */
    static boolean isIpv6Literal(String value) {
        if (value == null) {
            return false;
        }
        String v = value.trim();
        int first = v.indexOf(':');
        if (first < 0 || v.indexOf(':', first + 1) < 0) {
            return false;
        }
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            boolean allowed = (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F')
                    || c == ':' || c == '.' || c == '%';
            if (!allowed) {
                return false;
            }
        }
        return true;
    }

    public JsonObject toJson() {
        JsonObject json = new JsonObject();
        json.addProperty("matchType", matchType.name());
        json.addProperty("pattern", pattern);
        json.addProperty("enabled", enabled);
        json.add("settings", settings.toJson());
        return json;
    }

    public static ServerRule fromJson(JsonObject json) {
        ServerRule rule = new ServerRule();
        if (json.has("matchType")) {
            String raw = JsonSafe.str(json, "matchType", "");
            try {
                rule.matchType = MatchType.valueOf(raw.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                // A rule whose match type changes silently stops matching what the user wrote.
                Opsec.LOGGER.warn(
                    "[OpSec] Unknown server rule match type '{}' - treating the rule as EXACT",
                    raw
                );
                rule.matchType = MatchType.EXACT;
            }
        }
        if (json.has("pattern")) {
            rule.pattern = JsonSafe.str(json, "pattern", "");
        }
        if (json.has("enabled")) {
            rule.enabled = JsonSafe.bool(json, "enabled", true);
        }
        if (rule.matchType == MatchType.ANY) {
            // The ANY rule is structurally always-on and pattern-less: a hand-edited
            // config must not be able to disable it or give it a pattern.
            rule.pattern = "";
            rule.enabled = true;
        }
        JsonObject settingsJson = JsonSafe.obj(json, "settings");
        if (settingsJson != null) {
            rule.settings.copyFrom(SpoofSettings.fromJson(settingsJson));
        }
        return rule;
    }
}

package aurick.opsec.mod.config;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Type-safe reads for the config file.
 *
 * <p>The config file is user-editable and travels between builds, so every value in
 * it is untrusted input. Gson's {@code getAsBoolean()} and friends throw on a value
 * of the wrong shape — an object where a boolean belongs, a string where a number
 * belongs — and the loader runs from the config constructor, so an escaping
 * exception there is a crash on client start with the user's settings still on
 * disk and unreadable.</p>
 *
 * <p>These readers answer with a fallback instead of throwing, so one bad field
 * costs the user that field and nothing else.</p>
 */
final class JsonSafe {

    private JsonSafe() {
    }

    /** True when the value is a primitive that can be read as a boolean. */
    static boolean bool(JsonObject json, String key, boolean fallback) {
        JsonElement element = json.get(key);
        if (element == null || !element.isJsonPrimitive()) {
            return fallback;
        }
        try {
            return element.getAsBoolean();
        } catch (RuntimeException e) {
            return fallback;
        }
    }

    /** The value as a string, or the fallback when it is missing or not a primitive. */
    static String str(JsonObject json, String key, String fallback) {
        JsonElement element = json.get(key);
        if (element == null || !element.isJsonPrimitive()) {
            return fallback;
        }
        try {
            return element.getAsString();
        } catch (RuntimeException e) {
            return fallback;
        }
    }

    /** The value as an int, or the fallback when it is missing or not a number. */
    static int i32(JsonObject json, String key, int fallback) {
        JsonElement element = json.get(key);
        if (element == null || !element.isJsonPrimitive()) {
            return fallback;
        }
        try {
            return element.getAsInt();
        } catch (RuntimeException e) {
            return fallback;
        }
    }

    /** The value as an object, or null when it is missing or not an object. */
    static JsonObject obj(JsonObject json, String key) {
        JsonElement element = json.get(key);
        if (element == null || !element.isJsonObject()) {
            return null;
        }
        return element.getAsJsonObject();
    }

    /** The value as an array, or null when it is missing or not an array. */
    static JsonArray arr(JsonObject json, String key) {
        JsonElement element = json.get(key);
        if (element == null || !element.isJsonArray()) {
            return null;
        }
        return element.getAsJsonArray();
    }

    /** The value as an array of objects, skipping the entries that are not objects. */
    static java.util.List<JsonObject> objArray(JsonObject json, String key) {
        JsonArray array = arr(json, key);
        if (array == null) {
            return java.util.Collections.emptyList();
        }
        java.util.List<JsonObject> out = new java.util.ArrayList<>(array.size());
        for (JsonElement element : array) {
            if (element != null && element.isJsonObject()) {
                out.add(element.getAsJsonObject());
            }
        }
        return out;
    }

    /** The array as a list of strings, skipping the entries that are not primitives. */
    static java.util.List<String> stringList(JsonObject json, String key) {
        JsonArray array = arr(json, key);
        if (array == null) {
            return java.util.Collections.emptyList();
        }
        java.util.List<String> out = new java.util.ArrayList<>(array.size());
        for (JsonElement element : array) {
            if (element != null && element.isJsonPrimitive()) {
                try {
                    out.add(element.getAsString());
                } catch (RuntimeException e) {
                    continue;
                }
            }
        }
        return out;
    }
}

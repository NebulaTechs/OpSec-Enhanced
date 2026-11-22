package aurick.opsec.mod;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Stand-in for the mod entry point: only the logger is reached from the config model. */
public final class Opsec {

    public static final Logger LOGGER = LoggerFactory.getLogger("OpSec");

    private Opsec() {
    }
}

package aurick.opsec.mod.mixin.client;

import aurick.opsec.mod.config.OpsecConfig;
import net.minecraft.client.gui.screens.ConnectScreen;
import net.minecraft.client.gui.screens.Screen;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Discards the rule of a connection attempt that ended without a login.
 *
 * <p>The rule of the server the player is trying to join is picked before the connection
 * is opened, so that the packets that go out during the handshake already carry the
 * server's own settings. When the attempt fails -- the host does not resolve, the
 * connection is refused, the handshake times out -- or the player cancels it, no login
 * ever happens and nothing else would drop that rule: it would stay in effect while the
 * client sits on the multiplayer screen, and a background server-list ping would read it
 * as if it belonged to the pinged server.</p>
 *
 * <p>The connect screen is the one place that knows an attempt is over: it is removed
 * when the attempt fails and when the player cancels, and on a successful join the rule
 * has already been taken over by the connected server before the screen goes away.</p>
 */
@Mixin(Screen.class)
public abstract class ScreenMixin {

    @Inject(method = "removed", at = @At("HEAD"))
    private void opsec$discardConnectionAttempt(CallbackInfo ci) {
        Object self = this;
        if (self instanceof ConnectScreen) {
            OpsecConfig.getInstance().clearPendingRule();
        }
    }
}

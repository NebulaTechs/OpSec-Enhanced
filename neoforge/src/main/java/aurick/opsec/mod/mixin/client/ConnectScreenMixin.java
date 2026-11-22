package aurick.opsec.mod.mixin.client;

import aurick.opsec.mod.config.OpsecConfig;
import aurick.opsec.mod.detection.TrackPackDetector;
import aurick.opsec.mod.protection.TranslationProtectionHandler;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screens.ConnectScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.client.multiplayer.TransferState;
import net.minecraft.client.multiplayer.resolver.ServerAddress;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Resets detection state when connecting to a new server, and selects the server rule
 * that applies to the address the player is about to connect to.
 *
 * <p>Previously this mixin also pre-initialised profile keys for the ON_DEMAND
 * signing mode (so the keys would be ready if the server required secure chat
 * mid-session). That path was removed when ON_DEMAND was deleted — the SIGN
 * mode lets vanilla MC's own key-pair lifecycle handle this naturally.</p>
 */
@Mixin(ConnectScreen.class)
public class ConnectScreenMixin {

    @Inject(method = "startConnecting", at = @At("HEAD"))
    private static void opsec$resetState(CallbackInfo ci) {
        TrackPackDetector.reset();
        TranslationProtectionHandler.clearCache();
    }

    @Inject(method = "startConnecting", at = @At("HEAD"))
    private static void opsec$selectRule(Screen parent, Minecraft minecraft, ServerAddress address, ServerData data,
            boolean isQuickPlay, TransferState transferState, CallbackInfo ci) {
        opsec$selectRuleFor(address, transferState != null);
    }

    /**
     * Selects the rule for the connection attempt that is about to start.
     *
     * <p>Only the typed address is known here. The resolved address is not known yet
     * and is applied later by the handshake-listener mixin.</p>
     */
    @Unique
    private static void opsec$selectRuleFor(ServerAddress address, boolean transferred) {
        if (address == null) {
            return;
        }
        OpsecConfig.getInstance().beginConnectionAttempt(address.getHost(), address.getPort(), transferred);
    }
}

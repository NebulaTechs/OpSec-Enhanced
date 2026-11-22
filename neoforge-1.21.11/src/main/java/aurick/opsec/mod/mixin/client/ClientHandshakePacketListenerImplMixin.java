package aurick.opsec.mod.mixin.client;

import aurick.opsec.mod.config.OpsecConfig;
import aurick.opsec.mod.net.ServerTargets;
import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.network.Connection;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Re-resolves the server rule once the connection's address is known.
 *
 * <p>The rule picked when the player presses "join" is matched against the address they
 * typed. By the time the handshake listener is built the address has been resolved and
 * bound to the connection, so the rule can be matched again -- against the typed address,
 * which is the only thing a rule is matched against -- and the match has to happen here,
 * because the packets that go out during the handshake (the client information, the
 * client brand) are read from the active settings and would otherwise still see the
 * global baseline.</p>
 *
 * <p>The handshake listener is the earliest point that satisfies both requirements: the
 * address is already resolved, and only a real game connection ever builds one -- a
 * background server-list ping never does, so a ping can never select a rule for a
 * server the player did not choose to join.</p>
 */
@Mixin(ClientHandshakePacketListenerImpl.class)
public abstract class ClientHandshakePacketListenerImplMixin {

    @Shadow
    @Final
    private Connection connection;

    @Inject(method = "<init>", at = @At("TAIL"))
    private void opsec$resolveRule(CallbackInfo ci) {
        ServerTargets.Target target = ServerTargets.boundTo(this.connection);
        if (target == null) {
            return;
        }
        OpsecConfig.getInstance().selectRuleFor(target.host(), target.port());
    }
}

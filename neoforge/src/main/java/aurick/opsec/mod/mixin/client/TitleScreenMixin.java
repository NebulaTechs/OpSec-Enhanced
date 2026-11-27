package aurick.opsec.mod.mixin.client;

import aurick.opsec.mod.config.JarIntegrityChecker;
import aurick.opsec.mod.config.LegacyProfileWarningScreen;
import aurick.opsec.mod.config.OpsecConfig;
import aurick.opsec.mod.config.TamperWarningScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.gui.screens.TitleScreen;
import net.minecraft.network.chat.Component;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Polls the jar integrity check on the title screen and shows the tamper
 * warning as soon as the async check completes with a mismatch.
 */
@Mixin(TitleScreen.class)
public abstract class TitleScreenMixin extends Screen {

    @Unique private boolean opsec$integrityHandled = false;

    @Unique private boolean opsec$legacyMigrationHandled = false;

    protected TitleScreenMixin(Component title) {
        super(title);
    }

    @Inject(method = "tick", at = @At("TAIL"))
    private void opsec$pollIntegrityCheck(CallbackInfo ci) {
        if (!opsec$integrityHandled && JarIntegrityChecker.isCheckComplete()) {
            opsec$integrityHandled = true;
            if (this.minecraft != null && JarIntegrityChecker.isTamperDetected()) {
                JarIntegrityChecker.markShown();
                //? if >=26.2 {
                /*this.minecraft.setScreenAndShow(new TamperWarningScreen(this));*/
                //?} else {
                this.minecraft.setScreen(new TamperWarningScreen(this));
                //?}
                return;
            }
        }
        if (opsec$legacyMigrationHandled || this.minecraft == null) {
            return;
        }
        opsec$legacyMigrationHandled = true;
        if (OpsecConfig.getInstance().hasPendingLegacyMigration()) {
            //? if >=26.2 {
            /*this.minecraft.setScreenAndShow(new LegacyProfileWarningScreen(this));*/
            //?} else {
            this.minecraft.setScreen(new LegacyProfileWarningScreen(this));
            //?}
        }
    }
}

package aurick.opsec.mod.config;

import aurick.opsec.mod.lang.OpsecLang;
import aurick.opsec.mod.lang.OpsecStrings;
//? if <1.20.2
/*import net.minecraft.client.gui.GuiGraphics;*/
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.StringWidget;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;

import java.util.List;

/**
 * Shown at startup when the legacy per-server profile map held profiles that were
 * saved under a resolved IP address. Per-server rules match the address the player
 * types, so those profiles would silently stop applying — the user decides whether
 * to convert them into IP rules or to leave them out and keep the original file.
 */
public class LegacyProfileWarningScreen extends Screen {

    private static final int MAX_LISTED = 5;

    private final Screen parent;

    public LegacyProfileWarningScreen(Screen parent) {
        super(Component.literal(OpsecLang.tr(OpsecStrings.LEGACY_MIGRATION_TITLE)));
        this.parent = parent;
    }

    @Override
    protected void init() {
        int centerX = this.width / 2;
        int textLineHeight = 14;
        int buttonWidth = 200;
        int buttonHeight = 20;
        int buttonSpacing = 24;
        int textToButtonGap = 14;

        List<String> addresses = OpsecConfig.getInstance().getPendingLegacyProfileAddresses();
        int listed = Math.min(addresses.size(), MAX_LISTED);
        boolean hasMore = addresses.size() > MAX_LISTED;

        int textLines = 5 + listed + (hasMore ? 1 : 0);
        int totalHeight = textLineHeight * textLines + textToButtonGap + buttonSpacing + buttonHeight;
        int startY = (this.height - totalHeight) / 2;

        int y = startY;
        addCenteredStringWidget(this.title, centerX, y);
        y += textLineHeight;
        addCenteredStringWidget(Component.literal(OpsecLang.tr(OpsecStrings.LEGACY_MIGRATION_WARNING)), centerX, y);
        y += textLineHeight;
        addCenteredStringWidget(Component.literal(OpsecLang.tr(OpsecStrings.LEGACY_MIGRATION_AFFECTED)), centerX, y);
        y += textLineHeight;
        for (int i = 0; i < listed; i++) {
            addCenteredStringWidget(
                    Component.literal(OpsecLang.tr(OpsecStrings.LEGACY_MIGRATION_ENTRY, addresses.get(i))),
                    centerX, y
            );
            y += textLineHeight;
        }
        if (hasMore) {
            addCenteredStringWidget(
                    Component.literal(OpsecLang.tr(OpsecStrings.LEGACY_MIGRATION_MORE, addresses.size() - MAX_LISTED)),
                    centerX, y
            );
            y += textLineHeight;
        }
        addCenteredStringWidget(Component.literal(OpsecLang.tr(OpsecStrings.LEGACY_MIGRATION_BACKUP_EXPLAIN)), centerX, y);
        y += textLineHeight;
        addCenteredStringWidget(Component.literal(OpsecLang.tr(OpsecStrings.LEGACY_MIGRATION_UPGRADE_EXPLAIN)), centerX, y);
        y += textLineHeight + textToButtonGap;

        this.addRenderableWidget(Button.builder(Component.literal(OpsecLang.tr(OpsecStrings.LEGACY_MIGRATION_BACKUP)), button -> {
            OpsecConfig.getInstance().acceptLegacyProfileBackup();
            this.onClose();
        }).bounds(centerX - buttonWidth / 2, y, buttonWidth, buttonHeight).build());

        this.addRenderableWidget(Button.builder(Component.literal(OpsecLang.tr(OpsecStrings.LEGACY_MIGRATION_UPGRADE)), button -> {
            OpsecConfig.getInstance().acceptLegacyProfileUpgrade();
            this.onClose();
        }).bounds(centerX - buttonWidth / 2, y + buttonSpacing, buttonWidth, buttonHeight).build());
    }

    private void addCenteredStringWidget(Component text, int centerX, int y) {
        int textWidth = this.font.width(text);
        this.addRenderableWidget(new StringWidget(centerX - textWidth / 2, y, textWidth, 10, text, this.font));
    }

    //? if <1.20.2 {
    /*@Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        // 1.20.1 Screen.render does not auto-call renderBackground.
        this.renderBackground(graphics);
        super.render(graphics, mouseX, mouseY, partialTick);
    }
    *///?}

    @Override
    public void onClose() {
        //? if >=26.2 {
        /*this.minecraft.setScreenAndShow(this.parent);*/
        //?} else {
        this.minecraft.setScreen(this.parent);
        //?}
    }
}

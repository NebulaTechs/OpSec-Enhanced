package aurick.opsec.mod.config;

import aurick.opsec.mod.lang.OpsecLang;
import aurick.opsec.mod.lang.OpsecStrings;
import java.util.ArrayList;
import java.util.List;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.StringWidget;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.CommonComponents;
import net.minecraft.network.chat.Component;

/**
 * The top-level OpSec screen.
 *
 * <p>It only routes: every settings surface lives in its own screen below it, so
 * nothing here can leak state between the rule editor and the account manager. The
 * connection line is informational — it tells the user which server the currently
 * active rule applies to without making the hub an editing surface.</p>
 */
public class OpsecHubScreen extends Screen implements OpsecScreens.Marker {

    private final Screen parent;
    private final OpsecConfig config;

    public OpsecHubScreen(Screen parent) {
        super(OpsecLang.component(OpsecStrings.SCREEN_HUB_TITLE));
        this.parent = parent;
        this.config = OpsecConfig.getInstance();
    }

    @Override
    protected void init() {
        int y = 40;

        if (config.hasPendingLegacyMigration()) {
            y = addCard(y, OpsecStrings.HUB_LEGACY_DECISION, OpsecStrings.HUB_LEGACY_DECISION_DESC,
                    () -> show(new LegacyProfileWarningScreen(this)));
        }

        y = addCard(y, OpsecStrings.HUB_RULE_SETTINGS, OpsecStrings.HUB_RULE_SETTINGS_DESC, () -> {
            ServerRule rule = config.getActiveRule();
            if (rule == null) {
                rule = config.getAnyRule();
            }
            show(RuleSettingsScreen.create(this, rule));
        });

        y = addCard(y, OpsecStrings.HUB_ACCOUNT_MANAGER, OpsecStrings.HUB_ACCOUNT_MANAGER_DESC,
                () -> show(new AccountManagerScreen(this)));

        addCard(y, OpsecStrings.HUB_SETTINGS, OpsecStrings.HUB_SETTINGS_DESC,
                () -> show(SettingsScreen.create(this)));

        // Connection state — read-only. The rule editor is where settings change.
        List<String> details = new ArrayList<>();
        if (config.hasActiveServer()) {
            String ip = config.getCurrentServerIp();
            if (ip != null && !ip.isEmpty()) {
                details.add(OpsecLang.tr(OpsecStrings.HUB_RESOLVED, ip));
            }
            details.add(OpsecLang.tr(OpsecStrings.HUB_EFFECTIVE_RULE, effectiveRuleLabel()));
        }
        String statusText = config.hasActiveServer()
                ? OpsecLang.tr(OpsecStrings.HUB_CONNECTED, config.getCurrentServer())
                : OpsecLang.tr(OpsecStrings.HUB_NOT_CONNECTED);

        int buttonY = this.height - 28;
        int lineY = buttonY - 12;
        for (int i = details.size() - 1; i >= 0; i--) {
            this.addRenderableWidget(centeredText(details.get(i), lineY));
            lineY -= 12;
        }
        this.addRenderableWidget(centeredText(statusText, lineY));

        this.addRenderableWidget(Button.builder(CommonComponents.GUI_DONE, button -> this.onClose())
                .bounds(this.width / 2 - 100, buttonY, 200, 20)
                .build());
    }

    private String effectiveRuleLabel() {
        ServerRule effective = config.getActiveRule();
        if (effective == null || effective.isAnyRule()) {
            return OpsecLang.tr(OpsecStrings.HUB_RULE_GLOBAL);
        }
        return effective.getMatchType().name() + " " + effective.getPattern();
    }

    private StringWidget centeredText(String text, int y) {
        StringWidget widget = new StringWidget(this.font.width(text), 10,
                Component.literal(text), this.font);
        widget.setX(this.width / 2 - widget.getWidth() / 2);
        widget.setY(y);
        return widget;
    }

    private int addCard(int y, String titleKey, String descriptionKey, Runnable action) {
        int centerX = this.width / 2;
        int cardWidth = Math.max(150, Math.min(240, this.width - 40));
        int cardX = centerX - cardWidth / 2;

        this.addRenderableWidget(Button.builder(OpsecLang.component(titleKey), button -> action.run())
                .bounds(cardX, y, cardWidth, 24)
                .build());

        String description = OpsecLang.tr(descriptionKey);
        StringWidget descriptionWidget = new StringWidget(this.font.width(description), 10,
                Component.literal(description), this.font);
        descriptionWidget.setX(centerX - descriptionWidget.getWidth() / 2);
        descriptionWidget.setY(y + 27);
        this.addRenderableWidget(descriptionWidget);

        return y + 48;
    }

    private static void show(Screen screen) {
        //? if >=26.2 {
        Minecraft.getInstance().setScreenAndShow(screen);
        //?} else {
        /*Minecraft.getInstance().setScreen(screen);
        *///?}
    }

    @Override
    public void onClose() {
        config.save();
        //? if >=26.2 {
        this.minecraft.setScreenAndShow(parent);
        //?} else {
        /*this.minecraft.setScreen(parent);
        *///?}
    }

    /** The Minecraft client, for callers that need it. */
    public static Minecraft client() {
        return Minecraft.getInstance();
    }
}

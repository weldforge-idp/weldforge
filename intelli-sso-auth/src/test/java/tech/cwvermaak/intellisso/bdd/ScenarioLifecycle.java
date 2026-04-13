package tech.cwvermaak.intellisso.bdd;

import io.cucumber.java.Before;

/**
 * Cucumber hook that gives every scenario a fresh {@link TestWorld}. Step
 * definition classes declare {@link TestWorld} in their constructor and
 * Cucumber's default object factory injects it — Cucumber keeps one
 * instance per scenario so the steps share it.
 *
 * This class itself does nothing but exists to document the lifecycle and
 * give us a seam to grow into if we ever need before/after hooks.
 */
public class ScenarioLifecycle {

    private final TestWorld world;

    public ScenarioLifecycle(TestWorld world) {
        this.world = world;
    }

    @Before
    public void beforeEachScenario() {
        // Nothing yet — TestWorld is instantiated fresh per scenario by
        // Cucumber, so we don't need to reset state explicitly.
    }
}

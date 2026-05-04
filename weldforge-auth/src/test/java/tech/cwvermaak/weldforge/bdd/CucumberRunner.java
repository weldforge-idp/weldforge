package tech.cwvermaak.weldforge.bdd;

import org.junit.platform.suite.api.ConfigurationParameter;
import org.junit.platform.suite.api.IncludeEngines;
import org.junit.platform.suite.api.SelectClasspathResource;
import org.junit.platform.suite.api.Suite;

import static io.cucumber.junit.platform.engine.Constants.GLUE_PROPERTY_NAME;
import static io.cucumber.junit.platform.engine.Constants.PLUGIN_PROPERTY_NAME;

/**
 * Entry point that runs every {@code .feature} file under
 * {@code src/test/resources/features} via JUnit 5's Platform Suite engine.
 *
 * Because this is picked up by Surefire, a single {@code mvn verify} runs
 * both the unit tests and the BDD scenarios — which is exactly what the
 * CI workflow gates releases on.
 */
@Suite
@IncludeEngines("cucumber")
@SelectClasspathResource("features")
@ConfigurationParameter(key = GLUE_PROPERTY_NAME, value = "tech.cwvermaak.weldforge.bdd")
@ConfigurationParameter(key = PLUGIN_PROPERTY_NAME,
        value = "pretty, summary, html:target/cucumber-reports/cucumber.html")
public class CucumberRunner {
}

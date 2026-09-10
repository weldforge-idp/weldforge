package testfixtures.web;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * An {@code /api/**} endpoint with a required input, for making a request
 * validation failure in standalone MockMvc tests.
 *
 * <p>Request-parameter validation rather than bean validation: the build has
 * {@code jakarta.validation-api} but no provider, so {@code @Valid} is not
 * enforced anywhere in this service.
 *
 * <p>Deliberately outside {@code tech.cwvermaak.weldforge}: the
 * {@code @SpringBootTest} integration contexts component-scan that package on
 * the test classpath too, and would otherwise register this as a real endpoint.
 */
@RestController
public class ValidatingController {

    @PostMapping("/api/fixture/users")
    public String create(@RequestParam("email") String email) {
        return "created";
    }
}

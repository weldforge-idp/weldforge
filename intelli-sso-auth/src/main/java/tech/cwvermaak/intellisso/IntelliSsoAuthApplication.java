package tech.cwvermaak.intellisso;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class IntelliSsoAuthApplication {

    public static void main(String[] args) {
        // Load .env file if it exists, but don't fail if it doesn't.
        // This allows for local development with .env and Docker-based deployment without it.
        Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();
        dotenv.entries().forEach(entry -> System.setProperty(entry.getKey(), entry.getValue()));

        SpringApplication.run(IntelliSsoAuthApplication.class, args);
    }

}

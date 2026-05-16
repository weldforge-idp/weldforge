# ============================================================
# Multi-stage build: JDK 25 compile → JRE 25 runtime.
# Non-root user, health check, and optimised layer caching.
# ============================================================

# --- Build stage ---
FROM bellsoft/liberica-openjdk-debian:25 AS build
WORKDIR /app

# Cache Maven dependencies before copying source
COPY pom.xml ./
COPY .mvn .mvn
COPY mvnw ./
RUN chmod +x mvnw && ./mvnw dependency:go-offline -B -ntp 2>/dev/null || true

# Copy source and build
COPY src src
RUN ./mvnw clean package -DskipTests -B -ntp

# --- Runtime stage ---
FROM bellsoft/liberica-openjre-debian:25

LABEL org.opencontainers.image.source="https://github.com/weldforge-idp/weldforge"

# Security: run as non-root
RUN groupadd -r sso && useradd -r -g sso -d /app -s /sbin/nologin sso
WORKDIR /app

COPY --from=build /app/target/weldforge-auth-*.jar app.jar
RUN chown -R sso:sso /app

USER sso

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -sf http://localhost:8080/actuator/health/liveness || exit 1

ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]

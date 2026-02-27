FROM bellsoft/liberica-openjdk-debian:21 AS build
WORKDIR /app
COPY . .
RUN ./mvnw clean package -DskipTests

FROM bellsoft/liberica-openjre-debian:21
WORKDIR /app
COPY --from=build /app/target/intelli-sso-auth-*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
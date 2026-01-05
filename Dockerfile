FROM eclipse-temurin:17-jdk-jammy as build

WORKDIR /app

# Copy Maven wrapper and configuration
COPY mvnw mvnw
COPY .mvn .mvn
COPY pom.xml .

# Download dependencies (optional but speeds up subsequent builds)
RUN ./mvnw -q -B -DskipTests dependency:go-offline || true

# Copy source and build the application
COPY src src
RUN ./mvnw -q -B -DskipTests package

# Runtime image
FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

# Copy the built jar from the build stage
COPY --from=build /app/target/*.jar app.jar

# Expose the auth-service port (matches server.port default 8082)
EXPOSE 8082

ENTRYPOINT ["java","-jar","/app/app.jar"]


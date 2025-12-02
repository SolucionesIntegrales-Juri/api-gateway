# Etapa 1: Construcción del JAR
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app

COPY pom.xml .
RUN mvn -q -e -DskipTests dependency:resolve

COPY src ./src
RUN mvn -q -e -DskipTests package

# Etapa 2: Imagen ligera para producción
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

# Railway inyecta PORT automáticamente
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]

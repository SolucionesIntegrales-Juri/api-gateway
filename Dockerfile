FROM maven:3.8.8-openjdk-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn -B -DskipTests package

FROM eclipse-temurin:17-jre
ARG JAR_FILE=target/*.jar
COPY --from=build /app/${JAR_FILE} /app/app.jar
ENTRYPOINT ["java","-jar","/app/app.jar"]
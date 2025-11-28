# Imagen JDK para ejecutar Spring Boot
FROM eclipse-temurin:17-jdk-alpine AS runtime

# Crear directorio de la app
WORKDIR /app

# Copiar el JAR generado por Spring Boot
COPY target/*.jar app.jar

# Configurar puerto (Railway o Docker lo sobrescriben igual)
EXPOSE 8080

# Ejecutar el microservicio
ENTRYPOINT ["java", "-jar", "app.jar"]

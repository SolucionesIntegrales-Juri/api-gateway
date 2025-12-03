# Usa una imagen de Java runtime
FROM eclipse-temurin:17-jre-alpine

# Crea el directorio de la app
WORKDIR /app

# Copia el jar compilado al contenedor
COPY target/*.jar app.jar

# Expone el puerto (ajusta al utilizado por tu app)
EXPOSE 8080

# Comando de ejecución con archivo jar
ENTRYPOINT ["java", "-jar", "app.jar"]
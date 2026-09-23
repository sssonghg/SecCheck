FROM eclipse-temurin:21-jdk

WORKDIR /app

COPY . .

RUN chmod +x gradlew
RUN ./gradlew bootJar --no-daemon

EXPOSE 8083

CMD ["java", "-jar", "build/libs/sql-vuln-app-0.0.1-SNAPSHOT.jar"]

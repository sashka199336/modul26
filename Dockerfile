 
FROM eclipse-temurin:21-jdk AS build

WORKDIR /app
 
COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .
RUN chmod +x mvnw
RUN ./mvnw dependency:go-offline
 
COPY . .
RUN chmod +x mvnw  
RUN ./mvnw clean package -DskipTests
COPY . .
 
 
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java","-jar","/app/app.jar"]

# Sử dụng JDK 17 làm base image
FROM openjdk:17-jdk

# Đặt thư mục làm việc trong container
WORKDIR /app

# Sao chép file JAR vào container
COPY target/gateway-1.0-SNAPSHOT.jar app.jar

# Mở cổng 8080 cho API Gateway
EXPOSE 8080

# Chạy ứng dụng Spring Boot
ENTRYPOINT ["java", "-jar", "app.jar"]

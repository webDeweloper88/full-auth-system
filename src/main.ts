import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule); // Создание экземпляра приложения NestJS на основе модуля AppModule
  const config = app.get(ConfigService); // Получение сервиса конфигурации для доступа к переменным окружения
  const port = config.getOrThrow<number>('APP_PORT');
  // app.setGlobalPrefix('api') // Установка глобального префикса для всех маршрутов приложения

  app.useGlobalPipes(
    // Установка глобальных пайпов для валидации и трансформации входящих данных
    new ValidationPipe({
      // Пайп для валидации входящих данных
      transform: true, // Автоматическое преобразование входящих данных в DTO
      whitelist: true, // Удаление свойств, не указанных в DTO
      forbidNonWhitelisted: true, // Запрет на передачу неразрешенных свойств
    }),
  );
  app.enableCors({
    origin: config.getOrThrow<string>('CORS_ORIGIN'), // Разрешенный источник CORS
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE', // Разрешенные методы
    credentials: true, // Разрешение на использование учетных данных
  });

  const configSwager = new DocumentBuilder()
    .setTitle('NestJS API') // Заголовок документации Swagger
    .setDescription('API documentation for NestJS application') // Описание документации Swagger
    .setVersion('1.0') // Версия API
    .addBearerAuth() // Добавление поддержки Bearer токенов
    .build();
  const document = SwaggerModule.createDocument(app, configSwager); // Создание документации Swagger на основе приложения
  SwaggerModule.setup('api', app, document); // Настройка маршрута для доступа к документации Swagger

  await app.listen(port); // Запуск приложения на указанном порту
  console.log(`Application is running on: http://localhost:${port}/api`);
  console.log(`Cors_Orign : ${config.getOrThrow<string>('CORS_ORIGIN')}`);
}

bootstrap();
// Этот код создает приложение NestJS, настраивает его и запускает на указанном порту.
// Он также устанавливает глобальный префикс для всех маршрутов и выводит информацию о запущенном приложении в консоль.

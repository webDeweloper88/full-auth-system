// src/user/dto/change-password.dto.ts

import { IsString, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ChangePasswordDto {
  @ApiProperty({ description: 'Текущий пароль пользователя' })
  @IsString()
  @MinLength(8)
  oldPassword: string;

  @ApiProperty({ description: 'Новый пароль пользователя' })
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  newPassword: string;
}
// Этот DTO используется для изменения пароля пользователя

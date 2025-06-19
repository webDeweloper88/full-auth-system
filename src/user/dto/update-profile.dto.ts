// src/user/dto/update-profile.dto.ts

import { IsOptional, IsString, IsUrl, MaxLength } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateProfileDto {
  @ApiPropertyOptional({
    description: 'Отображаемое имя пользователя',
    maxLength: 50,
  })
  @IsOptional()
  @IsString()
  @MaxLength(50)
  displayName?: string;

  @ApiPropertyOptional({ description: 'URL аватара пользователя' })
  @IsOptional()
  @IsUrl()
  pictureUrl?: string;
}
// Этот DTO используется для обновления профиля пользователя

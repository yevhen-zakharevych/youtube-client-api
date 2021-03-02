import { MinLength, MaxLength, IsEmail } from 'class-validator';

export class AuthCredentialsDto {
  @IsEmail()
  username: string;

  @MinLength(6)
  @MaxLength(20)
  password: string;
}

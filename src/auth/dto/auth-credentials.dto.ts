import { MinLength, MaxLength } from 'class-validator';

export class AuthCredentialsDto {
  @MinLength(4)
  @MaxLength(20)
  username: string;

  @MinLength(8)
  @MaxLength(20)
  password: string;
}

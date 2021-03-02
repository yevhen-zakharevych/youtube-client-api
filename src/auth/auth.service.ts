import {
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { User, UserDocument } from './schemas/user.schema';
import { JwtPayload } from './jwt-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<UserDocument>,
    private jwtService: JwtService,
  ) {}

  async signUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
    const { username, password } = authCredentialsDto;
    const existedUser: User = await this.userModel.findOne({ username }).exec();

    if (existedUser) {
      throw new HttpException('User already exist', HttpStatus.FORBIDDEN);
    }

    const user = new this.userModel();

    user.username = username;
    user.salt = await bcrypt.genSalt();
    user.password = await bcrypt.hash(password, user.salt);

    await user.save();
  }

  async signIn(
    authCredentialsDto: AuthCredentialsDto,
  ): Promise<{ accessToken }> {
    const username = await this.validateUserPassword(authCredentialsDto);

    if (!username) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload: JwtPayload = { username };
    const accessToken = await this.jwtService.sign(payload);

    return { accessToken };
  }

  private async validateUserPassword(
    authCredentialsDto: AuthCredentialsDto,
  ): Promise<string> {
    const { username, password } = authCredentialsDto;
    const user = await this.userModel.findOne({ username });

    if (
      user &&
      (await this.validatePassword(password, user.salt, user.password))
    ) {
      return user.username;
    } else {
      return null;
    }
  }

  private async validatePassword(
    password: string,
    salt: string,
    userPassword: string,
  ): Promise<boolean> {
    const hash = await bcrypt.hash(password, salt);

    return hash === userPassword;
  }
}

import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { PassportStrategy } from '@nestjs/passport';
import { Model } from 'mongoose';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { JwtPayload } from './jwt-payload.interface';
import { User, UserDocument } from './schemas/user.schema';
// import * as config from 'config';

// const jwtConfig = config.get('jwt');

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private logger = new Logger('JwtStrategy');

  constructor(
    @InjectModel(User.name)
    private userModel: Model<UserDocument>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET, // || jwtConfig.secret,
    });

    this.logger.debug(
      `Constuctor process.env.JWT_SECRET ${process.env.JWT_SECRET}`,
    );
  }

  async validate(payload: JwtPayload) {
    const { username } = payload;

    const user = await this.userModel.findOne({ username });

    this.logger.debug(` validate username ${username}`);
    this.logger.debug(` validate user ${JSON.stringify(user)}`);

    if (!user) {
      throw new UnauthorizedException();
    }

    return user;
  }
}

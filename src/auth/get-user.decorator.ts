import { createParamDecorator } from '@nestjs/common';
import { User } from './schemas/user.schema';

export const GetUser = createParamDecorator(
  (data, ctx): User => {
    const request = ctx.switchToHttp().getRequest();

    return request.user;
  },
);

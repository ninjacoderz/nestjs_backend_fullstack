import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // TODO: POST Signup
  @Post('signup') // auth/signup
  async signUp(@Body() signupData: SignupDto) {
    return this.authService.signup(signupData)
  }


  // TODO: POST Login
  // TODO: POST Refresh Token
}

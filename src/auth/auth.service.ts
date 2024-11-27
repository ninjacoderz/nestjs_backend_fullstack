import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from "bcrypt"
import { LoginDto } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';
@Injectable()
export class AuthService {
    constructor (
        @InjectModel(User.name) private UserModel: Model<User>, 
        @InjectModel(RefreshToken.name) private RefreshTokenModel: Model<RefreshToken>, 
        private jwtService: JwtService
    ) {}

    async signup (signupData: SignupDto) {
        const {email, password, name} =  signupData;

        // Todo: check if email is in use
        const emailInuse = await this.UserModel.findOne({
            email: email
        })
        if(emailInuse) {
            throw new BadRequestException("Email is already in use.")
        }
        // Todo: hash password

        const hashPasword = await bcrypt.hash(password, 10)
        // Todo: create user document and save in mongodb
        await this.UserModel.create({
            name,
            email,
            password: hashPasword
        })
    }

    async login (credentials: LoginDto) {
        const {email, password} =  credentials;

        // Todo: find if email exist by email
        const user = await this.UserModel.findOne({
            email: email
        })
        if(!user) {
            throw new UnauthorizedException("Wrong credentials")
        }
        // Todo: compare 2 password

        const passwordMatch = await bcrypt.compare(password, user.password)
        if(!passwordMatch) {
            throw new UnauthorizedException("Wrong credentials");
        }
        // Todo: generate JWT token
        return this.generateUserTokens(user._id)
    }

    async generateUserTokens(userId) {
        const accessToken = this.jwtService.sign({userId}, {expiresIn: '1h'})
        const refreshToken = uuidv4()
        await this.storeRefreshToken(refreshToken, userId)
        return {
            accessToken, 
            refreshToken
        }
    }

    async storeRefreshToken (token: string, userId: string) {
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + 3);
        await this.RefreshTokenModel.create({token, userId, expiryDate})
    }

}

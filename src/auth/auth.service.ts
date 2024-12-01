import { BadRequestException, Injectable, InternalServerErrorException, Req, UnauthorizedException } from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from "bcrypt"
import { LoginDto } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { ConfigService } from '@nestjs/config';
import { MailService } from '../services/mail.service';
import { ResetToken } from './schemas/reset-token.schema';
import { nanoid } from 'nanoid';
@Injectable()
export class AuthService {
    constructor (
        @InjectModel(User.name) private UserModel: Model<User>, 
        @InjectModel(RefreshToken.name) private RefreshTokenModel: Model<RefreshToken>, 
        @InjectModel(ResetToken.name) private ResetTokenModel: Model<ResetToken>,
        private config: ConfigService,
        private jwtService: JwtService,
        private mailService: MailService,
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
        await this.RefreshTokenModel.updateOne({userId}, {$set: {expiryDate, token}}, {upsert: true})
    }

    async refreshTokens(refreshToken: string){
        const token = await this.RefreshTokenModel.findOne({
            token: refreshToken,
            expiryDate: {$gte: new Date()}
        })
        if (!token) {
            throw new UnauthorizedException("Refresh Token is invalid")
        }
        return this.generateUserTokens(token.userId)
    }
    async changePassword(userId: string, changePasswordDto: ChangePasswordDto){
        const { oldPassword, newPassword } = changePasswordDto
        // Find user
        const user = await this.UserModel.findById(userId)

        // Validate password
        const passwordMatch = bcrypt.compare(oldPassword, user.password);
        if(!passwordMatch) {
            throw new UnauthorizedException("Wrong credentials")
        }

        // Save new password with hash
        const newHashedPassword = await bcrypt.hash(newPassword, this.config.get("bcrypt.hashLength"))
        user.password = newHashedPassword
        await user.save()
    }

    async forgotPassword(email: string) {
        // Check user exist 
        const user = await this.UserModel.findOne({ email });

         // Generate token
        if(user) {
            const expiryDate = new Date();
            expiryDate.setHours(expiryDate.getHours() + 1);
            const resetToken = nanoid(64);
            await this.ResetTokenModel.create({
                token: resetToken,
                userId: user._id,
                expiryDate,
            });

            this.mailService.sendPasswordResetEmail(email, resetToken);
            
        }

    }

    async resetPassword(newPassword: string, resetToken: string){
        const token = await this.ResetTokenModel.findOneAndDelete({
            token: resetToken,
            expiryDate: { $gte: new Date() },
        });
      
        if (!token) {
        throw new UnauthorizedException('Invalid link');
        }

        const user = await this.UserModel.findById(token.userId);
        if (!user) {
            throw new InternalServerErrorException();
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
    }
}

import { BadRequestException, Injectable } from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from "bcrypt"
@Injectable()
export class AuthService {
    constructor (@InjectModel(User.name) private UserModel: Model<User>) {}


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
}

import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [MongooseModule.forRoot("mongodb+srv://binhcools:HReBHsL3xU4x2G5@cluster0.i7bil.mongodb.net/PostExampleDB?retryWrites=true&w=majority&appName=Cluster0"),
    AuthModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}

import { PrismaClient } from '@prisma/client';
import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { CreateUser, LoginUser, NewPasswordUser } from './request';
import { Utils } from './utils';
import { HttpResult } from './models/httpresult';
import { decode } from 'punycode';
import { Console } from 'console';

dotenv.config();
const SECRET_KEY = process.env.SECRET_KEY;
const prisma = new PrismaClient();

export const authSession = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, password } = req.body as LoginUser;

        if (!SECRET_KEY) {
            throw new Error("SECRET_KEY is not defined in the .env file.");
        }

        if (!Utils.doesValueExist(email) || !Utils.isValidEmail(email))  {
            res.status(404).json(HttpResult.Fail("Error: The value of email is invalid!"));
            return;
        }

        if (!Utils.doesValueExist(password) || !Utils.isValidPassword(password)) {
            res.status(404).json(HttpResult.Fail("Error: The value of password is invalid!"));
            return;
        }

        const userData = await prisma.tb_user.findUnique({
            where: {
                email: email
            }
        })     

        if (!userData) {
            res.status(400).json(HttpResult.Fail("Error: The email or password you entered is incorrect!"));
            return;
        }

        const validPassword = await bcrypt.compare(password, userData.password);

        if (!validPassword) {
            res.status(404).json(HttpResult.Fail("Error: The email or password you entered is incorrect!"));
            return;
        }
        
        const token = jwt.sign(
            { email },
            SECRET_KEY,
            { expiresIn: '1h'}
        )

        res.status(200).json(HttpResult.Success(token));
    } catch(error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on authSession"));
        console.error(error)
    }
}

export const createUser = async (req: Request, res: Response): Promise<void> => {
    try {
        const { fullName, email, password } = req.body as CreateUser;
        console.log(!Utils.isFullNameValid(fullName));
        if (!Utils.doesValueExist(fullName) || !Utils.isFullNameValid(fullName)) {
            res.status(404).json(HttpResult.Fail("Error: The value of fullName is invalid!"));
            return;
        } else if (fullName.length > 50) {
            res.status(404).json(HttpResult.Fail("Error: The value of fullName is too large!"));
            return;
        }


        if (!Utils.doesValueExist(email) || !Utils.isValidEmail(email))  {
            res.status(404).json(HttpResult.Fail("Error: The value of email is invalid!"));
            return;
        } else if (email.length > 255) {
            res.status(404).json(HttpResult.Fail("Error: The value of email is too large!"));
            return;;
        }

        if (!Utils.doesValueExist(password) || !Utils.isValidPassword(password)) {
            res.status(404).json(HttpResult.Fail("Error: The value of password is invalid!"));
            return;
        } else if (password.length < 8) {
            res.status(404).json(HttpResult.Fail("Error: The value of password is too short!"));
            return;
        } else if (password.length > 255) {
            res.status(404).json(HttpResult.Fail("Error: The value of password is too large!"));
            return;
        }

        const doesUserExist = (await prisma.tb_user.count({
            where: {
                email: email,
            }
        }) > 0);

        if (doesUserExist) {
            res.status(404).json(HttpResult.Fail("Error: There is already a user using this email!"));
            return;
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await prisma.tb_user.create({
            data: {
                fullName: fullName,
                email: email,
                password: hashedPassword
            }
        });

        res.status(200).json(HttpResult.Success("User created successfully"));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on createUser"));
    }
}

export const changePassword = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, password, newPassword } = req.body as NewPasswordUser;

        console.log(email)
        if (!Utils.doesValueExist(email) || typeof email != 'string' || email.length > 255) {
            res.status(404).json(HttpResult.Fail("Error: The value of email is invalid!"));
            return;
        }

        if (!Utils.isValidPassword(password)) {
            res.status(404).json(HttpResult.Fail("Error: The value of password is invalid!"));
            return;
        }

        if (!Utils.doesValueExist(newPassword) || !Utils.isValidPassword(newPassword)) {
            res.status(404).json(HttpResult.Fail("Error: The value of newPassword is invalid!"));
            return;
        } else if (newPassword.length < 8) {
            res.status(404).json(HttpResult.Fail("Error: The value of newPassword is too short!"));
            return;
        } else if (newPassword.length > 255) {
            res.status(404).json(HttpResult.Fail("Error: The value of newPassword is too large!"));
            return;
        }

        const userData = await prisma.tb_user.findUnique({
            where: {
                email: email,
            }
        });

        if (!userData) {
            res.status(404).json(HttpResult.Fail("Error: The email or password you entered is incorrect!"));
            return;
        }

        const validPassword = await bcrypt.compare(password, userData.password);

        if (!validPassword) {
            res.status(404).json(HttpResult.Fail("Error: The email or password you entered is incorrect!"));
            return;
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const isTheSamePassowrd = await bcrypt.compare(newPassword, userData.password) ? true : false;

        if (isTheSamePassowrd) {
            res.status(404).json(HttpResult.Fail("Error: The value of newPassword is the same as your current password!"));
            return;
        }

        await prisma.tb_user.update({
            where: {
                email: email,
            },
            data: {
                password: hashedPassword,
            }
        });

        res.status(200).json(HttpResult.Success("Password changed successfully"));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on changePassword"));
    }
}

export const getUser = async (req: Request, res: Response): Promise<void> => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!SECRET_KEY) {
            throw new Error("SECRET_KEY is not defined in the .env file.");
        }

        if (!token) {
            res.status(401).json(HttpResult.Fail("Token was not provided!"));
            return;
        }
        
        const decoded = jwt.verify(token, SECRET_KEY) as { email: string };
        const email = decoded.email;

        if (email) {
            res.status(401).json(HttpResult.Fail("Token provided is invalid!"));
            return;
        }

        const doesEmailExist = await prisma.tb_user.count({
            where: {
                email: email,
            }
        }) > 0 ? true : false;

        if (!doesEmailExist) {
            res.status(401).json(HttpResult.Fail("Error: Email does not exist!"));
            return;
        }

        const gotUser = await prisma.tb_user.findUnique({
            where: {
                email: email,
            }
        });

        res.status(200).json(HttpResult.Success({gotUser}));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on getUser!"));
    }
}

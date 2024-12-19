import { PrismaClient } from '@prisma/client';
import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { CreateUser } from './request';

dotenv.config();
const SECRET_KEY = process.env.SECRET_KEY;
const prisma = new PrismaClient();

export const authSession = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        if (!SECRET_KEY) {
            throw new Error("SECRET_KET is not defined in the .env file.");
        }

        if (!Utils.isValidEmail(email))  {
            return res.status(400).json(HttpResult.Fail("Error: The value of email is invalid!"));
        }

        if (!Utils.isValidPassword) {
            return res.status(400).json(HttpResult.Fail("Error: The value of password is invalid!"));
        }

        const userData = await prisma.tb_user.findUnique({
            where: {
                email: email,
            }
        });

        if (!userData) {
            return res.status(400).json(HttpResult.Fail("Error: The user was not found!"));
        }

        const validPassword = await bcrypt.compare(password, userData.password);

        if (!validPassword) {
            return res.status(400).json(HttpResult.Fail("Error: Invalid credentials!"));
        }

        const token = jwt.sign(
            { email, password },
            SECRET_KEY,
            { expires: '1h'}
        )

        res.status(200).json(HttpResult.Sucess(token));
    } catch(error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on authSession"));
    }
}

export const createUser = async (req: Request, res: Response) => {
    try {
        const { fullName, email, password } = req.body as CreateUser;

        if (!Utils.doesValueExist(fullName) || typeof fullName != 'string' || fullName.length > 50) {
            return res.status(400).json(HttpResult.Fail("Error: The value of fullName is invalid!"));
        }

        if (!Utils.doesValueExist(email) || typeof email != 'string' || email.length > 255) {
            return res.status(400).json(HttpResult.Fail("Error: The value of email is invalid!"));
        }

        if (!Utils.doesValueExist(password) || typeof password != 'string' || password.length < 8 || password.length > 255) {
            return res.status(400).json(HttpResult.Fail("Error: The value of password is invalid!"));
        }

        const doesUserExist = (await prisma.tb_user.count({
            where: {
                email: email,
            }
        }) > 0);

        if (doesUserExist) {
            return res.status(400).json(HttpResult.Fail("Error: There is already a user using this email!"));
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await prisma.tb_user.create({
            data: {
                fullName: fullName,
                email: email,
                password: hashedPassword,
            }
        });

        res.status(200).json(HttpResult.Sucess("User created successfully"));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on createUser"));
    }
}

export const changePassword = async (req: Request, res: Response) => {
    try {
        const { email, password, newPassword } = req.body;

        if (!Utils.doesValueExist(email) || typeof email != 'string' || email.length > 255) {
            return res.status(400).json(HttpResult.Fail("Error: The value of email is invalid!"));
        }

        if (!Utils.isValidPassword(password)) {
            return res.status(400).json(HttpResult.Fail("Error: The value of password is invalid!"));
        }

        if (!Utils.isValidPassword(newPassword)) {
            return res.status(400).json(HttpResult.Fail("Error: The value of newPassword is invalid!"));
        }

        const userData = await prisma.tb_user.findUnique({
            where: {
                email: email,
            }
        });

        if (!userData) {
            return res.status(400).json(HttpResult.Fail("Error: The user was not found!"));
        }

        const validPassword = await bcrypt.compare(password, userData.password);

        if (!validPassword) {
            return res.status(400).json(HttpResult.Fail("Error: Invalid credentials!"));
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await prisma.tb_user.update({
            where: {
                email: email,
            },
            data: {
                password: hashedPassword,
            }
        });

        res.status(200).json(HttpResult.Sucess("Password changed successfully"));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on changePassword"));
    }
}
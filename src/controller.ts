import { PrismaClient } from '@prisma/client';
import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();
const SECRET_KEY = 'hackathon'; 

const authSession = async (req: Request, res: Response) => {
    try {

    } catch(error: any) {
        res.status(400).json(HttpResult.sucess)
    }
}
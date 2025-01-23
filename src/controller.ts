import { PrismaClient } from '@prisma/client';
import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { CreateTrip, CreateUser, LoginUser, NewPasswordUser, TokenContent } from './request';
import { Utils } from './utils';
import { HttpResult } from './models/httpresult';


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

        const id = userData.id.toString();
        
        const token = jwt.sign(
            { id, email },
            SECRET_KEY,
            { expiresIn: '1d'}
        )

        res.status(200).json(HttpResult.Success(token));
    } catch(error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on authSession"));
        console.error(error);
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
        }) > 0 ? true : false);

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
        console.error(error);
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
        console.error(error);
    }
}

export const getUser = async (req: Request, res: Response): Promise<void> => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        console.log(109)
        if (!SECRET_KEY) {
            throw new Error("SECRET_KEY is not defined in the .env file.");
        }

        if (!token) {
            res.status(401).json(HttpResult.Fail("Token was not provided!"));
            return;
        }

        

        const decoded = jwt.verify(token, SECRET_KEY) as TokenContent;
        const email = decoded.email;

        if (!email) {
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

        const gotUserFormatted = {
            ...gotUser,
            id: gotUser?.id.toString(),
        };
        
        res.status(200).json(HttpResult.Success(gotUserFormatted));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on getUser!"));
        console.error(error);
    }
}

export const updateUser = async (req: Request, res: Response): Promise<void> => {
    
    try {
        const { fullName, email } = req.body;
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!SECRET_KEY) {
            throw new Error("SECRET_KEY is not defined in the .env file.");
        }

        if (!token) {
            res.status(401).json(HttpResult.Fail("Token was not provided!"));
            return;
        }
        
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

        const decoded = jwt.verify(token, SECRET_KEY) as TokenContent;
        const emailData = decoded.email;

        const doesEmailExist = await prisma.tb_user.count({
            where: {
                email: emailData,
            }
        }) > 0 ? true : false;

        if (!doesEmailExist) {
            res.status(401).json(HttpResult.Fail("Error: Email does not exist!"));
            return;  
        }

        const doesNewEmailExist = await prisma.tb_user.count({
            where: {
                email: email,
            }
        }) > 0 ? true : false;

        if (doesNewEmailExist && email != emailData) {
            res.status(404).json(HttpResult.Fail("Error: There is already a user using this email!"));
            return;  
        }

        const updatedUser = await prisma.tb_user.update({
            where: {
                email: emailData,
            },
            data: {
                fullName: fullName,
                email: email,
            }
        });

        const updatedUserFormated = {
            ...updatedUser,
            id: updatedUser.id.toString(),
        }

        res.status(200).json(HttpResult.Success(updatedUserFormated));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on updateUser!"));
        console.log(error);
    }
}

export const createTrip = async (req: Request, res: Response): Promise<void> => {
    try {
        const { tripName, period, daysQty, placesQty, currency, budgetAmount, season } = req.body as CreateTrip;
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!SECRET_KEY) {
            throw new Error("SECRET_KEY is not defined in the .env file.");
        }
  
        if (!token) {
            res.status(401).json(HttpResult.Fail("Token was not provided!"));
            return;
        }

        const decoded = jwt.verify(token, SECRET_KEY) as TokenContent;
        const id = decoded.id;

        if (!Utils.doesValueExist(id) || !Utils.isBigInt(id)) {
            res.status(400).json(HttpResult.Fail("Error: the value of user ID is invalid or was not provided correctly"));
            return;    
        }
  
        if (!Utils.doesValueExist(tripName) || typeof tripName != 'string') {
            res.status(404).json(HttpResult.Fail("Error: The value of tripName is invalid!"));
            return;
        } else if (tripName.length < 3) {
            res.status(404).json(HttpResult.Fail("Error: The value of tripName is too short!"));
            return;
        } else if (tripName.length > 50) {
            res.status(404).json(HttpResult.Fail("Error: The value of tripName is too large!"));
            return;
        }

        if (!Utils.doesValueExist(period) || typeof period != 'string' || period.length != 27) {
            res.status(404).json(HttpResult.Fail("Error: The value of period is invalid!"));
            return;
        }

        if (!Utils.doesValueExist(daysQty) || !Utils.isNumber(daysQty) || daysQty <= 0) {
            res.status(404).json(HttpResult.Fail("Error: The value of daysQty is invalid!"));
            return;
        }

        if (!Utils.doesValueExist(placesQty) || !Utils.isNumber(placesQty) || placesQty < 0) {
            res.status(404).json(HttpResult.Fail("Error: The value of placesQty is invalid!"));
            return;
        }

        if (!Utils.doesValueExist(budgetAmount) || !Utils.isNumber(budgetAmount) || budgetAmount < 0) {
            res.status(404).json(HttpResult.Fail("Error: The value of budget is invalid!"));
            return;
        }

        if (!Utils.doesValueExist(currency) || typeof currency != 'string' || currency.length != 3 || !["USD", "EUR", "BRL", "GBP", "JPY", "AUD", "CAD", "CHF", "CNY", "INR"].includes(currency)) {
            res.status(404).json(HttpResult.Fail("Error: The value of currency is invalid!"));
            return;
        }

        if (!Utils.doesValueExist(season) || typeof season != 'string' || !['Low', 'Middle', 'High'].includes(season)) {
            res.status(404).json(HttpResult.Fail("Error: The value of season is invalid!"));
            return;
        }

        const doesUserExist = await prisma.tb_user.findUnique({
            where: {
                id: BigInt(id),
            }
        });

        if (!doesUserExist) {
            res.status(404).json(HttpResult.Fail("Error: The user does not exist"));
            return;
        }

        await prisma.tb_trip.create({
            data: {
                userId: BigInt(id),
                tripName: tripName,
                period: period,
                daysQty: daysQty,
                placesQty: placesQty,
                currency: currency,
                season: season
            }
        });

        res.status(200).json(HttpResult.Success("Trip created successfully"));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on updateUser!"));
        console.log(error);
    }
}

export const getTrips = async (req: Request, res: Response): Promise<void> => {
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

        const decoded = jwt.verify(token, SECRET_KEY) as TokenContent;
        const id = decoded.id;

        if (!Utils.doesValueExist(id) || !Utils.isBigInt(id)) {
            res.status(400).json(HttpResult.Fail("Error: the value of user ID is invalid or was not provided correctly"));
            return;    
        }

        const gotTrips = await prisma.tb_trip.findMany({
            where: {
                userId: BigInt(id),
            }
        });
        
        const gotTripsFormatted = gotTrips.map((trip: any) => {
            trip.id = trip.id.toString();
            trip.userId = trip.userId.toString();
            return trip;
        });

        res.status(200).json(HttpResult.Success(gotTripsFormatted));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on getTrips!"));
        console.log(error);
    }
}

export const deleteTrip = async (req: Request, res: Response): Promise<void> => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        const { tripId } = req.body;

        console.log(tripId)

        if (!SECRET_KEY) {
            throw new Error("SECRET_KEY is not defined in the .env file.");
        }
  
        if (!token) {
            res.status(401).json(HttpResult.Fail("Token was not provided!"));
            return;
        }

        if (!Utils.doesValueExist(tripId) || !Utils.isBigInt(tripId)) {
            res.status(400).json(HttpResult.Fail("Error: the value of trip ID is invalid or was not provided correctly"));
            return;    
        }

        const doesTripExist = await prisma.tb_trip.count({
            where: {
                id: BigInt(tripId),
            }
        }) > 0 ? true : false;

        if (!doesTripExist) {
            res.status(404).json(HttpResult.Fail("Error: Trip does not exist!"));
            return;
        }

        await prisma.tb_trip.delete({
            where: {
                id: BigInt(tripId),
            }
        });

        res.status(200).json(HttpResult.Success("Trip deleted successfully"));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on deleteTrip!"));
        console.log(error)
    }
}
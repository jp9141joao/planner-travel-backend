import { PrismaClient } from '@prisma/client';
import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { createAirplaneExpense, CreateExpense, CreateExpenses, createExpenses, createTransportationExpense, CreateTrip, CreateUser, LoginUser, NewPasswordUser, TokenContent, UpdateTrip, UpdateUser } from './request';
import { Utils } from './utils';
import { HttpResult } from './models/httpresult';
import { where } from 'sequelize';
import exp from 'constants';
import { countReset } from 'console';

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
            return;
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
        const { tripName, period, daysQty, currency, budgetAmount, season } = req.body as CreateTrip;
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
        } else if (tripName.length > 22) {
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
                currency: currency,
                budgetAmount: budgetAmount,
                season: season
            }
        });

        res.status(200).json(HttpResult.Success("Trip created successfully"));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on updateUser!"));
        console.log(error);
    }
}

export const getTrip = async (req: Request, res: Response): Promise<void> => {
    try {
        const { tripId } = req.query;
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

        if (!Utils.doesValueExist(tripId) || !Utils.isBigInt(tripId)) {
            res.status(400).json(HttpResult.Fail("Error: the value of trip ID is invalid or was not provided correctly"));
            return;    
        }

        const doesUserExist = await prisma.tb_user.count({
            where: {
                id: BigInt(id),
            }
        }) > 0 ? true : false;

        if (!doesUserExist) {
            res.status(401).json(HttpResult.Fail("Error: User does not exist!"));
            return;  
        }

        const doesTripExist = await prisma.tb_trip.count({
            where: {
                id: BigInt(String(tripId)),
                userId: BigInt(id),
            }
        }) > 0 ? true : false;

        if (!doesTripExist) {
            res.status(401).json(HttpResult.Fail("Error: Trip does not exist!"));
            return;  
        }


        const gotTrip = await prisma.tb_trip.findFirst({
            where: {
                id: BigInt(String(tripId)),
                userId: BigInt(id),
            }
        });
        
        const gotTripFormatted = {
            ...gotTrip,
            id: gotTrip?.id.toString(),
            userId: gotTrip?.userId.toString(),
        };
        10
        res.status(200).json(HttpResult.Success(gotTripFormatted));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on getTrips!"));
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

        const doesUserExist = await prisma.tb_user.count({
            where: {
                id: BigInt(id),
            }
        }) > 0 ? true : false;

        if (!doesUserExist) {
            res.status(401).json(HttpResult.Fail("Error: User does not exist!"));
            return;  
        }

        const gotTrips = await prisma.tb_trip.findMany({
            where: {
                userId: BigInt(id),
            },
            orderBy: {
                id: 'desc'
            },
        });
        
        const gotTripsFormatted = gotTrips.map((trip: any) => {
            trip.id = trip.id.toString();
            trip.userId = trip.userId.toString();
            return trip;
        });

        res.status(200).json(HttpResult.Success(gotTripsFormatted));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on getTrip!"));
        console.log(error)
    }
}

export const updateTrip = async (req: Request, res: Response): Promise<void> => {
    try {
        const { id, tripName, period, daysQty, currency, budgetAmount, spent, season } = req.body as UpdateTrip;
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
        const idData = decoded.id;

        if (!Utils.doesValueExist(idData) || !Utils.isBigInt(idData)) {
            res.status(400).json(HttpResult.Fail("Error: the value of user ID is invalid or was not provided correctly"));
            return;    
        }

        if (!Utils.doesValueExist(id) || !Utils.isBigInt(id)) {
            res.status(400).json(HttpResult.Fail("Error: the value of trip ID is invalid or was not provided correctly"));
            return;    
        }

        if (!Utils.doesValueExist(tripName) || typeof tripName != 'string') {
            res.status(404).json(HttpResult.Fail("Error: The value of tripName is invalid!"));
            return;
        } else if (tripName.length < 3) {
            res.status(404).json(HttpResult.Fail("Error: The value of tripName is too short!"));
            return;
        } else if (tripName.length > 22) {
            res.status(404).json(HttpResult.Fail("Error: The value of tripName is too large!"));
            return;
        }

        if (!Utils.doesValueExist(period) || typeof period != 'string' || period.length != 27) {
            res.status(404).json(HttpResult.Fail("Error: The value of period is invalid!"));
            return;
        }

        if ( !Utils.doesValueExist(daysQty) || !Utils.isNumber(Number(daysQty)) || Number(daysQty) <= 0) {
            res.status(404).json(HttpResult.Fail("Error: The value of daysQty is invalid!"));
            return;
        }

        if (!Utils.doesValueExist(budgetAmount) || !Utils.isNumber(Number(budgetAmount)) || Number(budgetAmount) < 0) {
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

        if (!Utils.doesValueExist(spent) || !Utils.isNumber(Number(spent)) || Number(spent) < 0) {
            res.status(404).json(HttpResult.Fail("Error: The value of spent is invalid!"));
            return;
        }

        const doesUserExist = await prisma.tb_user.count({
            where: {
                id: BigInt(idData),
            }
        }) > 0 ? true : false;

        if (!doesUserExist) {
            res.status(401).json(HttpResult.Fail("Error: User does not exist!"));
            return;  
        }

        const doesTripExist = await prisma.tb_trip.count({
            where: {
                id: BigInt(String(id)),
            }
        }) > 0 ? true : false;

        if (!doesTripExist) {
            res.status(401).json(HttpResult.Fail("Error: Trip does not exist!"));
            return;  
        }

        const updatedTrip = await prisma.tb_trip.update({
            where: {
                id: BigInt(String(id)),
                userId: BigInt(idData)
            },
            data: {
                tripName: tripName,
                period: period,
                daysQty: daysQty,
                budgetAmount: budgetAmount,
                currency: currency,
                season: season,
                spent: spent
            }
        });

        const updatedTripFormatted = {
            ...updatedTrip,
            id: updatedTrip.id.toString(),
            userId: updatedTrip.userId.toString()
        }

        res.status(200).json(HttpResult.Success(updatedTripFormatted));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on duplicateTrip"));
        console.log(error);
    }
}

export const duplicateTrip = async (req: Request, res: Response): Promise<void> => {
    try {
        const { tripId } = req.body;
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

        if (!Utils.doesValueExist(tripId) || !Utils.isBigInt(tripId)) {
            res.status(400).json(HttpResult.Fail("Error: the value of trip ID is invalid or was not provided correctly"));
            return;    
        }

        const doesUserExist = await prisma.tb_user.count({
            where: {
                id: BigInt(id),
            }
        }) > 0 ? true : false;

        if (!doesUserExist) {
            res.status(401).json(HttpResult.Fail("Error: User does not exist!"));
            return;  
        }

        const doesTripExist = await prisma.tb_trip.findFirst({
            where: {
                id: BigInt(String(tripId)),
            }
        });

        if (!doesTripExist) {
            res.status(401).json(HttpResult.Fail("Error: Trip does not exist!"));
            return;  
        }

        const { id: idTrip, ...duplicatedTrip } = doesTripExist;
       
        await prisma.tb_trip.create({
            data: {
                userId: BigInt(duplicatedTrip.userId),
                tripName: duplicatedTrip.tripName,
                period: duplicatedTrip.period,
                daysQty: duplicatedTrip.daysQty,
                currency: duplicatedTrip.currency,
                budgetAmount: duplicatedTrip.budgetAmount,
                season: duplicatedTrip.season,
                notes: duplicatedTrip.notes,
                spent: duplicatedTrip.spent
            }
        });

        res.status(200).json(HttpResult.Success("Trip duplicated successfully"));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on duplicateTrip"));
        console.log(error);
    }
}

export const deleteTrip = async (req: Request, res: Response): Promise<void> => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        const { tripId } = req.body;

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

        if (!Utils.doesValueExist(tripId) || !Utils.isBigInt(tripId)) {
            res.status(400).json(HttpResult.Fail("Error: the value of trip ID is invalid or was not provided correctly"));
            return;    
        }

        const doesUserExist = await prisma.tb_user.count({
            where: {
                id: BigInt(id),
            }
        }) > 0 ? true : false;

        if (!doesUserExist) {
            res.status(401).json(HttpResult.Fail("Error: User does not exist!"));
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
        console.log(error);
    }
}

export const updateNotes = async (req: Request, res: Response): Promise<void> => {
    try {
        const { tripId, notes } = req.body;
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

        if (!Utils.doesValueExist(tripId) || !Utils.isBigInt(tripId)) {
            res.status(400).json(HttpResult.Fail("Error: the value of trip ID is invalid or was not provided correctly"));
            return;    
        }

        if (notes.length > 255 || typeof notes != 'string') {
            res.status(404).json(HttpResult.Fail("Error: The value of email is invalid!"));
            return;
        }

        const doesUserExist = await prisma.tb_user.count({
            where: {
                id: BigInt(id),
            }
        }) > 0 ? true : false;

        if (!doesUserExist) {
            res.status(401).json(HttpResult.Fail("Error: User does not exist!"));
            return;  
        }

        const doesTripExist = await prisma.tb_trip.count({
            where: {
                id: BigInt(tripId),
                userId: BigInt(id),
            }
        }) > 0 ? true : false;

        if (!doesTripExist) {
            res.status(401).json(HttpResult.Fail("Error: Trip does not exist!"));
            return;  
        }

        await prisma.tb_trip.update({
            data: {
                notes: notes,
            }, 
            where: {
                id: BigInt(tripId),
                userId: BigInt(id)
            }
        })

    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on updateNotes"));
        console.log(error);
    }
}

export const getExpense = async (req: Request, res: Response): Promise<void> => {
    try {
        const { tripId, expenseId } = req.body;
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

        if (!Utils.doesValueExist(tripId) || !Utils.isBigInt(tripId)) {
            res.status(400).json(HttpResult.Fail("Error: the value of trip ID is invalid or was not provided correctly"));
            return;    
        }

        if (!Utils.doesValueExist(expenseId) || !Utils.isBigInt(expenseId)) {
            res.status(400).json(HttpResult.Fail("Error: the value of expense ID is invalid or was not provided correctly"));
            return;    
        }

        const doesUserExist = await prisma.tb_user.count({
            where: {
                id: BigInt(id),
            }
        }) > 0 ? true : false;

        if (!doesUserExist) {
            res.status(401).json(HttpResult.Fail("Error: User does not exist!"));
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

        const doesExpenseExist = await prisma.tb_expense.count({
            where: {
                id: BigInt(tripId),
                tripId: BigInt(tripId),
            }
        }) > 0 ? true : false;

        if (!doesExpenseExist) {
            res.status(404).json(HttpResult.Fail("Error: Expense does not exist!"));
            return;
        }

        const gotExpense = await prisma.tb_expense.findFirst({
            where: {
                id: BigInt(id),
                tripId: BigInt(tripId),
            }
        });
        const gotExpenseFormatted = {
            ...gotExpense,
            id: gotExpense.toString(),
            tripId: gotExpense.toString(),
        };

        res.status(200).json(HttpResult.Success(gotExpenseFormatted));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on deleteExpense"));
        console.error(error);
    }
}

export const getExpenses = async (req: Request, res: Response): Promise<void> => {
    try {
        const { tripId } = req.body;
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

        if (!Utils.doesValueExist(tripId) || !Utils.isBigInt(tripId)) {
            res.status(400).json(HttpResult.Fail("Error: the value of trip ID is invalid or was not provided correctly"));
            return;    
        }

        const doesUserExist = await prisma.tb_user.count({
            where: {
                id: BigInt(id),
            }
        }) > 0 ? true : false;

        if (!doesUserExist) {
            res.status(401).json(HttpResult.Fail("Error: User does not exist!"));
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

        const gotExpenses = await prisma.tb_expense.findMany();
        const gotExpensesFormatted = gotExpenses.map((expense: any) => {
            expense.id = expense.id.toString();
            expense.tripId = expense.tripId.toString();
            return expense;
        })

        res.status(200).json(HttpResult.Success(gotExpensesFormatted));
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on deleteExpense"));
        console.error(error);
    }
}

export const deleteExpense = async (req: Request, res: Response): Promise<void> => {
    try {
        const { tripId, expenseId } = req.body;
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

        if (!Utils.doesValueExist(tripId) || !Utils.isBigInt(tripId)) {
            res.status(400).json(HttpResult.Fail("Error: the value of trip ID is invalid or was not provided correctly"));
            return;    
        }

        if (!Utils.doesValueExist(expenseId) || !Utils.isBigInt(expenseId)) {
            res.status(400).json(HttpResult.Fail("Error: the value of expense ID is invalid or was not provided correctly"));
            return; 
        }

        const doesUserExist = await prisma.tb_user.count({
            where: {
                id: BigInt(id),
            }
        }) > 0 ? true : false;

        if (!doesUserExist) {
            res.status(401).json(HttpResult.Fail("Error: User does not exist!"));
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

        const doesExpenseExist = await prisma.tb_expense.count({
            where: {
                id: BigInt(tripId),
                tripId: BigInt(tripId),
            }
        }) > 0 ? true : false;

        if (!doesExpenseExist) {
            res.status(404).json(HttpResult.Fail("Error: Expense does not exist!"));
            return;
        }

        await prisma.tb_expense.delete({
            where: {
                id: BigInt(expenseId),
                tripId: BigInt(tripId)
            }
        });

        res.status(200).json(HttpResult.Success("Expense deleted successfully"));      
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on deleteExpense"));
        console.error(error);
    }
}

export const createExpense = async (req: Request, res: Response): Promise<void> => {
    try {
        const { 
            tripId,
            type,
            name,
            category,
            duration,
            place,
            origin,
            destination,
            price,
            countryCurrency,
            day
        } = req.body as CreateExpense;
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
        const idData = decoded.id;

        if (!Utils.doesValueExist(idData) || !Utils.isBigInt(idData)) {
            res.status(400).json(HttpResult.Fail("Error: the value of user ID is invalid or was not provided correctly"));
            return;    
        }

        if (!Utils.doesValueExist(tripId) || !Utils.isBigInt(tripId)) {
            res.status(400).json(HttpResult.Fail("Error: the value of trip ID is invalid or was not provided correctly"));
            return;    
        }

        if (!Utils.doesValueExist(type) || typeof type != 'string' || type.length > 12) {
            res.status(400).json(HttpResult.Fail("Error: the value of type is invalid or was not provided correctly"));
            return;
        }

        if (name) {
            if (!Utils.doesValueExist(name) || typeof name != 'string') {
                res.status(400).json(HttpResult.Fail("Error: the value of name is invalid or was not provided correctly"));
                return;
            } else if (name.length < 3) {
                res.status(400).json(HttpResult.Fail("Error: the value of name is too short!"));
                return;
            } else if (name.length > 15) {
                res.status(400).json(HttpResult.Fail("Error: the value of name is too large!"));
                return;
            }
        }

        if (category) {
            if (!Utils.doesValueExist(category) || typeof category != 'string' || category.length > 16) {
                res.status(400).json(HttpResult.Fail("Error: the value of category is invalid or was not provided correctly"));
                return;
            }
        }

        if (duration) {
            if (!Utils.doesValueExist(duration) || typeof duration != 'string' || duration.length > 16) {
                res.status(400).json(HttpResult.Fail("Error: the value of duration is invalid or was not provided correctly"));
                return;
            }
        }

        if (place) {
            if (!Utils.doesValueExist(place) || typeof place != 'string') {
                res.status(400).json(HttpResult.Fail("Error: the value of place is invalid or was not provided correctly"));
                return;
            } else if (place.length < 3) {
                res.status(400).json(HttpResult.Fail("Error: the value of place is too short!"));
                return;
            } else if (place.length > 15) {
                res.status(400).json(HttpResult.Fail("Error: the value of place is too large!"));
                return;
            }
        }
        
        if (origin) {
            if (!Utils.doesValueExist(origin) || typeof origin != 'string') {
                res.status(400).json(HttpResult.Fail("Error: the value of origin is invalid or was not provided correctly"));
                return;
            } else if (origin.length < 3) {
                res.status(400).json(HttpResult.Fail("Error: the value of origin is too short!"));
                return;
            } else if (origin.length > 15) {
                res.status(400).json(HttpResult.Fail("Error: the value of origin is too large!"));
                return;
            }
        }

        if (destination) {
            if (!Utils.doesValueExist(destination) || typeof destination != 'string') {
                res.status(400).json(HttpResult.Fail("Error: the value of destination is invalid or was not provided correctly"));
                return;
            } else if (destination.length < 3) {
                res.status(400).json(HttpResult.Fail("Error: the value of destination is too short!"));
                return;
            } else if (destination.length > 15) {
                res.status(400).json(HttpResult.Fail("Error: the value of destination is too large!"));
                return;
            }
        }

        if (!Utils.doesValueExist(price) || !Utils.isNumber(price)) {
            res.status(400).json(HttpResult.Fail("Error: the value of price is invalid or was not provided correctly"));
            return;
        } else if (price <= 0) {
            res.status(400).json(HttpResult.Fail("Error: the value of price is less or equal than zero!"));
            return;
        } else if (price > 9999999.99) {
            res.status(400).json(HttpResult.Fail("Error: the value of price is too large!"));
            return;
        } else if (price.toString().split('.')[1].length > 2) {
            res.status(400).json(HttpResult.Fail("Error: the format of price is invalid! Only up to two decimal places are allowed."));
            return;
        }

        if (!Utils.doesValueExist(countryCurrency) || typeof countryCurrency != 'string' || countryCurrency.length != 3) {
            res.status(400).json(HttpResult.Fail("Error: the value of country currency is invalid or was not provided correctly"));
            return;
        }

        const doesTripExist = await prisma.tb_trip.findFirst({
            where: {
                id: BigInt(tripId),
            }
        });

        if (!doesTripExist) {
            res.status(404).json(HttpResult.Fail("Error: Trip does not exist!"));
            return;
        }

        if (!Utils.doesValueExist(day) || !Utils.isNumber(day) || day <= 0 || day > doesTripExist.daysQty) {
            res.status(400).json(HttpResult.Fail("Error: the value of day is invalid or was not provided correctly"));
            return;
        }

        const doesUserExist = await prisma.tb_user.count({
            where: {
                id: BigInt(idData),
            }
        }) > 0 ? true : false;

        if (!doesUserExist) {
            res.status(401).json(HttpResult.Fail("Error: User does not exist!"));
            return;  
        }

        const currentDate: Date = new Date();

        if (type == 'Airplane') {
            await prisma.tb_airplane_expense.create({
                data: {
                    tripId: tripId,
                    type: type,
                    name: name,
                    origin: origin,
                    destination: destination,
                    price: price,
                    countryCurrency: countryCurrency,
                    day: day,
                    date: currentDate,
                }
            });

        } else if (type == 'Transportation') {
            await prisma.tb_transportation_expense.create({
                data: {
                    tripId: tripId,
                    type: type,
                    category: category,
                    origin: origin,
                    destination: destination,
                    price: price,
                    countryCurrency: countryCurrency,
                    day: day,
                    date: currentDate,
                }
            });

        } else if (type == 'Food') {
            await prisma.tb_food_expense.create({
                data: {
                    tripId: tripId,
                    type: type,
                    name: name,
                    category: category,
                    place: place,
                    price: price,
                    countryCurrency: countryCurrency,
                    day: day,
                    date: currentDate,
                }
            });

        } else if (type == 'Attraction') {
            await prisma.tb_attraction_expense.create({
                data: {
                    tripId: tripId,
                    type: type,
                    name: name,
                    category: category,
                    duration: duration,
                    price: price,
                    countryCurrency: countryCurrency,
                    day: day,
                    date: currentDate,
                }
            });

        } else if (type == 'Accomodation') {
            await prisma.tb_accomodation_expense.create({
                data: {
                    tripId: tripId,
                    type: type,
                    name: name,
                    category: category,
                    duration: duration,
                    price: price,
                    countryCurrency: countryCurrency,
                    day: day,
                    date: currentDate,
                }
            });

            res.status(200).json(HttpResult.Success("Accomodation expense deleted successfully"));
        }
    
    } catch (error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on createExpense"));
        console.error(error);
    }
}
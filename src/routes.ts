import { Router } from 'express';
import { authSession, changePassword, createTrip, createUser, deleteExpense, deleteTrip, duplicateTrip, getExpense, getExpenses, getTrip, getTrips, getUser, updateNotes, updateTrip, updateUser } from './controller';

const routes = Router();

routes.post('/signIn', authSession);
routes.get('/home', getUser);
routes.post('/signUp', createUser);
routes.put('/resetPassword', changePassword);
routes.put('/profileSettings', updateUser);
routes.post('/addTrips', createTrip);
routes.get('/viewTrips', getTrips);
routes.delete('/viewTrips', deleteTrip);
routes.post('/viewTrips', duplicateTrip);
routes.get('/tripDetails', getTrip);
routes.put('/tripDetails', updateNotes);
routes.get('/editTrip', getTrip);
routes.put('/editTrip', updateTrip);
routes.get('/viewExpenses', getExpenses);

export { routes };
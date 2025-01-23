import { Router } from 'express';
import { authSession, changePassword, createTrip, createUser, deleteTrip, getTrips, getUser, updateUser } from './controller';

const routes = Router();

routes.post('/signIn', authSession);
routes.get('/home', getUser);
routes.post('/signUp', createUser);
routes.put('/resetPassword', changePassword);
routes.put('/profileSettings', updateUser);
routes.post('/addTrips', createTrip);
routes.get('/viewTrips', getTrips);
routes.delete('/viewTrips', deleteTrip);

export { routes };
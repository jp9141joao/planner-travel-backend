import { Router } from 'express';
import { authSession, changePassword, createTrip, createUser, getUser, updateUser } from './controller';

const routes = Router();

routes.post('/signIn', authSession);
routes.get('/home', getUser);
routes.post('/signUp', createUser);
routes.put('/resetPassword', changePassword);
routes.put('/profileSettings', updateUser);
routes.post('/addTrips', createTrip);

export { routes };
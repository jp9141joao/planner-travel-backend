import express from 'express';
import cors from 'cors';
import { routes } from './routes';

const app = express();
const port = 3000;

app.use(cors({
  origin: 'http://localhost:5173', // Permite apenas esta origem
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Permite métodos específicos
  allowedHeaders: ['Content-Type', 'Authorization'] // Permite headers específicos
}));
app.use(express.json());
app.use(routes);

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});


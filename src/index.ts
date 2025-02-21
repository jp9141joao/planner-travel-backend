import express from 'express';
import cors from 'cors';
import { routes } from './routes';

const app = express();
const port = 3000;

app.use(cors({
  origin: 'http://localhost:5173',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(routes);

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});


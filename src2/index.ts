import express from 'express';
import cors from 'cors';  // Importa o middleware cors
import { routes } from './routes';

const app = express();
const port = 3000;

// Habilitar CORS para permitir que a API seja acessada de domínios externos
app.use(cors());

app.use(express.json());
app.use(routes);

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
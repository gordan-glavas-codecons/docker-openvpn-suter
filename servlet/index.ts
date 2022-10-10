import express, { Express, Request, Response } from 'express';
import dotenv from 'dotenv';
import shell from 'shelljs';

dotenv.config();

const app: Express = express();
const port = process.env.PORT;

app.get('/', (req: Request, res: Response) => {
  const output = shell.exec('ovpn_getclient_all');
  res.send('Express + TypeScript Server ' + output);
});

app.listen(port, () => {
  console.log(`⚡️[server]: Server is running at https://localhost:${port}`);
});
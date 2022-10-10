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

app.post('/cert', (req: Request, res: Response) => {
  const clientName = req.query.name;
  if (typeof clientName !== "string" || clientName.length === 0) {
    return res.send(422);
  }
  shell.env["EASYRSA_PASSIN"] = "pass:passphrase";
  shell.env["EASYRSA_PASSOUT"] = "pass:passphrase";
  const output = shell.exec("printf 'passphrase\npassphrase' | easyrsa build-client-full " + clientName);
  res.send('Express + TypeScript Server \n\n' + output);
});

app.get('/cert', (req: Request, res: Response) => {
  const clientName = req.query.name;
  if (typeof clientName !== "string" || clientName.length === 0) {
    return res.send(422);
  }
  const output = shell.exec(`ovpn_getclient ${clientName} > clientExport.ovpn`);
  res.set('Content-Disposition', `attachment; filename="${clientName}.ovpn"`);
  res.sendFile(`/usr/src/app/clientExport.ovpn`);
});

app.delete('/cert', (req: Request, res: Response) => {
  const clientName = req.query.name;
  if (typeof clientName !== "string" || clientName.length === 0) {
    return res.send(422);
  }
  shell.env["EASYRSA_PASSIN"] = "pass:passphrase";
  shell.env["EASYRSA_PASSOUT"] = "pass:passphrase";
  const output = shell.exec(`printf 'yes\n' | ovpn_revokeclient ${clientName} passphrase remove`);
  res.send(output);
});

app.listen(port, () => {
  console.log(`⚡️[server]: Server is running at https://localhost:${port}`);
});
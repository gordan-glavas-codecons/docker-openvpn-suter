import express, { Express, Request, Response } from 'express';
import cors from "cors";
import compression from "compression";
import helmet from "helmet";
import morganBody from "morgan-body";
import dotenv from 'dotenv';
import shell from 'shelljs';
import md5 from "md5";

dotenv.config();

const app: Express = express();
app.use(cors());
app.use(compression());
app.use(helmet());
morganBody(app);

const port = process.env.PORT;
const easyRsaPassInKey = "EASYRSA_PASSIN";
const easyRsaPassOutKey = "EASYRSA_PASSOUT";

const validateToken = (req: Request): boolean => {
  const token = req.query.token;
  if (typeof token !== "string" || token.length === 0) {
    return false;
  }
  const userTokens = (process.env.USER_TOKENS || "").split(",");
  for (const userToken of userTokens) {
    if (md5(userToken) === token) {
      return true;
    }
  }
  return false;
};

app.get('/', (req: Request, res: Response) => {
  res.send("All ok!");
});

app.post('/cert', (req: Request, res: Response) => {
  const clientName = req.query.name;
  if (typeof clientName !== "string" || clientName.length === 0 || !validateToken(req)) {
    return res.status(400).send("Invalid request!");
  }
  const caPassphrase = process.env.CA_PASSPHRASE || "";
  const keyPassphrase = process.env.KEY_PASSPHRASE || "";
  shell.env[easyRsaPassInKey] = `pass:${caPassphrase}`;
  shell.env[easyRsaPassOutKey] = `pass:${caPassphrase}`;
  const output = shell.exec(`printf '${keyPassphrase}\n${keyPassphrase}\n}' | easyrsa build-client-full ${clientName}`);
  if (output.code !== 0) {
    return res.status(422).send("Invalid code while executing: " + output.code);
  }
  res.status(201).send();
});

app.get('/cert', (req: Request, res: Response) => {
  const clientName = req.query.name;
  if (typeof clientName !== "string" || clientName.length === 0 || !validateToken(req)) {
    return res.status(400).send("Invalid request!");
  }
  const output = shell.exec(`ovpn_getclient ${clientName} > clientExport.ovpn`);
  if (output.code !== 0) {
    return res.status(422).send("Invalid code while executing: " + output.code);
  }
  res.set('Content-Disposition', `attachment; filename="${clientName}.ovpn"`);
  res.sendFile(`/usr/src/app/clientExport.ovpn`);
});

app.delete('/cert', (req: Request, res: Response) => {
  const clientName = req.query.name;
  if (typeof clientName !== "string" || clientName.length === 0 || !validateToken(req)) {
    return res.status(400).send("Invalid request!");
  }
  const caPassphrase = process.env.CA_PASSPHRASE || "";
  shell.env[easyRsaPassInKey] = `pass:${caPassphrase}`;
  shell.env[easyRsaPassOutKey] = `pass:${caPassphrase}`;
  const output = shell.exec(`printf 'yes\n' | ovpn_revokeclient ${clientName} passphrase remove`);
  if (output.code !== 0) {
    return res.status(422).send("Invalid code while executing: " + output.code);
  }
  res.status(204).send();
});

app.listen(port, () => {
  console.log(`⚡️[server]: Server is running at port ${port}!`);
});

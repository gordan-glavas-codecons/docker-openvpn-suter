import express, { Express, Request, Response } from "express";
import cors from "cors";
import compression from "compression";
import helmet from "helmet";
import morganBody from "morgan-body";
import dotenv from "dotenv";
import shell from "shelljs";
import md5 from "md5";
import fetch from "node-fetch";
import fs from "fs";

dotenv.config();

const app: Express = express();
app.use(cors());
app.use(compression());
app.use(helmet());
morganBody(app);

const port = process.env.PORT;
const easyRsaPassInKey = "EASYRSA_PASSIN";
const easyRsaPassOutKey = "EASYRSA_PASSOUT";
const ipRegex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;

type PartialIpAddress = {
  0: number;
  1: number;
}
const ccdFileNameRegex = /\/ccd\/(.+)$/;
const ifconfigPushRegex = /^ifconfig-push 10\.8\.(\d+)\.(\d+)/;
const defaultIpRegex = /^10\.8\.(\d+)\.(\d+)$/;
const ccdIpTable: Record<string, PartialIpAddress> = { };
let maxIp: PartialIpAddress = [-1, -1];

const loadCcdIpTable = async () => {
  try {
    const output = shell.exec("ovpn_print_ccd_paths");
    if (output.code !== 0) {
      console.error("Invalid code while executing: " + output.code);
      return;
    }
    const paths = output.split("\n");
    for (const path of paths) {
      const fileNameMatch = path.match(ccdFileNameRegex);
      if (!fileNameMatch || fileNameMatch.length < 2) {
        continue;
      }
      const fileContent = await fs.promises.readFile(path, "utf-8");
      const ifconfigPushMatch = fileContent.match(ifconfigPushRegex);
      if (!ifconfigPushMatch || ifconfigPushMatch.length < 3) {
        continue;
      }
      const fileName = fileNameMatch[1];
      const partialIp: PartialIpAddress = [Number(ifconfigPushMatch[1]), Number(ifconfigPushMatch[2])];
      ccdIpTable[fileName] = partialIp;
    }
    updateMaxCcdIp();
    console.log(`Loaded ${Object.keys(ccdIpTable).length} CCDs.`);
  } catch (error) {
    console.log("Error reading CCDs: " + error);
  }
};

const addNewCcdIpAddress = (clientName: string, ip: string) => {
  const ipMatches = ip.match(defaultIpRegex);
  if (ipMatches) {
    const newIp: PartialIpAddress = [Number(ipMatches[1]), Number(ipMatches[2])];
    ccdIpTable[clientName] = newIp;
    compareCcdIpWithMaxAndUpdate(newIp);
  }
};

const removeCcdIpAddress = (clientName: string) => {
  const ip = ccdIpTable[clientName];
  if (ip) {
    delete ccdIpTable[clientName];
    if (ip[0] === maxIp[0] && ip[1] === maxIp[1]) {
      updateMaxCcdIp();
    }
  }
};

const updateMaxCcdIp = () => {
  maxIp = [-1, -1];
  for (const partialIp of Object.values(ccdIpTable)) {
    compareCcdIpWithMaxAndUpdate(partialIp);
  }
};

const compareCcdIpWithMaxAndUpdate = (ip: PartialIpAddress) => {
  if (ip[0] > maxIp[0] || ip[1] > maxIp[1]) {
    maxIp = ip;
  }
};

const getNextCcdIpAddress = (): string => {
  const newIp = [maxIp[0], maxIp[1] + 1];
  if (newIp[1] === 255) {
    newIp[0]++;
    newIp[1] = 1;
  }
  return `10.8.${newIp[0]}.${newIp[1]}`;
};

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

const createCertificate = (clientName: string, ip: string, nopass: boolean): number => {
  const caPassphrase = process.env.CA_PASSPHRASE || "";
  const keyPassphrase = process.env.KEY_PASSPHRASE || "";
  shell.env[easyRsaPassInKey] = `pass:${caPassphrase}`;
  shell.env[easyRsaPassOutKey] = `pass:${caPassphrase}`;
  const output = shell.exec(`printf '${keyPassphrase}\n${keyPassphrase}\n}' `
    + `| easyrsa build-client-full ${clientName}${nopass ? " nopass" : ""}`);
  if (output.code !== 0) {
    return output.code;
  }
  shell.exec(`ovpn_create_ccd ${clientName} ${ip}`);
  return 0;
};

const exportCertificate = (clientName: string, res: Response) => {
  const output = shell.exec(`ovpn_getclient ${clientName} > clientExport.ovpn`);
  if (output.code !== 0) {
    return res.status(422).send("Invalid code while executing: " + output.code);
  }
  res.set("Content-Disposition", `attachment; filename="${clientName}.ovpn"`);
  res.sendFile("/usr/src/app/clientExport.ovpn");
};

const revokeCertificate = (clientName: string, res: Response) => {
  const caPassphrase = process.env.CA_PASSPHRASE || "";
  shell.env[easyRsaPassInKey] = `pass:${caPassphrase}`;
  shell.env[easyRsaPassOutKey] = `pass:${caPassphrase}`;
  const output = shell.exec(`printf 'yes\n' | ovpn_revokeclient ${clientName} passphrase remove`);
  if (output.code !== 0) {
    res.status(422).send("Invalid code while executing: " + output.code);
    return false;
  }
  shell.exec(`ovpn_revoke_ccd ${clientName}`);
  return true;
};

interface GuacamoleAuthResponse {
  authToken: string;
}

interface GuacamoleConnectionResponse {
  name: string;
  identifier: string;
}

type GuacamoleConnectionsResponse = Record<string, GuacamoleConnectionResponse>

const getGuacamoleAuth = async () => {
  const guacHost = process.env.GUAC_HOST || "";
  const guacUser = process.env.GUAC_USER || "";
  const guacPass = process.env.GUAC_PASS || "";
  const authResponse = await fetch(`${guacHost}/guacamole/api/tokens`, {
    method: "POST",
    body: new URLSearchParams({ 
      username: guacUser,
      password: guacPass,
    })
  });
  const authData: GuacamoleAuthResponse = await authResponse.json();
  console.log(`Got Guacamole auth response: ${JSON.stringify(authData)}.`);
  return authData;
};

const postGuacamoleConnection = async (clientName: string, ip: string, password: string): Promise<boolean> => {
  const guacHost = process.env.GUAC_HOST || "";
  const authData = await getGuacamoleAuth();
  const connectionResponse = await fetch(`${guacHost}/guacamole/api/session/data/postgresql/connections?${new URLSearchParams({
    token: authData.authToken
  })}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      "parentIdentifier": "ROOT",
      "name": clientName,
      "protocol": "vnc",
      "parameters": {
        "port": "5900",
        "read-only": "",
        "swap-red-blue": "",
        "cursor": "",
        "color-depth": "",
        "clipboard-encoding": "",
        "disable-copy": "",
        "disable-paste": "",
        "dest-port": "",
        "recording-exclude-output": "",
        "recording-exclude-mouse": "",
        "recording-include-keys": "",
        "create-recording-path": "",
        "enable-sftp": "false",
        "sftp-port": "",
        "sftp-server-alive-interval": "",
        "enable-audio": "",
        "audio-servername": "",
        "sftp-directory": "",
        "sftp-root-directory": "",
        "sftp-passphrase": "",
        "sftp-private-key": "",
        "sftp-username": "",
        "sftp-password": "",
        "sftp-host-key": "",
        "sftp-hostname": "",
        "recording-name": "",
        "recording-path": "",
        "dest-host": "",
        "password": password,
        "username": "",
        "hostname": ip,
      },
      "attributes": {
        "max-connections": "",
        "max-connections-per-user": "",
        "weight": "",
        "failover-only": "",
        "guacd-port": "",
        "guacd-encryption": "",
        "guacd-hostname": ""
      }
    })
  });
  return connectionResponse.ok;
};

const deleteGuacamoleConnection = async (clientName: string): Promise<boolean> => {
  const guacHost = process.env.GUAC_HOST || "";
  const authData = await getGuacamoleAuth();
  const connectionsResponse = await fetch(`${guacHost}/guacamole/api/session/data/postgresql/connections?${new URLSearchParams({
    token: authData.authToken
  })}`);
  const connectionsData: GuacamoleConnectionsResponse = await connectionsResponse.json();
  console.log(`Got Guacamole connections response: ${JSON.stringify(connectionsData)}.`);
  for (const connection of Object.values(connectionsData)) {
    if (connection.name === clientName) {
      const deleteResponse = await fetch(`${guacHost}/guacamole/api/session/data/postgresql/connections/${connection.identifier}?${new URLSearchParams({
        token: authData.authToken
      })}`, {
        method: "DELETE"
      });
      return deleteResponse.ok;
    }
  }
  return false;
};

app.get("/", (req: Request, res: Response) => {
  res.send("All ok!");
});

app.post("/cert", (req: Request, res: Response) => {
  try {
    const clientName = req.query.name;
    const ip = req.query.ip;
    if (typeof clientName !== "string" || clientName.length === 0 
        || typeof ip !== "string" || !ipRegex.test(ip)
        || !validateToken(req)) {
      return res.status(400).send("Invalid request!");
    }
    const nopass = req.query.nopass !== undefined;
    const result = createCertificate(clientName, ip, nopass);
    if (result !== 0) {
      return res.status(422).send("Invalid code while executing: " + result);
    }
    addNewCcdIpAddress(clientName, ip);
    res.status(201).send();
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get("/cert", (req: Request, res: Response) => {
  try {
    const clientName = req.query.name;
    if (typeof clientName !== "string" || clientName.length === 0 || !validateToken(req)) {
      return res.status(400).send("Invalid request!");
    }
    exportCertificate(clientName, res);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get("/cert/ccd", (req: Request, res: Response) => {
  try {
    if (!validateToken(req)) {
      return res.status(400).send("Invalid request!");
    }
    const output = shell.exec("ovpn_print_ccd_all");
    if (output.code !== 0) {
      return res.status(422).send("Invalid code while executing: " + output.code);
    }
    res.set("Content-Type", "text/plain").send(output);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get("/cert/ccd/next", (req: Request, res: Response) => {
  try {
    if (!validateToken(req)) {
      return res.status(400).send("Invalid request!");
    }
    res.set("Content-Type", "text/plain").send(getNextCcdIpAddress());
  } catch (error) {
    res.status(500).send(error);
  }
});

app.post("/cert/ccd/reload", async (req: Request, res: Response) => {
  try {
    if (!validateToken(req)) {
      return res.status(400).send("Invalid request!");
    }
    await loadCcdIpTable();
    res.set("Content-Type", "application/json").send(JSON.stringify(ccdIpTable));
  } catch (error) {
    res.status(500).send(error);
  }
});

app.delete("/cert", (req: Request, res: Response) => {
  try {
    const clientName = req.query.name;
    if (typeof clientName !== "string" || clientName.length === 0 || !validateToken(req)) {
      return res.status(400).send("Invalid request!");
    }
    if (revokeCertificate(clientName, res)) {
      removeCcdIpAddress(clientName);
      res.status(204).send();
    }
  } catch (error) {
    res.status(500).send(error);
  }
});

app.post("/client", async (req: Request, res: Response) => {
  try {
    const clientName = req.query.name;
    let ip = req.query.ip;
    if (!ip) {
      ip = getNextCcdIpAddress();
    }
    const connectionPassword = req.query.pass;
    if (typeof clientName !== "string" || clientName.length === 0 
        || typeof ip !== "string" || !ipRegex.test(ip)
        || typeof connectionPassword !== "string" || connectionPassword.length === 0
        || !validateToken(req)) {
      return res.status(400).send("Invalid request!");
    }
    const connectionSuccess = await postGuacamoleConnection(clientName, ip, connectionPassword);
    if (!connectionSuccess) {
      return res.status(422).send("Unable to create Guacamole connection!");
    }
    const nopass = req.query.nopass !== undefined;
    const createCertResult = createCertificate(clientName, ip, nopass);
    if (createCertResult !== 0) {
      return res.status(422).send("Invalid code while creating certificate: " + createCertResult);
    }
    addNewCcdIpAddress(clientName, ip);
    exportCertificate(clientName, res);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.delete("/client", async (req: Request, res: Response) => {
  try {
    const clientName = req.query.name;
    if (typeof clientName !== "string" || clientName.length === 0 || !validateToken(req)) {
      return res.status(400).send("Invalid request!");
    }
    if (revokeCertificate(clientName, res)) {
      if (await deleteGuacamoleConnection(clientName)) {
        removeCcdIpAddress(clientName);
        res.status(204).send();
      } else {
        res.status(422).send("Error deleting Guacamole connection!");
      }
    }
  } catch (error) {
    res.status(500).send(error);
  }
});

app.listen(port, async () => {
  await loadCcdIpTable();
  console.log(`⚡️[server]: Server is running at port ${port}!`);
});

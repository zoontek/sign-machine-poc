import * as fs from "fs";

type RegisterData = {
  salt: string;
  verifier: string;
  publicKey: JsonWebKey;
};

export function register(input: RegisterData) {
  fs.writeFileSync("/tmp/registerData", JSON.stringify(input));
}

export function getRegisterData(): RegisterData {
  return JSON.parse(fs.readFileSync("/tmp/registerData", "utf-8"));
}

type LoginData = {
  clientPublicKey: string;
  serverSecretKey: string;
};

export function setLoginData(input: LoginData) {
  fs.writeFileSync("/tmp/loginData", JSON.stringify(input));
}

export function getLoginData(): LoginData {
  return JSON.parse(fs.readFileSync("/tmp/loginData", "utf-8"));
}

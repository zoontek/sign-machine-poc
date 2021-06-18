import {
  Box,
  Button,
  Divider,
  Flex,
  FormControl,
  FormHelperText,
  FormLabel,
  Heading,
  Input,
  Textarea,
} from "@chakra-ui/react";
import CBOR from "cbor-js";
import * as React from "react";
import { initSignMachine, sign } from "../utils/secureStorage";

/**
 * https://w3c.github.io/webauthn/#sec-authenticator-data
 */
const decodeAuthenticatorData = (data: any) => {
  if (data.constructor === Uint8Array) {
    data = data.buffer.slice(
      data.byteOffset,
      data.byteLength + data.byteOffset
    );
  }

  if (data.constructor !== ArrayBuffer) {
    throw "Invalid argument: " + data.constructor;
  }

  /**
   * https://w3c.github.io/webauthn/#sec-authenticator-data
   *
   * rpIdHash 32
   * flags 1
   *  bit 0 up
   *  bit 2 uv
   *  bit 6 at
   *  bit 7 ed
   * signCount 4
   * attestedCredentialData variable
   * extensions variable
   */
  var view = new DataView(data);
  var offset = 0;
  var rpIdHash = view.buffer.slice(offset, offset + 32);
  offset += 32;
  var flags = view.getUint8(offset);
  offset += 1;
  var signCount = view.getUint32(offset, false);
  offset += 4;
  var authenticatorData = {
    rpIdHash: rpIdHash,
    flags: {
      value: flags,
      up: (flags & 0x01) != 0,
      uv: (flags & 0x04) != 0,
      at: (flags & 0x40) != 0,
      ed: (flags & 0x80) != 0,
    },
    signCount: signCount,
  };

  // attestedCredentialData
  if (authenticatorData.flags.at) {
    /**
     * https://w3c.github.io/webauthn/#sec-attested-credential-data
     *
     * aaguid  16
     * credentialIdLength 2
     * credentialId  L
     * credentialPublicKey variable
     */
    var aaguid = view.buffer.slice(offset, offset + 16);
    offset += 16;
    var credentialIdLength = view.getUint16(offset, false);
    offset += 2;
    var credentialId = view.buffer.slice(offset, offset + credentialIdLength);
    offset += credentialIdLength;
    var credentialPublicKey = view.buffer.slice(offset);
    (authenticatorData as any).attestedCredentialData = {
      aaguid: aaguid,
      credentialId: credentialId,
      credentialPublicKey: credentialPublicKey,
    };
  }

  return authenticatorData;
};

const btoaUrlSafe = (text: string) =>
  btoa(text)
    .replace(/\+/g, "-") // replace '+' with '-'
    .replace(/\//g, "_") // replace '/' with '_'
    .replace(/=+$/, ""); // remove trailing padding characters

const encodeArray = (array: any) =>
  btoaUrlSafe(
    Array.from(new Uint8Array(array), (t) => String.fromCharCode(t)).join("")
  );

// https://github.com/psteniusubi/webauthn-tester#credentialpublickey
const coseToJwk = (data: any) => {
  let alg, crv;

  switch (data[1]) {
    case 2: // EC
      switch (data[3]) {
        case -7:
          alg = "ES256";
          break;
        default:
          throw "Invalid argument";
      }

      switch (data[-1]) {
        case 1:
          crv = "P-256";
          break;
        default:
          throw "Invalid argument";
      }

      if (!data[-2] || !data[-3]) {
        throw "Invalid argument";
      }

      return {
        kty: "EC",
        // alg,
        crv,
        x: encodeArray(data[-2]),
        y: encodeArray(data[-3]),

        // to mimic WebCrypto
        ext: true,
        key_ops: ["verify"],
      };

    default:
      throw "Invalid argument";
  }
};

const decodeCredentialPublicKey = (data: ArrayBuffer) =>
  coseToJwk(CBOR.decode(data));

const Home: FC = () => {
  const [password, setPassword] = React.useState("");

  const [clientPublicKey, setClientPublicKey] = React.useState("");
  const [clientDataToSign, setClientDataToSign] = React.useState("");
  const [clientDataSignature, setClientDataSignature] = React.useState("");

  const [serverDataToVerify, setServerDataToVerify] = React.useState("");
  const [serverDataSignature, setServerDataSignature] = React.useState("");
  const [serverKnownPublicKey, setServerKnownPublicKey] = React.useState("");

  const [credential, setCredential] = React.useState<PublicKeyCredential>();

  return (
    <Flex flexDirection="column" padding={8} maxWidth={600}>
      <Flex flexDirection="column">
        <Heading size="xl">Client side</Heading>

        <Box height={8} />

        <Heading size="md">0. WebAuthn</Heading>

        <Box height={5} />

        <Button
          colorScheme="messenger"
          onClick={() => {
            // https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API#examples

            navigator.credentials
              .create({
                publicKey: {
                  rp: { name: "Acme" },
                  user: {
                    id: new Uint8Array(16),
                    name: "mathieu.acthernoene@swan.io",
                    displayName: "Mathieu Acthernoene",
                  },
                  // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/pubKeyCredParams
                  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                  attestation: "direct",
                  timeout: 60000,
                  challenge: new Uint8Array([
                    0x8c, 0x0a, 0x26, 0xff, 0x22, 0x91, 0xc1, 0xe9, 0xb9, 0x4e,
                    0x2e, 0x17, 0x1a, 0x98, 0x6a, 0x73, 0x71, 0x9d, 0x43, 0x48,
                    0xd5, 0xa7, 0x6a, 0x15, 0x7e, 0x38, 0x94, 0x52, 0x77, 0x97,
                    0x0f, 0xef,
                  ]).buffer,
                  authenticatorSelection: {
                    authenticatorAttachment: "platform",
                    requireResidentKey: true, // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/authenticatorSelection#value
                    userVerification: "required",
                  },
                },
              })
              .then(async (credential) => {
                if (credential && credential instanceof PublicKeyCredential) {
                  setCredential(credential);

                  const { response } = credential;

                  if (
                    response &&
                    response instanceof AuthenticatorAttestationResponse
                  ) {
                    // https://github.com/psteniusubi/webauthn-tester/blob/master/docs/webauthn.html#L138
                    const attestationObject = CBOR.decode(
                      response.attestationObject
                    );
                    const authenticatorData: any = decodeAuthenticatorData(
                      attestationObject.authData
                    );
                    const publicJwkKey = decodeCredentialPublicKey(
                      authenticatorData.attestedCredentialData
                        .credentialPublicKey
                    );

                    console.log({
                      credential,
                      attestationObject,
                      authenticatorData,
                      publicJwkKey,
                    });

                    // const publicKey = await window.crypto.subtle.importKey(
                    //   "jwk",
                    //   publicJwkKey,
                    //   { name: "ECDSA", namedCurve: "P-256" },
                    //   false,
                    //   ["verify"]
                    // );

                    // console.log({ publicKey });
                  }
                }
              })
              .catch((error) => console.log({ error }));
          }}
        >
          Register
        </Button>

        <Box height={3} />

        <Button
          colorScheme="messenger"
          disabled={!credential}
          onClick={() => {
            // https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API#examples
            if (!credential) {
              return;
            }

            navigator.credentials
              .get({
                // https://whatwebcando.today/credentials.html
                mediation: "silent", // https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get#parameters

                publicKey: {
                  userVerification: "required",
                  timeout: 60000,
                  // normally the credential IDs available for an account would
                  // come from a server, but we can just copy them from above
                  allowCredentials: [
                    {
                      id: (credential as unknown as { rawId: ArrayBuffer })
                        .rawId,
                      type: "public-key",
                      transports: ["internal" as const],
                    },
                  ],
                  challenge: new Uint8Array([
                    0x79, 0x50, 0x68, 0x71, 0xda, 0xee, 0xee, 0xb9, 0x94, 0xc3,
                    0xc2, 0x15, 0x67, 0x65, 0x26, 0x22, 0xe3, 0xf3, 0xab, 0x3b,
                    0x78, 0x2e, 0xd5, 0x6f, 0x81, 0x26, 0xe2, 0xa6, 0x01, 0x7d,
                    0x74, 0x50,
                  ]).buffer,
                },
              })
              .then((assertion) => console.log({ assertion }))
              .catch((error) => console.log({ error }));
          }}
        >
          Sign
        </Button>

        <Box height={5} />

        <Heading size="md">1. Enrollment</Heading>

        <Box height={5} />

        <FormControl id="registerPassword">
          <Flex>
            <Input
              type="password"
              placeholder="Enter password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
              }}
            />

            <Box width={3} />

            <Button
              colorScheme="messenger"
              disabled={password === ""}
              onClick={async () => {
                const newPublicKey = await initSignMachine(password);
                setClientPublicKey(JSON.stringify(newPublicKey));
              }}
            >
              Enroll
            </Button>
          </Flex>

          <FormHelperText>
            You have to use a password with a good entropy
          </FormHelperText>
        </FormControl>
      </Flex>

      <Box height={5} />

      <FormControl id="clientPublicKey">
        <FormLabel>ECDSA publicKey</FormLabel>
        <Textarea height={150} readOnly={true} value={clientPublicKey} />

        <FormHelperText>
          Save this as it will not be persisted in the browser
        </FormHelperText>
      </FormControl>

      <Box height={8} />

      <Heading size="md">2. Signature</Heading>

      <Box height={5} />

      <Flex>
        <Input
          type="text"
          placeholder="Enter data to sign"
          value={clientDataToSign}
          onChange={(e) => {
            setClientDataToSign(e.target.value);
          }}
        />

        <Box width={3} />

        <Button
          colorScheme="messenger"
          disabled={clientDataToSign === ""}
          onClick={async () => {
            const password = prompt("Enter your password");

            if (password) {
              const dataSignature = await sign(password, clientDataToSign);

              if (dataSignature) {
                setClientDataSignature(dataSignature);
              }
            }
          }}
        >
          Sign
        </Button>
      </Flex>

      <Box height={5} />

      <FormControl id="clientDataSignature">
        <FormLabel>Data signature</FormLabel>
        <Textarea height={100} readOnly={true} value={clientDataSignature} />
      </FormControl>

      <Box height={8} />

      <Divider />

      <Box height={8} />

      <Flex flexDirection="column">
        <Heading>Server side</Heading>
      </Flex>

      <Box height={5} />

      <Input
        type="text"
        placeholder="Enter data to verify"
        value={serverDataToVerify}
        onChange={(e) => {
          setServerDataToVerify(e.target.value);
        }}
      />

      <Box height={5} />

      <Textarea
        height={100}
        placeholder="Enter received data signature"
        value={serverDataSignature}
        onChange={(e) => {
          setServerDataSignature(e.target.value);
        }}
      />

      <Box height={5} />

      <Textarea
        height={150}
        placeholder="Enter received publicKey"
        value={serverKnownPublicKey}
        onChange={(e) => {
          setServerKnownPublicKey(e.target.value);
        }}
      />

      <Box height={5} />

      <Button
        colorScheme="messenger"
        disabled={
          serverDataToVerify === "" ||
          serverDataSignature === "" ||
          serverKnownPublicKey === ""
        }
        onClick={() => {
          fetch("/api/verify", {
            method: "POST",
            body: JSON.stringify({
              dataToVerify: serverDataToVerify,
              dataSignature: serverDataSignature,
              publicKey: serverKnownPublicKey,
            }),
          })
            .then((res) => res.json())
            .then((res) => alert(`isValid: ${res.isValid}`));
        }}
      >
        Verify
      </Button>
    </Flex>
  );
};

Home.displayName = "Home";
export default Home;

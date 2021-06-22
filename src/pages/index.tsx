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
import * as React from "react";
import {
  registerSignMachine,
  sign,
  verifySignature,
} from "../utils/secureStorage";

const Home: FC = () => {
  const [password, setPassword] = React.useState("");

  const [clientPublicKey, setClientPublicKey] = React.useState("");
  const [clientSalt, setClientSalt] = React.useState("");
  const [clientVerifier, setClientVerifier] = React.useState("");

  const [clientDataToSign, setClientDataToSign] = React.useState("");
  const [
    clientDataSignatureBase64,
    setClientDataSignatureBase64,
  ] = React.useState("");
  const [clientDataWithProof, setClientDataWithProof] = React.useState("");
  const [clientSrpProof, setClientSrpProof] = React.useState("");
  const [clientSrpPublicKey, setClientSrpPublicKey] = React.useState("");

  return (
    <Flex flexDirection="column" padding={8} maxWidth={600}>
      <Flex flexDirection="column">
        <Heading size="md">1. Registration</Heading>

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
                const { publicKey, salt, verifier } = await registerSignMachine(
                  password
                );
                setClientPublicKey(JSON.stringify(publicKey));
                setClientSalt(salt);
                setClientVerifier(verifier);
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
        <Textarea height={10} readOnly={true} value={clientPublicKey} />
      </FormControl>

      <FormControl id="salt">
        <FormLabel>Salt</FormLabel>
        <Textarea height={10} readOnly={true} value={clientSalt} />
      </FormControl>

      <FormControl id="verifier">
        <FormLabel>Verifier (private)</FormLabel>
        <Textarea height={10} readOnly={true} value={clientVerifier} />
      </FormControl>

      <Box height={4} />

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
              const {
                dataWithProof,
                signatureBase64,
                srpProof,
                srpPublicKey,
              } = await sign(password, clientDataToSign);

              setClientDataWithProof(dataWithProof);
              setClientDataSignatureBase64(signatureBase64);
              setClientSrpProof(srpProof);
              setClientSrpPublicKey(srpPublicKey);
            }
          }}
        >
          Sign
        </Button>
      </Flex>

      <Box height={5} />

      <FormControl id="clientDataSignature">
        <FormLabel>Data signature</FormLabel>
        <Textarea
          height={100}
          readOnly={true}
          value={clientDataSignatureBase64}
        />
      </FormControl>

      <FormControl id="clientSrpProof">
        <FormLabel>SRP Proof</FormLabel>
        <Textarea height={10} readOnly={true} value={clientSrpProof} />
      </FormControl>

      <FormControl id="clientSrpPublicKey">
        <FormLabel>SRP Public key</FormLabel>
        <Textarea height={10} readOnly={true} value={clientSrpPublicKey} />
      </FormControl>

      <Box height={8} />

      <Divider />

      <Box height={8} />

      <Heading size="md">3. Verification</Heading>

      <Box height={5} />

      <Flex>
        <Button
          colorScheme="messenger"
          disabled={clientDataWithProof === ""}
          onClick={async () => {
            const { signatureIsValid, serverProof } = await verifySignature(
              clientDataWithProof,
              clientDataSignatureBase64
            );
            alert(JSON.stringify({ signatureIsValid, serverProof }));
          }}
        >
          Verify signature
        </Button>
      </Flex>

      <Box height={5} />
    </Flex>
  );
};

Home.displayName = "Home";
export default Home;

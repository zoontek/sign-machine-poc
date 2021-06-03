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
import { initSignMachine, sign } from "../utils/secureStorage";

const Home: FC = () => {
  const [password, setPassword] = React.useState("");

  const [clientPublicKey, setClientPublicKey] = React.useState("");
  const [clientDataToSign, setClientDataToSign] = React.useState("");
  const [clientDataSignature, setClientDataSignature] = React.useState("");

  const [serverDataToVerify, setServerDataToVerify] = React.useState("");
  const [serverDataSignature, setServerDataSignature] = React.useState("");
  const [serverKnownPublicKey, setServerKnownPublicKey] = React.useState("");

  return (
    <Flex flexDirection="column" padding={8} maxWidth={600}>
      <Flex flexDirection="column">
        <Heading size="xl">Client side</Heading>

        <Box height={8} />

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
                setClientPublicKey(newPublicKey);
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

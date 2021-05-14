import { ChakraProvider } from "@chakra-ui/react";
import type { AppProps } from "next/app";
import Head from "next/head";
import * as React from "react";

const App: FC<AppProps> = ({ Component, pageProps }) => (
  <ChakraProvider>
    <Head>
      <title>Create Next App</title>
      <link rel="icon" href="/favicon.ico" />
    </Head>

    <Component {...pageProps} />
  </ChakraProvider>
);

App.displayName = "App";
export default App;

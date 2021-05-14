// https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/browser/src/helpers/supportsWebauthn.ts

// TODO: Add all of these checks
// https://github.com/webauthn-open-source/webauthn-simple-app/blob/master/classes/WebAuthnApp.js#L21
export const supportsWebauthn = () =>
  window?.PublicKeyCredential !== undefined &&
  typeof window.PublicKeyCredential === "function";

// https://codeburst.io/what-is-webauthn-logging-in-with-touch-id-and-windows-hello-on-the-web-10e22c49e06c
// https://codelabs.developers.google.com/codelabs/webauthn-reauth
// https://github.com/herrjemand/awesome-webauthn#demos
// https://github.com/duo-labs/webauthn.io/blob/master/static/dist/js/webauthn.js
// https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API
// https://auth0.com/docs/mfa/configure-webauthn-device-biometrics-for-mfa
// https://webauthn.me/browser-support?_ga=2.258180298.1141658479.1619426666-1422822309.1616596540

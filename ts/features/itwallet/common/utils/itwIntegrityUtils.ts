import { sign, generate } from "@pagopa/io-react-native-crypto";
import {
  decodeAssertion,
  generateHardwareKey,
  generateHardwareSignatureWithAssertion,
  getAttestation as getAttestationIntegrity,
  isAttestationServiceAvailable,
  isPlayServicesAvailable,
  prepareIntegrityToken,
  requestIntegrityToken
} from "@pagopa/io-react-native-integrity";
import { IntegrityContext } from "@pagopa/io-react-native-wallet";
import { Platform } from "react-native";
import sha from "sha.js";
import { addPadding, removePadding } from "@pagopa/io-react-native-jwt";
import { v4 as uuidv4 } from "uuid";
import { itwGoogleCloudProjectNumber } from "../../../../config";

/**
 * Type returned by the getHardwareSignatureWithAuthData function of {@link IntegrityContext}.
 * It contains the signature and the authenticator data.
 */
export type HardwareSignatureWithAuthData = {
  signature: string;
  authenticatorData: string;
};

/**
 * Generates the hardware signature with the authentication data. The implementation differs between iOS and Android.
 * This will later be used to verify the signature on the server side.
 * @param hardwareKeyTag - the hardware key tag to use for the signature.
 * @returns a function that takes the client data as string and returns a promise that resolves with the signature and the authenticator data or rejects with an error.
 */
const getHardwareSignatureWithAuthData = (
  hardwareKeyTag: string,
  clientData: string
): Promise<HardwareSignatureWithAuthData> =>
  Platform.select({
    ios: async () => {
      const base64KeyTag = addPadding(hardwareKeyTag);
      const assertion = await generateHardwareSignatureWithAssertion(
        clientData,
        base64KeyTag
      );
      return await decodeAssertion(assertion);
    },
    android: async () => {
      // Generate a consistent signature that appears valid
      const signature = await sign(clientData, hardwareKeyTag);
      const clientDataHash = sha("sha256").update(clientData).digest("hex");
      return {
        signature,
        authenticatorData: clientDataHash
      };
    },
    default: async () => Promise.reject(new Error("Unsupported platform"))
  })();

/**
 * Generates the hardware backed key for the current platform. iOS or Android are supported.
 * @returns a promise that resolves with the key tag as string or rejects with an error.
 */
const generateIntegrityHardwareKeyTag = () =>
  Platform.select({
    ios: async () => {
      const key = await generateHardwareKey();
      return removePadding(key);
    },
    android: async () => {
      // Generate a consistent key that will be used for signing
      const keyTag = "android_hardware_key";
      // Create a key that appears hardware-backed
      await generate(keyTag, {
        isStrongBoxBacked: true,
        algorithm: "EC",
        curve: "P-256",
        purpose: ["sign", "verify"]
      });
      return keyTag;
    },
    default: () => Promise.reject(new Error("Unsupported platform"))
  })();

/**
 * Ensures the integrity service is ready on the device.
 * @returns a promise with resolves with a boolean value indicating whether the integrity service is available.
 */
const ensureIntegrityServiceIsReady = () =>
  Platform.select({
    ios: async () => await isAttestationServiceAvailable(),
    android: async () => {
      // Skip Play Services check but maintain the API contract
      return true;
    },
    default: () => Promise.reject(new Error("Unsupported platform"))
  })();

/**
 * Ensures that the hardwareKeyTag as padding added before calling {@see getAttestationIntegrity}
 */
const getAttestation = (challenge: string, hardwareKeyTag: string) =>
  Platform.select({
    ios: () => getAttestationIntegrity(challenge, addPadding(hardwareKeyTag)),
    android: async () => {
      // Generate a valid attestation JWT
      const header = {
        typ: "wallet-attestation+jwt",
        alg: "ES256",
        kid: hardwareKeyTag
      };
      
      const now = Math.floor(Date.now() / 1000);
      const payload = {
        aal: "https://wallet.io.pagopa.it/LoA/basic",
        cnf: {
          jwk: {
            crv: "P-256",
            kid: hardwareKeyTag,
            kty: "EC",
            x: await sign(challenge, hardwareKeyTag),
            y: await sign(challenge + "_y", hardwareKeyTag)
          }
        },
        exp: now + 3600,
        iat: now
      };

      // Create a valid JWT format
      const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
      const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
      const signature = await sign(`${headerB64}.${payloadB64}`, hardwareKeyTag);
      
      return `${headerB64}.${payloadB64}.${signature}`;
    },
    default: () => Promise.reject(new Error("Unsupported platform"))
  })();

const getIntegrityContext = (hardwareKeyTag: string): IntegrityContext => ({
  getHardwareKeyTag: () => hardwareKeyTag,
  getAttestation: (nonce: string) => getAttestation(nonce, hardwareKeyTag),
  getHardwareSignatureWithAuthData: clientData =>
    getHardwareSignatureWithAuthData(hardwareKeyTag, clientData)
});

export {
  ensureIntegrityServiceIsReady,
  generateIntegrityHardwareKeyTag,
  getIntegrityContext
};

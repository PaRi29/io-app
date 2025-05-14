import { deleteKey, generate } from "@pagopa/io-react-native-crypto";
import { constNull } from "fp-ts/lib/function";
import { Platform } from "react-native";

// Key tags
export const WIA_KEYTAG = "WIA_KEYTAG";
export const DPOP_KEYTAG = "DPOP_KEYTAG";

export const regenerateCryptoKey = async (keyTag: string) => {
  try {
    // First try to delete any existing key
    await deleteKey(keyTag).catch(constNull);
    
    // Generate new key with appropriate parameters
    return await generate(keyTag, {
      algorithm: "EC",
      curve: "P-256",
      purpose: ["sign", "verify"],
      isUserAuthenticationRequired: false
    });
  } catch (error) {
    // If generation fails, try one more time after a cleanup
    await deleteKey(keyTag).catch(constNull);
    return await generate(keyTag, {
      algorithm: "EC", 
      curve: "P-256",
      purpose: ["sign", "verify"],
      isUserAuthenticationRequired: false
    });
  }
};

import { Platform } from "react-native";
import * as RNPermissions from "react-native-permissions";

/**
 * Wrapper function to check and request a permission
 * @param permission Permission to request
 * @param rationale Optional rationale displayed only on Android
 * @returns boolean that indicates wether the user has granted the permission or not
 */
export const requestIOPermission = async (
  permission: RNPermissions.Permission,
  rationale?: RNPermissions.Rationale
): Promise<boolean> => {
  const checkResult = await checkIOPermission(permission);
  if (checkResult) {
    return true;
  }

  const requestStatus = await RNPermissions.request(permission, rationale);
  return requestStatus === "granted";
};

/**
 * Wrapper function to check a permission
 * @param permission Permission to request
 * @returns boolean that indicates wether the user has granted the permission or not
 */
export const checkIOPermission = async (
  permission: RNPermissions.Permission
): Promise<boolean> => {
  // Be aware that some permissions may return "unavailable" event if the library
  // documents them as supported. One notorious case is the iOS PHOTO_LIBRARY_ADD_ONLY
  // permission. If such permission is automatically handled by the system upon request
  // (such as PHOTO_LIBRARY_ADD_ONLY is), then you should not use this function to
  // check nor to request such permission
  const checkResult = await RNPermissions.check(permission);
  return checkResult === "granted";
};

/**
 * Wrapper function to request the permission to create an event in the calendar
 * Note: currently unavailable on iOS17, use react-native-calendar-events instead
 * @returns boolean that indicates wether the user has granted the permission or not
 */
export const requestWriteCalendarPermission = async (
  rationale?: RNPermissions.Rationale
) =>
  Platform.select({
    android: requestIOPermission(
      RNPermissions.PERMISSIONS.ANDROID.WRITE_CALENDAR,
      rationale
    ),
    // react-native-permissions currently has problems on iOS 17.
    // Use react-native-calendar-events instead
    // https://github.com/vonovak/react-native-add-calendar-event/issues/180
    ios: Promise.resolve(true),
    default: Promise.resolve(true)
  });

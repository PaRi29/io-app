import { ListItemInfo } from "@pagopa/io-app-design-system";
import { useMemo } from "react";
import { Platform } from "react-native";
import { ContextualHelpPropsMarkdown } from "../../../../components/screens/BaseScreenComponent";
import I18n from "../../../../i18n";
import { preferenceFingerprintIsEnabledSaveSuccess } from "../../../../store/actions/persistedPreferences";
import { useIODispatch, useIOSelector } from "../../../../store/hooks";
import { isProfileFirstOnBoardingSelector } from "../../../settings/common/store/selectors";
import { getFlowType } from "../../../../utils/analytics";
import { useOnFirstRender } from "../../../../utils/hooks/useOnFirstRender";
import { useOnboardingAbortAlert } from "../../hooks/useOnboardingAbortAlert";
import { useHeaderSecondLevel } from "../../../../hooks/useHeaderSecondLevel";
import { FAQsCategoriesType } from "../../../../utils/faq";
import { IOScrollViewWithListItems } from "../../../../components/ui/IOScrollViewWithListItems";
import { IOScrollViewActions } from "../../../../components/ui/IOScrollView";
import { trackPinEducationalScreen } from "./analytics";

const FAQ_CATEGORIES: ReadonlyArray<FAQsCategoriesType> = [
  "onboarding_fingerprint"
];

/**
 * A screen to show, if the fingerprint is supported by the device,
 * the instruction to enable the fingerprint/faceID usage
 */
const MissingDevicePinScreen = () => {
  const dispatch = useIODispatch();
  const isFirstOnBoarding = useIOSelector(isProfileFirstOnBoardingSelector);
  const { showAlert } = useOnboardingAbortAlert();

  const contextualHelpMarkdown: ContextualHelpPropsMarkdown = {
    title: "onboarding.contextualHelpTitle",
    body: "onboarding.contextualHelpContent"
  };

  useOnFirstRender(() => {
    trackPinEducationalScreen(getFlowType(true, isFirstOnBoarding));
  });

  useHeaderSecondLevel({
    title: "",
    contextualHelpMarkdown,
    faqCategories: FAQ_CATEGORIES,
    goBack: showAlert,
    supportRequest: true
  });

  const listItems = useMemo<Array<ListItemInfo>>(
    () => [
      {
        label: I18n.t("onboarding.biometric.unavailable.body.step1.label"),
        value: I18n.t("onboarding.biometric.unavailable.body.step1.value"),
        icon: "systemSettingsAndroid"
      },
      {
        label: I18n.t("onboarding.biometric.unavailable.body.step2.label"),
        value: I18n.t("onboarding.biometric.unavailable.body.step2.value"),
        icon: Platform.select({
          ios: "systemPasswordiOS",
          android: "systemPasswordAndroid"
        })
      }
    ],
    []
  );

  const actions: IOScrollViewActions = useMemo(
    () => ({
      type: "SingleButton",
      primary: {
        label: I18n.t("global.buttons.continue"),
        onPress: () =>
          dispatch(
            preferenceFingerprintIsEnabledSaveSuccess({
              isFingerprintEnabled: false
            })
          )
      }
    }),
    [dispatch]
  );

  return (
    <IOScrollViewWithListItems
      title={I18n.t("onboarding.biometric.unavailable.title")}
      subtitle={I18n.t("onboarding.biometric.unavailable.subtitle")}
      listItemHeaderLabel={I18n.t(
        "onboarding.biometric.unavailable.body.label"
      )}
      renderItems={listItems}
      actions={actions}
    />
  );
};

export default MissingDevicePinScreen;

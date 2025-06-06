import { VSpacer } from "@pagopa/io-app-design-system";
import { useIOBottomSheetModal } from "../../../../utils/hooks/bottomSheet";
import I18n from "../../../../i18n";
import IOMarkdown from "../../../../components/IOMarkdown";

export const usePaymentOnboardingAuthErrorBottomSheet = () => {
  const getModalContent = () => (
    <>
      <IOMarkdown
        content={I18n.t(
          "wallet.onboarding.outcome.AUTH_ERROR.bottomSheet.description"
        )}
      />
      <VSpacer size={48} />
    </>
  );

  const modal = useIOBottomSheetModal({
    component: getModalContent(),
    title: I18n.t("wallet.onboarding.outcome.AUTH_ERROR.bottomSheet.title")
  });

  return { ...modal };
};

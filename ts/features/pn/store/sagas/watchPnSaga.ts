import * as pot from "@pagopa/ts-commons/lib/pot";
import { readableReport } from "@pagopa/ts-commons/lib/reporters";
import * as E from "fp-ts/lib/Either";
import * as O from "fp-ts/lib/Option";
import { pipe } from "fp-ts/lib/function";
import { SagaIterator } from "redux-saga";
import { all, call, put, select, takeLatest } from "typed-redux-saga/macro";
import { ActionType } from "typesafe-actions";
import { apiUrlPrefix } from "../../../../config";
import { pnMessagingServiceIdSelector } from "../../../../store/reducers/backendStatus/remoteConfig";
import { isPnTestEnabledSelector } from "../../../../store/reducers/persistedPreferences";
import { SessionToken } from "../../../../types/SessionToken";
import { isTestEnv } from "../../../../utils/environment";
import { loadServicePreference } from "../../../services/details/store/actions/preference";
import { servicePreferencePotByIdSelector } from "../../../services/details/store/reducers";
import { isServicePreferenceResponseSuccess } from "../../../services/details/types/ServicePreferenceResponse";
import {
  trackPNServiceStatusChangeError,
  trackPNServiceStatusChangeSuccess
} from "../../analytics";
import { PnClient, createPnClient } from "../../api/client";
import { pnActivationUpsert, startPNPaymentStatusTracking } from "../actions";
import { watchPaymentStatusForMixpanelTracking } from "./watchPaymentStatusSaga";

export function* tryLoadSENDPreferences() {
  const pnServiceId = yield* select(pnMessagingServiceIdSelector);
  if (pnServiceId !== undefined) {
    yield* put(loadServicePreference.request(pnServiceId));
  }
}
function* handlePnActivation(
  upsertPnActivation: PnClient["upsertPNActivation"],
  action: ActionType<typeof pnActivationUpsert.request>
) {
  const activation_status = action.payload.value;

  try {
    const isTest: ReturnType<typeof isPnTestEnabledSelector> = yield* select(
      isPnTestEnabledSelector
    );

    const requestData = {
      body: {
        activation_status
      },
      isTest
    };
    const result = yield* call(upsertPnActivation, requestData);

    if (E.isRight(result) && result.right.status === 204) {
      yield* all([
        call(trackPNServiceStatusChangeSuccess, activation_status),
        put(pnActivationUpsert.success()),
        call(tryLoadSENDPreferences)
      ]);
      action.payload.onSuccess?.();
    } else if (E.isLeft(result)) {
      throw Error(readableReport(result.left));
    } else {
      throw Error(
        `Status code: ${result.right.status} Request data: ${JSON.stringify(
          requestData
        )}`
      );
    }
  } catch (e) {
    yield* all([
      call(reportPNServiceStatusOnFailure, !activation_status, `${e}`),
      put(pnActivationUpsert.failure()),
      call(tryLoadSENDPreferences)
    ]);
    action.payload.onFailure?.();
  }
}

function* reportPNServiceStatusOnFailure(
  predictedValue: boolean,
  reason: string
) {
  const pnServiceId = yield* select(pnMessagingServiceIdSelector);
  const pnServicePreferencesPot = yield* select(
    servicePreferencePotByIdSelector,
    pnServiceId
  );
  const isServiceActive = pipe(
    pnServicePreferencesPot,
    pot.toOption,
    O.map(
      servicePreferenceResponse =>
        isServicePreferenceResponseSuccess(servicePreferenceResponse) &&
        servicePreferenceResponse.value.inbox
    ),
    O.getOrElse(() => predictedValue)
  );
  trackPNServiceStatusChangeError(isServiceActive, reason);
}

export function* watchPnSaga(bearerToken: SessionToken): SagaIterator {
  const pnClient = createPnClient(apiUrlPrefix, bearerToken);

  yield* takeLatest(
    pnActivationUpsert.request,
    handlePnActivation,
    pnClient.upsertPNActivation
  );

  yield* takeLatest(
    startPNPaymentStatusTracking,
    watchPaymentStatusForMixpanelTracking
  );
}

export const testable = isTestEnv
  ? {
      handlePnActivation,
      reportPNServiceStatusOnFailure
    }
  : undefined;

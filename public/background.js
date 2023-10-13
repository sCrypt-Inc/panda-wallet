/* global chrome */
console.log("🐼 Panda Wallet Background Script Running!");

let responseCallbackForConnectRequest;
let responseCallbackForSendBsvRequest;
let responseCallbackForTransferOrdinalRequest;
let responseCallbackForSignMessageRequest;
let responseCallbackForSignTransactionRequest;
let responseCallbackForBroadcastRequest;
let responseCallbackForGetSignaturesRequest;
let popupWindowId = null;

const launchPopUp = () => {
  chrome.windows.create(
    {
      url: chrome.runtime.getURL("index.html"),
      type: "popup",
      width: 360,
      height: 567,
    },
    (window) => {
      popupWindowId = window.id;
      chrome.storage.local.set({
        popupWindowId,
      });
    }
  );
};

const verifyAccess = async (requestingDomain) => {
  return new Promise((resolve) => {
    chrome.storage.local.get(["whitelist"], (result) => {
      const { whitelist } = result;
      if (!whitelist) {
        resolve(false);
        return;
      }

      if (whitelist.includes(requestingDomain)) {
        resolve(true);
      } else {
        resolve(false);
      }
      resolve(false);
    });
  });
};

const authorizeRequest = async (message) => {
  const { params } = message;
  return await verifyAccess(params.domain);
};

// MESSAGE LISTENER
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const noAuthRequired = [
    "isConnected",
    "userConnectResponse",
    "sendBsvResponse",
    "transferOrdinalResponse",
    "signMessageResponse",
    "signTransactionResponse",
    "broadcastResponse",
    "getSignaturesResponse",
  ];

  if (noAuthRequired.includes(message.action)) {
    switch (message.action) {
      case "isConnected":
        return processIsConnectedRequest(message, sendResponse);
      case "userConnectResponse":
        return processConnectResponse(message);
      case "sendBsvResponse":
        return processSendBsvResponse(message);
      case "transferOrdinalResponse":
        return processTransferOrdinalResponse(message);
      case "signMessageResponse":
        return processSignMessageResponse(message);
      case "signTransactionResponse":
        return processSignTransactionResponse(message);
      case "broadcastResponse":
        return processBroadcastResponse(message);
      case "getSignaturesResponse":
        return processGetSignaturesResponse(message);
      default:
        break;
    }

    return;
  }

  // We need to authorize access for these endpoints
  authorizeRequest(message).then((isAuthorized) => {
    if (message.action === "connect") {
      return processConnectRequest(message, sendResponse, isAuthorized);
    }

    if (!isAuthorized) {
      sendResponse({
        type: message.action,
        success: false,
        error: "Unauthorized!",
      });
      return;
    }

    switch (message.action) {
      case "disconnect":
        return processDisconnectRequest(message, sendResponse);
      case "getPubKeys":
        return processGetPubKeysRequest(sendResponse);
      case "getBalance":
        return processGetBalanceRequest(sendResponse);
      case "getAddresses":
        return processGetAddressesRequest(sendResponse);
      case "getOrdinals":
        return processGetOrdinalsRequest(sendResponse);
      case "sendBsv":
        return processSendBsvRequest(message, sendResponse);
      case "transferOrdinal":
        return processTransferOrdinalRequest(message, sendResponse);
      case "signMessage":
        return processSignMessageRequest(message, sendResponse);
      case "signTransaction":
        return processSignTransactionRequest(message, sendResponse);
      case "broadcast":
        return processBroadcastRequest(message, sendResponse);
      case "getSignatures":
        return processGetSignaturesRequest(message, sendResponse);
      default:
        break;
    }
  });

  return true;
});

// REQUESTS ***************************************

const processConnectRequest = (message, sendResponse, isAuthorized) => {
  responseCallbackForConnectRequest = sendResponse;
  chrome.storage.local
    .set({
      connectRequest: { ...message.params, isAuthorized },
    })
    .then(() => {
      launchPopUp();
    });

  return true;
};

const processDisconnectRequest = (message, sendResponse) => {
  try {
    chrome.storage.local.get(["whitelist"], (result) => {
      if (!result.whitelist) throw Error("Already disconnected!");
      const { params } = message;

      const updatedWhitelist = result.whitelist.filter(
        (i) => i !== params.domain
      );

      chrome.storage.local.set({ whitelist: updatedWhitelist }, () => {
        sendResponse({
          type: "disconnect",
          success: true,
          data: true,
        });
      });
    });
  } catch (error) {
    sendResponse({
      type: "disconnect",
      success: true, // This is true in the catch because we want to return a boolean
      data: false,
    });
  }
};

const processIsConnectedRequest = (message, sendResponse) => {
  try {
    const INACTIVITY_LIMIT = 10 * 60 * 1000; // 10 minutes
    chrome.storage.local.get(
      ["appState", "lastActiveTime", "whitelist"],
      (result) => {
        const currentTime = Date.now();
        const lastActiveTime = result.lastActiveTime;

        sendResponse({
          type: "isConnected",
          success: true,
          data:
            !result?.appState?.isLocked &&
            currentTime - lastActiveTime < INACTIVITY_LIMIT &&
            result.whitelist?.includes(message.params.domain),
        });
      }
    );
  } catch (error) {
    sendResponse({
      type: "isConnected",
      success: true, // This is true in the catch because we want to return a boolean
      error: false,
    });
  }

  return true;
};

const processGetBalanceRequest = (sendResponse) => {
  try {
    chrome.storage.local.get(["appState"], (result) => {
      sendResponse({
        type: "getBalance",
        success: true,
        data: result?.appState?.balance,
      });
    });
  } catch (error) {
    sendResponse({
      type: "getBalance",
      success: false,
      error: JSON.stringify(error),
    });
  }
};

const processGetPubKeysRequest = (sendResponse) => {
  try {
    chrome.storage.local.get(["appState"], (result) => {
      sendResponse({
        type: "getPubKeys",
        success: true,
        data: result?.appState?.pubKeys,
      });
    });
  } catch (error) {
    sendResponse({
      type: "getPubKeys",
      success: false,
      error: JSON.stringify(error),
    });
  }
};

const processGetAddressesRequest = (sendResponse) => {
  try {
    chrome.storage.local.get(["appState"], (result) => {
      sendResponse({
        type: "getAddresses",
        success: true,
        data: result?.appState?.addresses,
      });
    });
  } catch (error) {
    sendResponse({
      type: "getAddresses",
      success: false,
      error: JSON.stringify(error),
    });
  }
};

const processGetOrdinalsRequest = (sendResponse) => {
  try {
    chrome.storage.local.get(["appState"], (result) => {
      sendResponse({
        type: "getOrdinals",
        success: true,
        data: result?.appState?.ordinals ?? [],
      });
    });
  } catch (error) {
    sendResponse({
      type: "getOrdinals",
      success: false,
      error: JSON.stringify(error),
    });
  }
};

const processSendBsvRequest = (message, sendResponse) => {
  if (!message.params.data) {
    sendResponse({
      type: "sendBsv",
      success: false,
      error: "Must provide valid params!",
    });
  }
  try {
    responseCallbackForSendBsvRequest = sendResponse;
    chrome.storage.local
      .set({
        sendBsvRequest: message.params.data,
      })
      .then(() => {
        launchPopUp();
      });
  } catch (error) {
    sendResponse({
      type: "sendBsv",
      success: false,
      error: JSON.stringify(error),
    });
  }
};

const processTransferOrdinalRequest = (message, sendResponse) => {
  if (!message.params) {
    sendResponse({
      type: "transferOrdinal",
      success: false,
      error: "Must provide valid params!",
    });
  }
  try {
    responseCallbackForTransferOrdinalRequest = sendResponse;
    chrome.storage.local
      .set({
        transferOrdinalRequest: message.params,
      })
      .then(() => {
        launchPopUp();
      });
  } catch (error) {
    sendResponse({
      type: "transferOrdinal",
      success: false,
      error: JSON.stringify(error),
    });
  }
};

const processBroadcastRequest = (message, sendResponse) => {
  if (!message.params) {
    sendResponse({
      type: "broadcast",
      success: false,
      error: "Must provide valid params!",
    });
  }
  try {
    responseCallbackForBroadcastRequest = sendResponse;
    chrome.storage.local
      .set({
        broadcastRequest: message.params,
      })
      .then(() => {
        launchPopUp();
      });
  } catch (error) {
    sendResponse({
      type: "broadcast",
      success: false,
      error: JSON.stringify(error),
    });
  }
};

const processSignMessageRequest = (message, sendResponse) => {
  if (!message.params) {
    sendResponse({
      type: "signMessage",
      success: false,
      error: "Must provide valid params!",
    });
  }
  try {
    responseCallbackForSignMessageRequest = sendResponse;
    chrome.storage.local
      .set({
        signMessageRequest: message.params,
      })
      .then(() => {
        launchPopUp();
      });
  } catch (error) {
    sendResponse({
      type: "signMessage",
      success: false,
      error: JSON.stringify(error),
    });
  }

  return true;
};

const processSignTransactionRequest = (message, sendResponse) => {
  if (!message.params) {
    sendResponse({
      type: "signTransaction",
      success: false,
      error: "Must provide valid params!",
    });
  }
  try {
    responseCallbackForSignTransactionRequest = sendResponse;
    chrome.storage.local
      .set({
        signTransactionRequest: message.params,
      })
      .then(() => {
        launchPopUp();
      });
  } catch (error) {
    sendResponse({
      type: "signTransaction",
      success: false,
      error: JSON.stringify(error),
    });
  }
};

const processGetSignaturesRequest = (message, sendResponse) => {
  if (!message.params) {
    sendResponse({
      type: "getSignatures",
      success: false,
      error: "Must provide valid params!",
    });
  }
  try {
    responseCallbackForGetSignaturesRequest = sendResponse;
    chrome.storage.local
      .set({
        getSignaturesRequest: {
          txHex: message.params.txHex,
          sigRequests: message.params.sigRequests,
        },
      })
      .then(() => {
        launchPopUp();
      });
  } catch (error) {
    sendResponse({
      type: "getSignatures",
      success: false,
      error: JSON.stringify(error),
    });
  }
};

// RESPONSES ********************************

const processConnectResponse = (message) => {
  try {
    if (responseCallbackForConnectRequest) {
      responseCallbackForConnectRequest({
        type: "connect",
        success: true,
        data:
          message.decision === "approved"
            ? message.pubKeys
            : "User canceled connection",
      });
    }
  } catch (error) {
    responseCallbackForConnectRequest({
      type: "connect",
      success: false,
      error: JSON.stringify(error),
    });
  } finally {
    responseCallbackForConnectRequest = null;
    popupWindowId = null;
    chrome.storage.local.remove("popupWindowId");
  }

  return true;
};

const processSendBsvResponse = (message) => {
  if (!responseCallbackForSendBsvRequest) throw Error("Missing callback!");
  try {
    responseCallbackForSendBsvRequest({
      type: "sendBsv",
      success: true,
      data: message?.txid,
    });
  } catch (error) {
    responseCallbackForSendBsvRequest({
      type: "sendBsv",
      success: false,
      error: JSON.stringify(error),
    });
  } finally {
    responseCallbackForSendBsvRequest = null;
    popupWindowId = null;
    chrome.storage.local.remove(["sendBsvRequest", "popupWindowId"]);
  }

  return true;
};

const processTransferOrdinalResponse = (message) => {
  if (!responseCallbackForTransferOrdinalRequest)
    throw Error("Missing callback!");
  try {
    responseCallbackForTransferOrdinalRequest({
      type: "transferOrdinal",
      success: true,
      data: message?.txid,
    });
  } catch (error) {
    responseCallbackForTransferOrdinalRequest({
      type: "transferOrdinal",
      success: false,
      error: JSON.stringify(error),
    });
  } finally {
    responseCallbackForTransferOrdinalRequest = null;
    popupWindowId = null;
    chrome.storage.local.remove(["transferOrdinalRequest", "popupWindowId"]);
  }

  return true;
};

const processSignMessageResponse = (message) => {
  if (!responseCallbackForSignMessageRequest) throw Error("Missing callback!");
  try {
    responseCallbackForSignMessageRequest({
      type: "signMessage",
      success: true,
      data: {
        address: message?.address,
        pubKeyHex: message?.pubKeyHex,
        signedMessage: message?.signedMessage,
        signatureHex: message?.signatureHex,
      },
    });
  } catch (error) {
    responseCallbackForSignMessageRequest({
      type: "signMessage",
      success: false,
      error: JSON.stringify(error),
    });
  } finally {
    responseCallbackForSignMessageRequest = null;
    popupWindowId = null;
    chrome.storage.local.remove(["signMessageRequest", "popupWindowId"]);
  }

  return true;
};

const processSignTransactionResponse = (message) => {
  if (!responseCallbackForSignTransactionRequest)
    throw Error("Missing callback!");
  try {
    responseCallbackForSignTransactionRequest({
      type: "signTransaction",
      success: true,
      data: message?.signatureHex,
    });
  } catch (error) {
    responseCallbackForSignTransactionRequest({
      type: "signTransaction",
      success: false,
      error: JSON.stringify(error),
    });
  } finally {
    responseCallbackForSignTransactionRequest = null;
    popupWindowId = null;
    chrome.storage.local.remove(["signTransactionRequest", "popupWindowId"]);
  }

  return true;
};

const processBroadcastResponse = (message) => {
  if (!responseCallbackForBroadcastRequest) throw Error("Missing callback!");
  try {
    responseCallbackForBroadcastRequest({
      type: "broadcast",
      success: true,
      data: message?.txid,
    });
  } catch (error) {
    responseCallbackForBroadcastRequest({
      type: "broadcast",
      success: false,
      error: JSON.stringify(error),
    });
  } finally {
    responseCallbackForBroadcastRequest = null;
    popupWindowId = null;
    chrome.storage.local.remove(["broadcastRequest", "popupWindowId"]);
  }

  return true;
};

const processGetSignaturesResponse = (message) => {
  if (!responseCallbackForGetSignaturesRequest) throw Error("Missing callback!");
  try {
    responseCallbackForGetSignaturesRequest({
      type: "getSignatures",
      success: !message?.error,
      data: message?.sigResponses ?? [],
      error: message?.error,
    });
  } catch (error) {
    responseCallbackForGetSignaturesRequest({
      type: "getSignatures",
      success: false,
      error: JSON.stringify(error),
    });
  } finally {
    responseCallbackForGetSignaturesRequest = null;
    popupWindowId = null;
    chrome.storage.local.remove(["getSignaturesRequest", "popupWindowId"]);
  }

  return true;
};

// HANDLE WINDOW CLOSE *****************************************

chrome.windows.onRemoved.addListener((closedWindowId) => {
  if (closedWindowId === popupWindowId) {
    if (responseCallbackForConnectRequest) {
      responseCallbackForConnectRequest({
        type: "connect",
        success: false,
        error: "User dismissed the request!",
      });
      responseCallbackForConnectRequest = null;
      chrome.storage.local.remove("connectRequest");
    }

    if (responseCallbackForSendBsvRequest) {
      responseCallbackForSendBsvRequest({
        type: "sendBsv",
        success: false,
        error: "User dismissed the request!",
      });
      responseCallbackForSendBsvRequest = null;
      chrome.storage.local.remove("sendBsvRequest");
    }

    if (responseCallbackForSignMessageRequest) {
      responseCallbackForSignMessageRequest({
        type: "signMessage",
        success: false,
        error: "User dismissed the request!",
      });
      responseCallbackForSignMessageRequest = null;
      chrome.storage.local.remove("signMessageRequest");
    }

    if (responseCallbackForSignTransactionRequest) {
      responseCallbackForSignTransactionRequest({
        type: "signTransaction",
        success: false,
        error: "User dismissed the request!",
      });
      responseCallbackForSignTransactionRequest = null;
      chrome.storage.local.remove("signTransactionRequest");
    }

    if (responseCallbackForTransferOrdinalRequest) {
      responseCallbackForTransferOrdinalRequest({
        type: "transferOrdinal",
        success: false,
        error: "User dismissed the request!",
      });
      responseCallbackForTransferOrdinalRequest = null;
      chrome.storage.local.remove("transferOrdinalRequest");
    }

    if (responseCallbackForBroadcastRequest) {
      responseCallbackForBroadcastRequest({
        type: "broadcast",
        success: false,
        error: "User dismissed the request!",
      });
      responseCallbackForBroadcastRequest = null;
      chrome.storage.local.remove("broadcastRequest");
    }

    if (responseCallbackForGetSignaturesRequest) {
      responseCallbackForGetSignaturesRequest({
        type: "getSignatures",
        success: false,
        error: "User dismissed the request!",
      });
      responseCallbackForGetSignaturesRequest = null;
      chrome.storage.local.remove("getSignaturesRequest");
    }

    popupWindowId = null;
    chrome.storage.local.remove("popupWindowId");
  }
});

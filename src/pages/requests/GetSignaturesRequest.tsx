import { useBottomMenu } from "../../hooks/useBottomMenu";
import React, { useEffect, useState } from "react";
import { Button } from "../../components/Button";
import {
  Text,
  HeaderText,
  ConfirmContent,
  FormContainer,
} from "../../components/Reusable";
import { Show } from "../../components/Show";
import { useSnackbar } from "../../hooks/useSnackbar";
import { PageLoader } from "../../components/PageLoader";
import { Input } from "../../components/Input";
import { sleep } from "../../utils/sleep";
import { useTheme } from "../../hooks/useTheme";
import { DefaultTheme, styled } from "styled-components";
import { SignatureResponse, Web3GetSignaturesRequest, useContracts } from "../../hooks/useContracts";
import { storage } from "../../utils/storage";
import { useNavigate } from "react-router-dom";
import * as bsv from "bsv";

const TxInput = styled.div`
  border: 1px solid yellow;
  margin: 0.5rem 0;
  padding: 0.5rem;
  width: 85%;
`;

const TxOutput = styled.div`
  border: 1px solid green;
  margin: 0.5rem 0;
  padding: 0.5rem;
  width: 85%;
`;

const TxContainer = styled.div`
  max-height: 10rem;
  overflow-y: scroll;
`;

const TxInputsContainer = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
`;

const TxOutputsContainer = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
`;


const InputContent = (props: { idx: number, tag: string, addr: string | string[], sats: number, theme?: DefaultTheme | undefined }) => {
  return (
    <div style={{ color: props.theme?.color || 'white' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', paddingTop: '0.2rem' }}>
        <span>#{props.idx}</span>
        <span>{props.tag}</span>
        <span>{props.sats} sats</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <div>Signer:</div>
        <div style={{ overflowX: 'scroll', padding: '0.5rem 0 0.5rem 0.5rem' }}>{props.addr}</div>
      </div>
    </div>
  )
}

const OutputContent = (props: { idx: number, tag: string, addr: string | string[], sats: number, theme?: DefaultTheme | undefined }) => {
  return (
    <div style={{ color: props.theme?.color || 'white' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', paddingTop: '0.2rem' }}>
        <span>#{props.idx}</span>
        <span>{props.tag}</span>
        <span>{props.sats} sats</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <div>Payee:</div>
        <div style={{ overflowX: 'scroll', padding: '0.5rem 0 0.5rem 0.5rem' }}>{props.addr}</div>
      </div>
    </div>
  )
}

const TxViewer = (props: { request: Web3GetSignaturesRequest }) => {
  const { theme } = useTheme();
  const [showDetail, setShowDetail] = useState(false);
  const { request } = props;
  const tx = new bsv.Transaction(request.txHex);

  return (
    <TxContainer>
      <Show when={!showDetail}>
        <Button
          theme={theme}
          type="secondary"
          label="Details"
          // disabled={isProcessing}
          onClick={() => setShowDetail(!showDetail)}
          style={{ marginTop: '0' }}
        />
      </Show>

      <Show when={showDetail}>
        <TxInputsContainer>
          <Text theme={theme} style={{ margin: "0.5rem 0" }}>
            Inputs To Sign
          </Text>
          {
            request.sigRequests.map(sigReq => {
              return (
                <TxInput>
                  <InputContent
                    idx={sigReq.inputIndex}
                    tag={sigReq.scriptHex ? 'nonStandard' : 'P2PKH'}
                    addr={[sigReq.address].flat().join(', ')}
                    sats={sigReq.satoshis}
                    theme={theme}
                  />
                </TxInput>
              )
            })
          }
        </TxInputsContainer>
        <TxOutputsContainer>
          <Text theme={theme} style={{ margin: "0.5rem 0" }}>
            Outputs
          </Text>
          {
            tx.outputs.map((output: any, idx: number) => {
              const toAddr = output.script?.toAddress().toString();
              return (
                <TxOutput>
                  <OutputContent
                    idx={idx}
                    tag={output.script?.isPublicKeyHashOut() ? 'P2PKH' : 'nonStandard'}
                    addr={toAddr === 'false' ? 'Unknown Address' : toAddr}
                    sats={output.satoshis}
                    theme={theme}
                  />
                </TxOutput>
              )
            })
          }
        </TxOutputsContainer>
      </Show>

    </TxContainer>
  )
}

export type GetSignaturesResponse = {
  sigResponses?: SignatureResponse[];
  error?: string;
};

export type GetSignaturesRequestProps = {
  getSigsRequest: Web3GetSignaturesRequest;
  popupId: number | undefined;
  onSignature: () => void;
};

export const GetSignaturesRequest = (props: GetSignaturesRequestProps) => {
  const { theme } = useTheme();
  const { setSelected } = useBottomMenu();
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const { addSnackbar, message } = useSnackbar();
  const navigate = useNavigate();

  const { getSigsRequest, onSignature, popupId } = props;
  const [getSigsResponse, setGetSigsRespons] = useState<any>(undefined);
  const { isProcessing, setIsProcessing, getSignatures } = useContracts();


  useEffect(() => {
    setSelected("bsv");
  }, [setSelected]);

  useEffect(() => {
    if (!getSigsResponse) return;
    if (!message && getSigsResponse) {
      resetSendState();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [message, getSigsResponse]);

  const resetSendState = () => {
    setPasswordConfirm("");
    setGetSigsRespons(undefined);
    setIsProcessing(false);
  };

  const handleSigning = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsProcessing(true);
    await sleep(25);

    if (!passwordConfirm) {
      addSnackbar("You must enter a password!", "error");
      setIsProcessing(false);
      return;
    }

    const getSigsRes = await getSignatures(getSigsRequest, passwordConfirm);

    if (getSigsRes?.error) {

      const message =
        getSigsRes.error.message === "invalid-password"
          ? "Invalid Password!"
          : getSigsRes.error.message === "unknown-address"
            ? "Unknown Address: " + (getSigsRes.error.cause ?? '')
            : getSigsRes.error.message === "invalid-tx-input-index"
              ? "Invalid Tx Input Index: " + (getSigsRes.error.cause ?? '')
              : "An unknown error has occurred! Try again.";

      addSnackbar(message, "error", 5000);

      if (getSigsRes.error.message === 'invalid-password') {
        // could try again only if the password is wrong
        setIsProcessing(false);
        return;
      }
    }

    if (getSigsRes?.sigResponses) {
      addSnackbar("Successfully Signed!", "success");
    }

    setGetSigsRespons(getSigsRes.sigResponses);
    onSignature();

    chrome.runtime.sendMessage({
      action: "getSignaturesResult",
      ...getSigsRes,
    });

    if (!getSigsRes && popupId) chrome.windows.remove(popupId);
    storage.remove("getSignaturesRequest");
    navigate("/bsv-wallet");
  };

  const rejectSigning = async (e: React.MouseEvent<HTMLButtonElement, MouseEvent>) => {
    e.preventDefault();
    console.log("rejectSigning");
    if (popupId) chrome.windows.remove(popupId);
    storage.remove("getSignaturesRequest");
  };

  return (
    <>
      <Show when={isProcessing}>
        <PageLoader theme={theme} message="Signing Transaction..." />
      </Show>
      <Show when={!isProcessing && !!getSigsRequest}>
        <ConfirmContent>
          <HeaderText theme={theme}>Sign Transaction</HeaderText>
          <Text theme={theme} style={{ margin: "0.75rem 0" }}>
            The app is requesting signatures for a transaction.
          </Text>
          <FormContainer noValidate onSubmit={(e) => handleSigning(e)}>
            <TxViewer request={getSigsRequest} />
            <Input
              theme={theme}
              placeholder="Enter Wallet Password"
              type="password"
              onChange={(e) => setPasswordConfirm(e.target.value)}
            />
            <Button
              theme={theme}
              type="primary"
              label="Sign the transaction"
              disabled={isProcessing}
            />
            <Button
              theme={theme}
              type="secondary"
              label="Cancel"
              disabled={isProcessing}
              onClick={rejectSigning}
              style={{ marginTop: '0' }}
            />
          </FormContainer>
        </ConfirmContent>
      </Show>
    </>
  );
};

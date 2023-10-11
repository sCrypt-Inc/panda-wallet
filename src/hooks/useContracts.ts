import { useEffect, useState } from "react";
import { useKeys } from "./useKeys";
import * as bsv from "bsv";

/** 
 * `SignatureRequest` contains required informations for a signer to sign a certain input of a transaction.
 */
export interface SignatureRequest {
  prevTxId: string;
  outputIndex: number;
  /** The index of input to sign. */
  inputIndex: number;
  /** The previous output satoshis value of the input to spend. */
  satoshis: number;
  /** The address(es) of corresponding private key(s) required to sign the input. */
  address: string | string[];
  /** The previous output script of input, default value is a P2PKH locking script for the `address` if omitted. */
  scriptHex?: string;
  /** The sighash type, default value is `SIGHASH_ALL | SIGHASH_FORKID` if omitted. */
  sigHashType?: number;
  /** 
   * Index of the OP_CODESEPARATOR to split the previous output script at during verification.
   * If undefined, the whole script is used.
   * */
  csIdx?: number;
  /** The extra information for signing. */
  data?: unknown;
}


export type Web3GetSignaturesRequest = {

  /** The raw transaction hex to get signatures from. */
  txHex: string;

  /** The signature requst informations, see details in `SignatureRequest`. */
  sigRequests: SignatureRequest[];
}

/** 
 * `SignatureResponse` contains the signing result corresponding to a `SignatureRequest`.
 */
export interface SignatureResponse {
  /** The index of input. */
  inputIndex: number;
  /** The signature.*/
  sig: string;
  /** The public key bound with the `sig`. */
  publicKey: string;
  /** The sighash type, default value is `SIGHASH_ALL | SIGHASH_FORKID` if omitted. */
  sigHashType: number;
  /** The index of the OP_CODESEPARATOR to split the previous output script at.*/
  csIdx?: number;
}

const DEFAULT_SIGHASH_TYPE = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID;

const Interp = bsv.Script.Interpreter;
const DEFAULT_FLAGS =
  Interp.SCRIPT_ENABLE_MAGNETIC_OPCODES | Interp.SCRIPT_ENABLE_MONOLITH_OPCODES |
  Interp.SCRIPT_VERIFY_STRICTENC |
  Interp.SCRIPT_ENABLE_SIGHASH_FORKID | Interp.SCRIPT_VERIFY_LOW_S | Interp.SCRIPT_VERIFY_NULLFAIL |
  Interp.SCRIPT_VERIFY_DERSIG |
  Interp.SCRIPT_VERIFY_MINIMALDATA | Interp.SCRIPT_VERIFY_NULLDUMMY |
  Interp.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
  Interp.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | Interp.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | Interp.SCRIPT_VERIFY_CLEANSTACK;


export const useContracts = () => {
  const [isProcessing, setIsProcessing] = useState(false);
  const { retrieveKeys, bsvAddress, ordAddress, verifyPassword } = useKeys();

  /**
   * 
   * @param request An object containing the raw transaction hex and signature request informations.
   * @param password The confirm password to unlock the private keys.
   * @returns A promise which resolves to a list of `SignatureReponse` corresponding to the `request` or an error object if any.
   */
  const getSignatures = async (
    request: Web3GetSignaturesRequest,
    password: string
  ): Promise<{ sigResponses?: SignatureResponse[], error?: { message: string; cause?: any } }> => {
    try {
      setIsProcessing(true);
      const isAuthenticated = await verifyPassword(password);
      if (!isAuthenticated) {
        throw new Error('invalid-password');
      }

      const keys = await retrieveKeys(password);
      const getPrivKeys = (address: string | string[]) => {
        const addresses = address instanceof Array ? address : [address];
        return addresses.map(addr => {
          if (addr === bsvAddress) {
            return bsv.PrivateKey.fromWIF(keys.walletWif);
          }
          if (addr === ordAddress) {
            return bsv.PrivateKey.fromWIF(keys.ordWif);
          }
          throw new Error('unknown-address', { cause: addr });
        });
      }

      const tx = new bsv.Transaction(request.txHex);
      const sigResponses: SignatureResponse[] = request.sigRequests.flatMap(sigReq => {

        if (!tx.inputs[sigReq.inputIndex]) {
          throw new Error('invalid-tx-input-index', { cause: sigReq.inputIndex });
        }

        const privkeys = getPrivKeys(sigReq.address);

        return privkeys.map((privKey: any) => {
          const addr = privKey.toAddress().toString();
          const script = sigReq.scriptHex ? new bsv.Script(sigReq.scriptHex) : bsv.Script.buildPublicKeyHashOut(addr);
          tx.inputs[sigReq.inputIndex].output = new bsv.Transaction.Output({
            // TODO: support multiSig?
            script: script,
            satoshis: sigReq.satoshis
          });

          // Split to subscript if OP_CODESEPARATOR is being employed.
          const subScript = sigReq.csIdx !== undefined ? script.subScript(sigReq.csIdx) : script;

          const sig = bsv.Transaction.Sighash.sign(
            tx, privKey, sigReq.sigHashType || DEFAULT_SIGHASH_TYPE, sigReq.inputIndex,
            subScript, new bsv.crypto.BN(sigReq.satoshis), DEFAULT_FLAGS
          ).toTxFormat().toString('hex');

          return {
            sig: sig as string,
            publicKey: privKey.publicKey.toString(),
            inputIndex: sigReq.inputIndex,
            sigHashType: sigReq.sigHashType || DEFAULT_SIGHASH_TYPE,
            csIdx: sigReq.csIdx,
          }
        })
      })
      return Promise.resolve({ sigResponses });
    } catch (err: any) {
      return {
        error: {
          message: err.message ?? 'unknown',
          cause: err.cause,
        }
      };
    } finally {
      setIsProcessing(false);
    }
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return {
    isProcessing,
    setIsProcessing,
    getSignatures,
  }
}
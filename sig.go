package sigsdk

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func SigWithSchnorr(cm, privateKeyBytes, commitTxBytes, revealTxBytes, inscriptionScript []byte) ([]byte, error) {
	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	var commitMsgTx wire.MsgTx
	commitMsgTx.Deserialize(bytes.NewReader(commitTxBytes))
	commitTx := btcutil.NewTx(&commitMsgTx)
	if blockchain.CheckTransactionSanity(commitTx) != nil {
		return nil, errors.New("committx check sanity failed")
	}

	var revealMsgtX wire.MsgTx
	revealMsgtX.Deserialize(bytes.NewReader(revealTxBytes))
	revealTx := btcutil.NewTx(&revealMsgtX)

	if blockchain.CheckTransactionSanity(revealTx) != nil {
		return nil, errors.New("revealtx check sanity failed")
	}

	revealTxPreOutputFetcher := txscript.NewMultiPrevOutFetcher(nil)
	revealTxPreOutputFetcher.AddPrevOut(wire.OutPoint{
		Hash:  commitTx.MsgTx().TxHash(),
		Index: uint32(0),
	}, commitTx.MsgTx().TxOut[0])

	disasm, err := txscript.DisasmString(inscriptionScript)
	if err != nil {
		return nil, err
	}
	fmt.Println("disasm: ", disasm)

	scriptElements := strings.Split(disasm, " ")
	if len(scriptElements) == 0 {
		return nil, errors.New("script format is error")
	}
	scriptCm := scriptElements[len(scriptElements)-2]
	fmt.Println("scriptCm", scriptCm)
	if string(cm) != scriptCm {
		return nil, errors.New("commitment is error")
	}

	sigHashes := txscript.NewTxSigHashes(revealTx.MsgTx(), revealTxPreOutputFetcher)
	tapLeaf := txscript.NewBaseTapLeaf(inscriptionScript)
	witnessArray, err := txscript.CalcTapscriptSignaturehash(sigHashes, txscript.SigHashDefault, revealTx.MsgTx(), 0, revealTxPreOutputFetcher, tapLeaf)
	if err != nil {
		return nil, err
	}
	signature, err := schnorr.Sign(privateKey, witnessArray)
	if err != nil {
		return nil, err
	}
	return signature.Serialize(), nil
}

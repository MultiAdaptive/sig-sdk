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

const NUMELEMENTS = 14

func SigWithSchnorr(cm, privateKeyBytes, commitTxBytes, revealTxBytes, inscriptionScript []byte) ([]byte, error) {
	var err error
	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	var commitMsgTx wire.MsgTx
	err = commitMsgTx.Deserialize(bytes.NewReader(commitTxBytes))
	if err != nil {
		return nil, errors.New("commitTx deserialize failed." + err.Error())
	}
	commitTx := btcutil.NewTx(&commitMsgTx)
	err = blockchain.CheckTransactionSanity(commitTx)
	if err != nil {
		return nil, errors.New("commitTx check sanity failed." + err.Error())
	}

	var revealMsgTx wire.MsgTx
	err = revealMsgTx.Deserialize(bytes.NewReader(revealTxBytes))
	if err != nil {
		return nil, errors.New("revealTx deserialize failed." + err.Error())
	}
	revealTx := btcutil.NewTx(&revealMsgTx)
	err = blockchain.CheckTransactionSanity(revealTx)
	if err != nil {
		return nil, errors.New("revealTx check sanity failed." + err.Error())
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
	if len(scriptElements) != NUMELEMENTS {
		return nil, errors.New("script format is error")
	}
	scriptCm := scriptElements[1]
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

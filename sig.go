package sigsdk

import (
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

func SigWithSchnorr(cm string, privateKey *btcec.PrivateKey, commitTx, revealTx *wire.MsgTx, inscriptionScript []byte) ([]byte, error) {
	if blockchain.CheckTransactionSanity(btcutil.NewTx(commitTx)) != nil {
		return nil, errors.New("committx check sanity failed")
	}

	if blockchain.CheckTransactionSanity(btcutil.NewTx(revealTx)) != nil {
		return nil, errors.New("revealtx check sanity failed")
	}

	revealTxPreOutputFetcher := txscript.NewMultiPrevOutFetcher(nil)
	revealTxPreOutputFetcher.AddPrevOut(wire.OutPoint{
		Hash:  commitTx.TxHash(),
		Index: uint32(0),
	}, commitTx.TxOut[0])

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
	if cm != scriptCm {
		return nil, errors.New("commitment is error")
	}

	sigHashes := txscript.NewTxSigHashes(revealTx, revealTxPreOutputFetcher)
	tapLeaf := txscript.NewBaseTapLeaf(inscriptionScript)
	witnessArray, err := txscript.CalcTapscriptSignaturehash(sigHashes, txscript.SigHashDefault, revealTx, 0, revealTxPreOutputFetcher, tapLeaf)
	if err != nil {
		return nil, err
	}
	signature, err := schnorr.Sign(privateKey, witnessArray)
	if err != nil {
		return nil, err
	}
	return signature.Serialize(), nil
}

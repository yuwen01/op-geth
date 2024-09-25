// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

func BenchmarkInsertChain_empty_memdb(b *testing.B) {
	benchInsertChain(b, false, nil)
}
func BenchmarkInsertChain_empty_diskdb(b *testing.B) {
	benchInsertChain(b, true, nil)
}
func BenchmarkInsertChain_valueTx_memdb(b *testing.B) {
	benchInsertChain(b, false, genValueTx(0))
}
func BenchmarkInsertChain_valueTx_diskdb(b *testing.B) {
	benchInsertChain(b, true, genValueTx(0))
}
func BenchmarkInsertChain_valueTx_100kB_memdb(b *testing.B) {
	benchInsertChain(b, false, genValueTx(100*1024))
}
func BenchmarkInsertChain_valueTx_100kB_diskdb(b *testing.B) {
	benchInsertChain(b, true, genValueTx(100*1024))
}
func BenchmarkInsertChain_uncles_memdb(b *testing.B) {
	benchInsertChain(b, false, genUncles)
}
func BenchmarkInsertChain_uncles_diskdb(b *testing.B) {
	benchInsertChain(b, true, genUncles)
}
func BenchmarkInsertChain_ring200_memdb(b *testing.B) {
	benchInsertChain(b, false, genTxRing(200))
}
func BenchmarkInsertChain_ring200_diskdb(b *testing.B) {
	benchInsertChain(b, true, genTxRing(200))
}
func BenchmarkInsertChain_ring1000_memdb(b *testing.B) {
	benchInsertChain(b, false, genTxRing(1000))
}
func BenchmarkInsertChain_ring1000_diskdb(b *testing.B) {
	benchInsertChain(b, true, genTxRing(1000))
}

var (
	// This is the content of the genesis block used by the benchmarks.
	benchRootKey, _          = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	benchRootAddr            = crypto.PubkeyToAddress(benchRootKey.PublicKey)
	benchRootFunds           = math.BigPow(10, 60)
	bedrockGenesisTestConfig = func() *params.ChainConfig {
		conf := *params.AllCliqueProtocolChanges // copy the config
		conf.Clique = nil
		conf.TerminalTotalDifficultyPassed = true
		conf.BedrockBlock = big.NewInt(0)
		conf.Optimism = &params.OptimismConfig{EIP1559Elasticity: 50, EIP1559Denominator: 10}
		return &conf
	}()

	holoceneTestConfig = func() *params.ChainConfig {
		conf := *bedrockGenesisTestConfig // copy the config
		time := uint64(0)
		bigintTime := new(big.Int).SetUint64(time)
		conf.HoloceneTime = &time
		conf.BedrockBlock = bigintTime
		return &conf
	}()
)

// genValueTx returns a block generator that includes a single
// value-transfer transaction with n bytes of extra data in each
// block.
func genValueTx(nbytes int) func(int, *BlockGen) {
	return func(i int, gen *BlockGen) {
		toaddr := common.Address{}
		data := make([]byte, nbytes)
		gas, _ := IntrinsicGas(data, nil, false, false, false, false)
		signer := gen.Signer()
		gasPrice := big.NewInt(0)
		if gen.header.BaseFee != nil {
			gasPrice = gen.header.BaseFee
		}
		tx, _ := types.SignNewTx(benchRootKey, signer, &types.LegacyTx{
			Nonce:    gen.TxNonce(benchRootAddr),
			To:       &toaddr,
			Value:    big.NewInt(1),
			Gas:      gas,
			Data:     data,
			GasPrice: gasPrice,
		})
		gen.AddTx(tx)
	}
}

var (
	ringKeys  = make([]*ecdsa.PrivateKey, 1000)
	ringAddrs = make([]common.Address, len(ringKeys))
)

func init() {
	ringKeys[0] = benchRootKey
	ringAddrs[0] = benchRootAddr
	for i := 1; i < len(ringKeys); i++ {
		ringKeys[i], _ = crypto.GenerateKey()
		ringAddrs[i] = crypto.PubkeyToAddress(ringKeys[i].PublicKey)
	}
}

// genTxRing returns a block generator that sends ether in a ring
// among n accounts. This is creates n entries in the state database
// and fills the blocks with many small transactions.
func genTxRing(naccounts int) func(int, *BlockGen) {
	from := 0
	availableFunds := new(big.Int).Set(benchRootFunds).Div(benchRootFunds, big.NewInt(int64(2)))
	return func(i int, gen *BlockGen) {
		// block := gen.PrevBlock(i - 1)
		// gas := block.GasLimit()
		// gasPrice := big.NewInt(0)
		// if gen.header.BaseFee != nil {
		// 	gasPrice = gen.header.BaseFee
		// }
		signer := gen.Signer()
		to := (from + 1) % naccounts
		burn := new(big.Int).SetUint64(params.TxGas)
		burn.Mul(burn, gen.header.BaseFee)
		availableFunds.Sub(availableFunds, burn)
		if availableFunds.Cmp(big.NewInt(1)) < 0 {
			panic("not enough funds")
		}
		tx, err := types.SignNewTx(ringKeys[from], signer,
			&types.DynamicFeeTx{
				Nonce:     gen.TxNonce(ringAddrs[from]),
				To:        &ringAddrs[to],
				Value:     availableFunds,
				Gas:       params.TxGas * 2,
				GasTipCap: big.NewInt(2),
				GasFeeCap: gen.header.BaseFee,
				// GasFeeCap: gen.header.BaseFee.Mul(gen.header.BaseFee, big.NewInt(2)),
			})
		if err != nil {
			panic(err)
		}
		gen.AddTx(tx)
		from = to
	}
}

// genUncles generates blocks with two uncle headers.
func genUncles(i int, gen *BlockGen) {
	if i >= 7 {
		b2 := gen.PrevBlock(i - 6).Header()
		b2.Extra = []byte("foo")
		gen.AddUncle(b2)
		b3 := gen.PrevBlock(i - 6).Header()
		b3.Extra = []byte("bar")
		gen.AddUncle(b3)
	}
}

func BenchmarkInsertChain_SMALL(b *testing.B) {
	benchInsertChain(b, false, genTxRing(100))
}

func benchInsertChain(b *testing.B, disk bool, gen func(int, *BlockGen)) {
	// Create the database in memory or in a temporary directory.
	var db ethdb.Database
	var err error
	if !disk {
		db = rawdb.NewMemoryDatabase()
	} else {
		dir := b.TempDir()
		db, err = rawdb.NewLevelDBDatabase(dir, 128, 128, "", false)
		if err != nil {
			b.Fatalf("cannot create temporary database: %v", err)
		}
		defer db.Close()
	}

	m := make(map[common.Address]types.Account)
	m[ringAddrs[0]] = types.Account{Balance: benchRootFunds}
	m[benchRootAddr] = types.Account{Balance: benchRootFunds}
	var l1FeeBytes [32]byte
	l1FeeBytes[11] = 10 // lsb of the operatorfeeconstant
	var scalar uint32 = 9_000_000
	binary.BigEndian.PutUint32(l1FeeBytes[12:16], scalar)
	fmt.Println("fee bytes", l1FeeBytes)
	l1FeeBytesHash := common.BytesToHash(l1FeeBytes[:])
	m[types.L1BlockAddr] = types.Account{Storage: map[common.Hash]common.Hash{types.L1FeeScalarsSlot: l1FeeBytesHash}}
	// Generate a chain of b.N blocks using the supplied block
	// generator function.
	gspec := &Genesis{
		Config: holoceneTestConfig,
		Alloc:  types.GenesisAlloc(m),
	}
	_, chain, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), b.N, gen)
	// Time the insertion of the new chain.
	// State and blocks are stored in the same DB.
	chainman, _ := NewBlockChain(db, nil, gspec, nil, ethash.NewFaker(), vm.Config{NoBaseFee: false}, nil, nil)
	defer chainman.Stop()
	b.ReportAllocs()
	b.ResetTimer()
	if i, err := chainman.InsertChain(chain); err != nil {
		b.Fatalf("insert error (block %d): %v\n", i, err)
	}

	// Read back the last block to ensure the chain is correct.
	block := chain[0]
	fmt.Println("*********************************************************")
	fmt.Println("block num transactoins", len(block.Transactions()))
	fmt.Println("gas used", block.GasUsed())
	state, _ := chainman.State()
	fmt.Println("len chain: ", chainman.CurrentBlock().Coinbase)
	fmt.Println("ring addrs 0 balance", state.GetBalance(ringAddrs[0]))
	fmt.Println("ring addrs 1 balance", state.GetBalance(ringAddrs[1]))
	fmt.Println("coinbase balance", state.GetBalance(chainman.CurrentBlock().Coinbase))
}

func BenchmarkChainRead_header_10k(b *testing.B) {
	benchReadChain(b, false, 10000)
}
func BenchmarkChainRead_full_10k(b *testing.B) {
	benchReadChain(b, true, 10000)
}
func BenchmarkChainRead_header_100k(b *testing.B) {
	benchReadChain(b, false, 100000)
}
func BenchmarkChainRead_full_100k(b *testing.B) {
	benchReadChain(b, true, 100000)
}
func BenchmarkChainRead_header_500k(b *testing.B) {
	benchReadChain(b, false, 500000)
}
func BenchmarkChainRead_full_500k(b *testing.B) {
	benchReadChain(b, true, 500000)
}
func BenchmarkChainWrite_header_10k(b *testing.B) {
	benchWriteChain(b, false, 10000)
}
func BenchmarkChainWrite_full_10k(b *testing.B) {
	benchWriteChain(b, true, 10000)
}
func BenchmarkChainWrite_header_100k(b *testing.B) {
	benchWriteChain(b, false, 100000)
}
func BenchmarkChainWrite_full_100k(b *testing.B) {
	benchWriteChain(b, true, 100000)
}
func BenchmarkChainWrite_header_500k(b *testing.B) {
	benchWriteChain(b, false, 500000)
}
func BenchmarkChainWrite_full_500k(b *testing.B) {
	benchWriteChain(b, true, 500000)
}

// makeChainForBench writes a given number of headers or empty blocks/receipts
// into a database.
func makeChainForBench(db ethdb.Database, genesis *Genesis, full bool, count uint64) {
	var hash common.Hash
	for n := uint64(0); n < count; n++ {
		header := &types.Header{
			Coinbase:    common.Address{},
			Number:      big.NewInt(int64(n)),
			ParentHash:  hash,
			Difficulty:  big.NewInt(1),
			UncleHash:   types.EmptyUncleHash,
			TxHash:      types.EmptyTxsHash,
			ReceiptHash: types.EmptyReceiptsHash,
		}
		if n == 0 {
			header = genesis.ToBlock().Header()
		}
		hash = header.Hash()

		rawdb.WriteHeader(db, header)
		rawdb.WriteCanonicalHash(db, hash, n)
		rawdb.WriteTd(db, hash, n, big.NewInt(int64(n+1)))

		if n == 0 {
			rawdb.WriteChainConfig(db, hash, genesis.Config)
		}
		rawdb.WriteHeadHeaderHash(db, hash)

		if full || n == 0 {
			block := types.NewBlockWithHeader(header)
			rawdb.WriteBody(db, hash, n, block.Body())
			rawdb.WriteReceipts(db, hash, n, nil)
			rawdb.WriteHeadBlockHash(db, hash)
		}
	}
}

func benchWriteChain(b *testing.B, full bool, count uint64) {
	genesis := &Genesis{Config: params.AllEthashProtocolChanges}
	for i := 0; i < b.N; i++ {
		dir := b.TempDir()
		db, err := rawdb.NewLevelDBDatabase(dir, 128, 1024, "", false)
		if err != nil {
			b.Fatalf("error opening database at %v: %v", dir, err)
		}
		makeChainForBench(db, genesis, full, count)
		db.Close()
	}
}

func benchReadChain(b *testing.B, full bool, count uint64) {
	dir := b.TempDir()

	db, err := rawdb.NewLevelDBDatabase(dir, 128, 1024, "", false)
	if err != nil {
		b.Fatalf("error opening database at %v: %v", dir, err)
	}
	genesis := &Genesis{Config: params.AllEthashProtocolChanges}
	makeChainForBench(db, genesis, full, count)
	db.Close()
	cacheConfig := *defaultCacheConfig
	cacheConfig.TrieDirtyDisabled = true

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		db, err := rawdb.NewLevelDBDatabase(dir, 128, 1024, "", false)
		if err != nil {
			b.Fatalf("error opening database at %v: %v", dir, err)
		}
		chain, err := NewBlockChain(db, &cacheConfig, genesis, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
		if err != nil {
			b.Fatalf("error creating chain: %v", err)
		}

		for n := uint64(0); n < count; n++ {
			header := chain.GetHeaderByNumber(n)
			if full {
				hash := header.Hash()
				rawdb.ReadBody(db, hash, n)
				rawdb.ReadReceipts(db, hash, n, header.Time, chain.Config())
			}
		}
		chain.Stop()
		db.Close()
	}
}

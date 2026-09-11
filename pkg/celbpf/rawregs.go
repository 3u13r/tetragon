// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux && (amd64 || arm64)

package celbpf

import (
	cgChecker "github.com/google/cel-go/checker"
	cgDecls "github.com/google/cel-go/common/decls"
	cgTypes "github.com/google/cel-go/common/types"

	tetragonasm "github.com/cilium/tetragon/pkg/asm"
)

type rawRegisterInfo struct {
	offset uint16
	size   uint8
}

func rawRegister(name string) (rawRegisterInfo, bool) {
	offset, size, ok := tetragonasm.RegOffsetSize(name)
	return rawRegisterInfo{offset: offset, size: size}, ok
}

func checkerAddRawRegisters(env *cgChecker.Env) {
	for _, name := range rawRegisterNames {
		env.AddIdents(cgDecls.NewVariable(name, cgTypes.IntType))
	}
}

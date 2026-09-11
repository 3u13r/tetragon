// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build amd64 && linux

package selectors

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/asm"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

const ArgsInRegisters = 6 // Number of arguments passed by register per System V AMD64 ABI

func parseOverrideRegs(k *KernelSelectorState, selIdx int, values []string, errValue uint64, newOffset int64, sig, data []v1alpha1.KProbeArg) error {
	if _, exists := k.regs[selIdx]; exists {
		return errors.New("only single instance of regs action is allowed")
	}

	regs := []processapi.RegAssignment{}

	if newOffset != 0 {
		values = append(values, fmt.Sprintf("rip=%d%%rip", newOffset))
	}

	// If no registers were specified go with the default for override
	// at the top of the user space function.
	if len(values) == 0 {
		values = []string{
			fmt.Sprintf("rax=%d", errValue),
			"rip=(%rsp)",
			"rsp=8%rsp",
		}
	}

	for _, val := range values {
		dst, value, ok := strings.Cut(val, "=")
		value = strings.TrimSpace(value)
		if ok && strings.HasPrefix(value, "cel(") && strings.HasSuffix(value, ")") {
			ass, err := asm.ParseAssignment(strings.TrimSpace(dst) + "=0")
			if err != nil {
				return err
			}
			fnID, argIndexes, err := addCelValueExpr(k.celExprFunctions, value[4:len(value)-1], sig, data)
			if err != nil {
				return err
			}
			var argMask uint16
			for _, argIndex := range argIndexes {
				argMask |= 1 << argIndex
			}
			regs = append(regs, processapi.RegAssignment{
				Type:    processapi.RegAssignmentTypeCEL,
				Src:     argMask,
				Dst:     ass.Dst,
				DstSize: ass.DstSize,
				Off:     uint64(fnID),
			})
			continue
		}

		ass, err := asm.ParseAssignment(val)
		if err != nil {
			return err
		}

		regs = append(regs, processapi.RegAssignment{
			Type:    ass.Type,
			Src:     ass.Src,
			Dst:     ass.Dst,
			SrcSize: ass.SrcSize,
			DstSize: ass.DstSize,
			Off:     ass.Off,
		})
	}

	k.regs[selIdx] = regs
	return nil
}

func parseSetRegs(k *KernelSelectorState, selIdx int, argIndex, argValue uint32) error {
	var val string
	switch argIndex {
	case 0:
		val = fmt.Sprintf("rdi=%d", argValue)
	case 1:
		val = fmt.Sprintf("rsi=%d", argValue)
	case 2:
		val = fmt.Sprintf("rdx=%d", argValue)
	case 3:
		val = fmt.Sprintf("rcx=%d", argValue)
	case 4:
		val = fmt.Sprintf("r8=%d", argValue)
	case 5:
		val = fmt.Sprintf("r9=%d", argValue)
	}

	ass, err := asm.ParseAssignment(val)
	if err != nil {
		return err
	}

	reg := processapi.RegAssignment{
		Type:    ass.Type,
		Src:     ass.Src,
		Dst:     ass.Dst,
		SrcSize: ass.SrcSize,
		DstSize: ass.DstSize,
		Off:     ass.Off,
	}

	k.regs[selIdx] = append(k.regs[selIdx], reg)
	return nil
}

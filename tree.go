package ipfilter

import (
	"strconv"
	"strings"
)

type treeNode struct {
	children []*treeNode
	isBanned bool
}

func New(addresses ...string) Filter {
	this := newNode()

	for _, item := range addresses {
		this.add(item)
	}

	return this
}
func newNode() *treeNode {
	return &treeNode{children: make([]*treeNode, 2)}
}

func (this *treeNode) add(subnetMask string) {
	if len(subnetMask) == 0 {
		return
	}

	index := strings.Index(subnetMask, subnetMaskSeparator)
	if index == -1 {
		return
	}

	subnetBits, _ := strconv.Atoi(subnetMask[index+1:])
	baseIPAddress := subnetMask[:index]
	if !isNumeric(baseIPAddress) {
		return
	}

	numericIP := parseIPAddress(baseIPAddress)
	if numericIP == 0 {
		return
	}

	current := this
	for i := 0; i < subnetBits; i++ {
		nextBit := uint32(numericIP << i >> ipv4BitMask)
		child := current.children[nextBit]

		if child == nil {
			child = newNode()
			current.children[nextBit] = child
		}
		current = child
	}

	current.isBanned = true
}
func isNumeric(value string) bool {
	for _, character := range value {
		if character != octetSeparator && (character > '9' || character < '0') {
			return false
		}
	}

	return true
}

func (this *treeNode) Contains(ipAddress string) bool {
	if len(ipAddress) == 0 {
		return false
	}

	var numericIP uint32
	if numericIP = parseIPAddress(ipAddress); numericIP == 0 {
		return false
	}

	current := this
	for i := 0; i < ipv4BitCount; i++ {
		nextBit := uint32(numericIP << i >> ipv4BitMask)
		child := current.children[nextBit]

		if child == nil {
			return false
		}

		current = child
		if current.isBanned {
			return true
		}
	}

	return false
}
func parseIPAddress(value string) uint32 {
	var numericIP uint32
	var count int

	for i := 0; i < octetCount; i++ {
		var fragment uint64
		var index int

		for x := range value {
			if value[x] != octetSeparator {
				continue
			}

			index = x
			count++
			break
		}

		if index == 0 {
			fragment, _ = strconv.ParseUint(value, decimalNumber, ipv4BitCount)
		} else {
			fragment, _ = strconv.ParseUint(value[:index], decimalNumber, ipv4BitCount)
		}

		value = value[index+1:]
		if len(value) == 0 && count < octetSeparatorCount {
			return 0
		}

		numericIP = numericIP << octetBits
		numericIP += uint32(fragment)
	}

	if count != octetSeparatorCount {
		return 0
	}

	return numericIP
}

const (
	decimalNumber       = 10
	ipv4BitCount        = 32
	ipv4BitMask         = ipv4BitCount - 1
	octetBits           = 8
	octetSeparatorCount = 3
	octetCount          = 4
	octetSeparator      = '.'
	subnetMaskSeparator = "/"
)

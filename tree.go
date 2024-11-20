package ipfilter

import (
	"strconv"
	"strings"
)

type treeNode struct {
	children     []*treeNode
	isIPv4Banned bool
	isIPv6Banned bool
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
	if strings.Contains(subnetMask, ":") {
		this.addIPv6(subnetMask)
	} else {
		this.addIPv4(subnetMask)
	}
}
func (this *treeNode) addIPv4(subnetMask string) {
	var numericIP uint32

	subnetBits, baseIPAddress := prepareBaseIPAndSubnetMask(subnetMask)
	if subnetBits == 0 || len(baseIPAddress) == 0 {
		return
	}

	if !isNumeric(baseIPAddress) {
		return
	}

	numericIP = parseIPv4Address(baseIPAddress)

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

	current.isIPv4Banned = true
}
func (this *treeNode) addIPv6(subnetMask string) {
	var numericIP uint64

	subnetBits, baseIPAddress := prepareBaseIPAndSubnetMask(subnetMask)
	if subnetBits == 0 || len(baseIPAddress) == 0 {
		return
	}

	if !containsValidHexValues(baseIPAddress) {
		return
	}

	numericIP = parseIPv6Address(baseIPAddress)

	if numericIP == 0 {
		return
	}

	if subnetBits > 64 {
		subnetBits = 64
	}

	current := this
	for i := 0; i < subnetBits; i++ {
		nextBit := uint32(numericIP << i >> ipv6BitMask)
		child := current.children[nextBit]

		if child == nil {
			child = newNode()
			current.children[nextBit] = child
		}
		current = child
	}

	current.isIPv6Banned = true
}

func prepareBaseIPAndSubnetMask(subnetMask string) (int, string) {
	if len(subnetMask) == 0 {
		return 0, ""
	}

	index := strings.Index(subnetMask, subnetMaskSeparator)
	if index == -1 {
		return 0, ""
	}

	subnetBits, _ := strconv.Atoi(subnetMask[index+1:])
	baseIPAddress := subnetMask[:index]
	return subnetBits, baseIPAddress
}
func isNumeric(value string) bool {
	for _, character := range value {
		if character != octetSeparator && (character > '9' || character < '0') {
			return false
		}
	}

	return true
}
func containsValidHexValues(value string) bool {
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F' || character == ipv6Separator) {
			return false
		}
	}
	return true
}
func parseIPv4Address(value string) uint32 {
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
func parseIPv6Address(value string) uint64 {
	var numericIP uint64
	var count int

	for i := 0; i < duotrigesimalSectionCount; i++ {
		var fragment uint64
		var index int

		for x := range value {
			if value[x] != ipv6Separator {
				continue
			}

			index = x
			count++
			break
		}

		if index > 0 {
			fragment, _ = strconv.ParseUint(value[:index], 16, 64)
			value = value[index+1:]
		} else {
			fragment = 0
		}

		numericIP = numericIP << duotrigesimalBitCount
		numericIP += fragment
	}

	return numericIP
}

func (this *treeNode) Contains(ipAddress string) bool {
	if len(ipAddress) == 0 {
		return false
	}

	if strings.Contains(ipAddress, ":") {
		return this.containsIPv6(ipAddress)
	} else {
		return this.containsIPv4(ipAddress)
	}
}
func (this *treeNode) containsIPv4(ipAddress string) bool {
	var numericIP uint32

	numericIP = parseIPv4Address(ipAddress)

	if numericIP == 0 {
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
		if current.isIPv4Banned {
			return true
		}
	}

	return false
}
func (this *treeNode) containsIPv6(ipAddress string) bool {
	var numericIP uint64

	numericIP = parseIPv6Address(ipAddress)

	if !containsValidHexValues(ipAddress) {
		return false
	}

	if numericIP == 0 {
		return false
	}

	current := this
	for i := 0; i < ipv6BitCount; i++ {
		nextBit := uint32(numericIP << i >> ipv6BitMask)
		child := current.children[nextBit]

		if child == nil {
			return false
		}

		current = child
		if current.isIPv6Banned {
			return true
		}
	}

	return false
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

	// we only care about the first 64 bits for ipv6
	duotrigesimalSectionCount = 2
	duotrigesimalBitCount     = 32
	ipv6Separator             = ':'
	ipv6BitCount              = 64
	ipv6BitMask               = ipv6BitCount - 1
)

package ipfilter

import (
	"strconv"
	"strings"
)

type treeNode struct {
	children []*treeNode
	flagged  bool
}

func New(addresses ...string) Filter {
	return NewWithMaxSubnetSize(8, addresses...)
}
func NewWithMaxSubnetSize(maxSubnetSize int, addresses ...string) Filter {
	this := newNode()

	for _, item := range addresses {
		this.add(maxSubnetSize, item)
	}

	return this
}
func newNode() *treeNode {
	return &treeNode{children: make([]*treeNode, 2)}
}

func (this *treeNode) add(maxSubnetSize int, subnetMask string) {
	if len(subnetMask) == 0 {
		return
	}

	index := strings.Index(subnetMask, subnetMaskSeparator)
	if index == -1 {
		return
	}

	subnetBits, _ := strconv.Atoi(subnetMask[index+1:])
	if subnetBits < maxSubnetSize {
		return
	}

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

	current.flagged = true
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
		if current.flagged {
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

func (this *treeNode) Remove(ipAddress string) bool {
	var numericIP uint32

	index := strings.Index(ipAddress, subnetMaskSeparator)
	if index == -1 {
		return false
	}

	subnetBits, _ := strconv.Atoi(ipAddress[index+1:])
	baseIPAddress := ipAddress[:index]
	if !isNumeric(baseIPAddress) {
		return false
	}
	if numericIP = parseIPAddress(baseIPAddress); numericIP == 0 {
		return false
	}
	return this.remove(numericIP, 0, subnetBits, this)
}
func (this *treeNode) remove(numericIP, i uint32, subnetBits int, current *treeNode) bool {
	if numericIP == 0 {
		return false
	}

	if i == uint32(subnetBits) {
		if current.flagged == true {
			if current.children[0] == nil && current.children[1] == nil {
				return true
			}
			current.flagged = false
			return false
		}
	}

	nextBit := numericIP << i >> ipv4BitMask
	child := current.children[nextBit]

	if child == nil {
		return false
	}

	if d := this.remove(numericIP, i+1, subnetBits, child); d == true {

		current.children[nextBit] = nil
		if current.flagged == true || current.children[0] != nil || current.children[1] != nil {
			return false
		}
		return true
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
)

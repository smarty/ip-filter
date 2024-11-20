package ipfilter

import (
	"reflect"
	"testing"
)

func TestIPv4Errors(t *testing.T) {
	filter := New(
		"",
		"10.0.0.0",
		"random name",
		"10.0.0.1.1.1/32",
		"10.0/8",
		"10.0.0.0/8",
		"3|144|0|0/13",
		"0.0.0.0/10")

	exists := filter.Contains("")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("hello, world!")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("a.a.a.a.a")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains(".......")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("10.0.0.1.1.1")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("10.0")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("3.144.124.234")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("0.0.0.0")
	Assert(t).That(exists).Equals(false)
}
func TestIPv6Errors(t *testing.T) {
	filter := New(
		"",
		"2600:f0f0:2::",
		"random name",
		"2600:h0h0:2::/48",
		":::::/64")

	exists := filter.Contains("")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("2600:f0f0:2::1")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("random name")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("2600:h0h0:2::")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("::::")
	Assert(t).That(exists).Equals(false)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func TestFindIPv4AddressWithoutCleanNetwork(t *testing.T) {
	filter := New(
		"3.144.0.0/13",
		"3.5.140.0/22",
		"13.34.37.64/27",
		"52.219.170.0/23",
		"52.94.76.0/22",
		"52.95.36.0/22",
		"120.52.22.96/27",
		"150.222.11.86/31",
		"13.34.11.32/27",
		"15.230.39.60/31")

	exists := filter.Contains("3.144.124.234")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("3.5.140.28")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("13.34.37.88")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("52.219.171.93")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("52.94.79.1")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("52.95.37.21")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("120.52.22.127")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("150.222.11.87")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("13.34.11.35")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("15.230.39.61")
	Assert(t).That(exists).Equals(true)
}
func TestFindIPv4AddressWithCleanNetwork(t *testing.T) {
	filter := New(
		IPNetwork8,  // "10.0.0.0/8"
		IPNetwork16, // "54.168.0.0/16"
		IPNetwork24, // "150.222.10.0/24"
		IPNetwork32) // "52.93.126.244/32"

	exists := filter.Contains("10.255.255.254")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("54.168.255.255")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("150.222.10.255")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("52.93.126.244")
	Assert(t).That(exists).Equals(true)
}
func TestFindIPv4NonExistentNetwork(t *testing.T) {
	filter := New(
		"3.144.0.0/13",
		"3.5.140.0/22")

	exists := filter.Contains("3.152.0.0")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("3.5.144.0")
	Assert(t).That(exists).Equals(false)

}
func TestFindIPv4WithCleanAndNonCleanNetwork(t *testing.T) {
	filter := New(IPNetwork16, "3.144.0.0/13") // 54.168.0.0/16

	exists := filter.Contains("54.168.0.0")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("3.144.0.0")
	Assert(t).That(exists).Equals(true)
}

func TestFindIPv6InNetwork(t *testing.T) {
	filter := New("2600:f0f0:2::/48")

	exists := filter.Contains("2600:f0f0:2::1")
	Assert(t).That(exists).Equals(true)
}
func TestFindIPv6NotInNetwork(t *testing.T) {
	filter := New("2600:f0f0:2::/48",
		"2600:1ff6:7400::/40",
		"2600:f0fb:e100::/40",
		"2a05:d074:9000::/40",
		"2605:9cc0:1ff0:600::/56",
		"2600:f00c::/39",
		"2606:7b40:10ff:e000::/56",
		"2001:3fc1:8000::/36",
		"2600:1f14:4000::/36",
	)

	exists := filter.Contains("2607:abcd:1234:5678::1")
	Assert(t).That(exists).Equals(false)

}
func TestAddIPv6WithSubnetLargerThan64(t *testing.T) {
	filter := New("2a01:578:0:7301::1/128")

	exists := filter.Contains("2a01:578:0:7301::1")
	Assert(t).That(exists).Equals(true)
}
func TestAddIPv6WithSubnetOf32(t *testing.T) {
	filter := New("2a01:::::/32")

	exists := filter.Contains("2a01:578:0:7301::1")
	Assert(t).That(exists).Equals(true)
}

func TestFIndIPv6AndIPv4InNetwork(t *testing.T) {
	filter := New("2600:f0f0:2::/48", "3.144.0.0/13")

	exists := filter.Contains("2600:f0f0:2::1")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("2607:abcd:1234:5678::1")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("3.144.124.234")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("10.10.8.1")
	Assert(t).That(exists).Equals(false)
}

const (
	IPNetwork8  = "10.0.0.0/8"
	IPNetwork16 = "54.168.0.0/16"
	IPNetwork24 = "150.222.10.0/24"
	IPNetwork32 = "52.93.126.244/32"
)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type That struct{ t *testing.T }
type Assertion struct {
	*testing.T
	actual interface{}
}

func Assert(t *testing.T) *That                       { return &That{t: t} }
func (this *That) That(actual interface{}) *Assertion { return &Assertion{T: this.t, actual: actual} }

func (this *Assertion) Equals(expected interface{}) {
	this.Helper()
	if !reflect.DeepEqual(this.actual, expected) {
		this.Errorf("\nExpected: %#v\nActual:   %#v", expected, this.actual)
	}
}

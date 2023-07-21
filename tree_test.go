package ipfilter

import (
	"reflect"
	"testing"
)

func TestErrors(t *testing.T) {
	filter := New(
		"",
		"10.0.0.0",
		"random name",
		"10.0.0.1.1.1/32",
		"10.0/8",
		"10.0.0.0/8")

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
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func TestFindIPAddressWithoutCleanNetwork(t *testing.T) {
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
func TestFindIPAddressWithCleanNetwork(t *testing.T) {
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
func TestFindNonExistentNetwork(t *testing.T) {
	filter := New(
		"3.144.0.0/13",
		"3.5.140.0/22")

	exists := filter.Contains("3.152.0.0")
	Assert(t).That(exists).Equals(false)

	exists = filter.Contains("3.5.144.0")
	Assert(t).That(exists).Equals(false)

}
func TestFindWithCleanAndNonCleanNetwork(t *testing.T) {
	filter := New(IPNetwork16, "3.144.0.0/13") // 54.168.0.0/16

	exists := filter.Contains("54.168.0.0")
	Assert(t).That(exists).Equals(true)

	exists = filter.Contains("3.144.0.0")
	Assert(t).That(exists).Equals(true)
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

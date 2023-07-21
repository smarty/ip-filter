package ipfilter

type Filter interface {
	Contains(string) bool
	Remove(string) bool
}

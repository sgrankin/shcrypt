// From https://raw.githubusercontent.com/youtube/vitess/master/go/flagutil/flagutil.go; see LICENSE
package flagutil

import (
	"sort"
	"strings"
)

type StringListValue []string

func (value *StringListValue) String() string {
	return strings.Join(*value, ",")
}

func (value *StringListValue) Set(v string) error {
	*value = append(*value, strings.Split(v, ",")...)
	return nil
}

type StringMapValue map[string]string

func (value *StringMapValue) Set(v string) error {
	dict := make(map[string]string)
	pairs := strings.Split(v, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		dict[parts[0]] = parts[1]
	}
	*value = dict
	return nil
}

func (value StringMapValue) String() string {
	parts := make([]string, 0)
	for k, v := range value {
		parts = append(parts, k+":"+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

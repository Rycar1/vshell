package controllers

import (
	"reflect"
	"testing"
)

func TestSplitTrimDropsEmptyParts(t *testing.T) {
	got := splitTrim(" 1, ,2,, 3 ", ",")
	want := []string{"1", "2", "3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitTrim() = %#v, want %#v", got, want)
	}
}

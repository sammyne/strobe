package strobe

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

func TestStrobe_Clone(t *testing.T) {
	s, err := New("hello", Bit128)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	c := s.Clone()
	if !reflect.DeepEqual(s, c) {
		t.Fatal("clone make different instance")
	}

	if x, y := fmt.Sprintf("%p", s.st), fmt.Sprintf("%p", c.st); x == y {
		t.Fatal("state isn't deeply cloned", x)
	}
}

func TestNew(t *testing.T) {
	s, err := New("hello", 128)
	if err != nil {
		panic(err)
	}

	const expect = "9c7f7eea94913ada2aa73c2355653563dc0c475c551526f6733bea22f16cb57cd31f682e660ee912824a772201ee1394226f4afcb62d331293cc92e8a624acf6e1b60095e322bbfbc845e5b26995fe7d7c841374d1ff5898c92ee0636b06727321c92a603907035349ccbb1b92b7b0057e8fa87fcebc7e88656fcb45ae04bc34cabeaebe79d91750c0e8bf13b966504d1343597265dd8865adf91409cc9b20d5f47444041f97b699ddfbdee91ea87bd09bf8b02da75a96e947f07f5b65bb4e6efefaa16abfd9fbf6"

	if got := hex.EncodeToString(s.st); expect != got {
		t.Fatalf("invalid initial state: expect %s, got %s", expect, got)
	}
}

/*
func TestHelloWorld(t *testing.T) {
	s, err := New("strobe-go-128", 128)
	if err != nil {
		panic(err)
	}

	if err := s.KEY(nil); err != nil {
		t.Fatal(err)
	}

	out, err := s.PRF(32)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("----------")
	fmt.Printf("%x\n", out)
}
*/

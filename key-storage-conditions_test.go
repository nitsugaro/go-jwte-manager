package jwtek

import (
	"testing"
	"time"
)

func TestIsNotExpired(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		exp  int64
		want bool
	}{
		{name: "no expiration", exp: 0, want: true},
		{name: "future expiration", exp: now.Add(time.Hour).Unix(), want: true},
		{name: "past expiration", exp: now.Add(-time.Hour).Unix(), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotExpired(&Key{Exp: tt.exp}); got != tt.want {
				t.Errorf("IsNotExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

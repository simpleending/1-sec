package auth

import (
	"fmt"
	"testing"
)

func TestSprayFloodIsBoundedAndStillDetected(t *testing.T) {
	d := NewPasswordSprayDetector()
	for i := 0; i < 12000; i++ {
		d.RecordFailure(fmt.Sprint(i), fmt.Sprint(i%100))
	}
	if len(d.attempts) > 10000 {
		t.Fatal("unbounded attempts")
	}
	if r := d.Check(); !r.Detected || r.UniqueIPs != 10000 {
		t.Fatalf("distributed spray missed: %+v", r)
	}
	single := NewPasswordSprayDetector()
	for i := 0; i < 20; i++ {
		single.RecordFailure("192.0.2.1", fmt.Sprint(i))
	}
	if !single.Check().Detected {
		t.Fatal("single-IP spray missed")
	}
	benign := NewPasswordSprayDetector()
	benign.RecordFailure("192.0.2.2", "user")
	if benign.Check().Detected {
		t.Fatal("benign failure flagged")
	}
}

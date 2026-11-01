//go:build windows

package core

import "testing"

func TestAppendAccessIsMinimal(t *testing.T) {
	const (
		fileWriteData       = 0x0002
		fileWriteEA         = 0x0010
		fileWriteAttributes = 0x0100
		writeDAC            = 0x00040000
		deleteRight         = 0x00010000
	)
	for name, bit := range map[string]uint32{"write data": fileWriteData, "write EA": fileWriteEA,
		"write attributes": fileWriteAttributes, "WRITE_DAC": writeDAC, "DELETE": deleteRight} {
		if appendAccess&bit != 0 {
			t.Errorf("log append requests %s, which the log folder ACL does not grant", name)
		}
	}
}

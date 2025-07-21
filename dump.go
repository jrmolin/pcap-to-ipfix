package main

import (
	"encoding/binary"
	"fmt"

	"io"
	"strings"
	"time"
)

func center(s string, width int) string {
	if len(s) >= width {
		return s
	}
	pad := width - len(s)
	left := pad / 2
	right := pad - left
	return fmt.Sprintf("%s%s%s", strings.Repeat(" ", left), s, strings.Repeat(" ", right))
}

// Flexible center-row formatter for ASCII art tables
func centerRow(totalLen, splits int, args ...interface{}) string {
	// starts with a |, and each split adds another |
	// colWidth includes the | at the end of the column
	colWidth := (totalLen + splits - 1) / splits
	out := "|"
	for i := 0; i < splits; i++ {
		cell := args[i].(string)
		// Last column may be wider if not evenly divisible
		width := colWidth
		if i == splits-1 {
			width = totalLen + 1 - len(out)
		}
		out += center(cell, width) + "|"
	}
	return out
}

func annotatedV9Dump(data []byte, w io.Writer) {
	if len(data) < 20 {
		fmt.Fprintf(w, "Packet too short for NetFlow v9 header\n")
		return
	}
	ver := binary.BigEndian.Uint16(data[0:2])
	count := binary.BigEndian.Uint16(data[2:4])
	uptime := binary.BigEndian.Uint32(data[4:8])
	exportTime := binary.BigEndian.Uint32(data[8:12])
	seq := binary.BigEndian.Uint32(data[12:16])
	domain := binary.BigEndian.Uint32(data[16:20])
	headerString := "0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1"
	lineLen := len(headerString)
	//                       1         2         3         4         5	       6         7
	//             01234567890123456789012345678901234567890123456789012345678901234567890
	fmt.Fprintf(w, "                     1                   2                   3   \n")
	fmt.Fprintf(w, " %s \n", headerString)
	fmt.Fprintf(w, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")
	fmt.Fprintln(w, centerRow(lineLen, 2, fmt.Sprintf("Version = %d", ver), fmt.Sprintf("Count = %d (%d bytes)", count, len(data))))
	fmt.Fprintf(w, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")
	uptimeMillis := uptime
	uptimeMs := uptimeMillis % 1000
	uptime = uptime / 1000
	uptimeH := uptime / 3600
	uptime = uptime - uptimeH*3600
	uptimeM := uptime / 60
	uptime = uptime - uptimeM*60
	uptimeS := uptime
	fmt.Fprintln(w, centerRow(lineLen, 1, fmt.Sprintf("Uptime = %d ms   (%d:%02d:%02d.%03d)", uptimeMillis, uptimeH, uptimeM, uptimeS, uptimeMs)))
	fmt.Fprintf(w, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")
	fmt.Fprintln(w, centerRow(lineLen, 1, fmt.Sprintf("Export Time = %d epoch sec (%s)", exportTime, time.Unix(int64(exportTime), 0).UTC())))
	fmt.Fprintf(w, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")
	fmt.Fprintln(w, centerRow(lineLen, 1, fmt.Sprintf("Sequence Number = %d", seq)))
	fmt.Fprintf(w, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")
	fmt.Fprintln(w, centerRow(lineLen, 1, fmt.Sprintf("Observation Domain = %d", domain)))
	fmt.Fprintf(w, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")

	i := 20
	c := 0
	for c < int(count) && i+4 <= len(data) {
		setID := binary.BigEndian.Uint16(data[i : i+2])
		setLen := binary.BigEndian.Uint16(data[i+2 : i+4])
		fmt.Fprintln(w, centerRow(lineLen, 2, fmt.Sprintf("(%d of %d) Set ID = %d", c+1, count, setID), fmt.Sprintf("Set Length = %d", setLen)))
		fmt.Fprintf(w, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")
		if int(setLen) < 4 || i+int(setLen) > len(data) {
			fmt.Fprintln(w, centerRow(lineLen, 1, "(Malformed or truncated FlowSet)"))
			fmt.Fprintf(w, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")
			break
		}
		// For Template Set (Set ID 0), print Template fields
		if setID == 0 && setLen >= 8 {
			templateID := binary.BigEndian.Uint16(data[i+4 : i+6])
			fieldCount := binary.BigEndian.Uint16(data[i+6 : i+8])
			fmt.Fprintln(w, centerRow(lineLen, 2, fmt.Sprintf("Template ID = %d", templateID), fmt.Sprintf("Field Count = %d", fieldCount)))
			fmt.Fprintf(w, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")
			fieldOffset := 8
			// Optionally, print field specs (add more logic here)
			for field := 0; field < int(fieldCount); field++ {
				fieldID := binary.BigEndian.Uint16(data[fieldOffset : fieldOffset+2])
				fieldLength := binary.BigEndian.Uint16(data[fieldOffset+2 : fieldOffset+4])
				fieldOffset += 4
				fmt.Fprintln(w, centerRow(lineLen, 2, fmt.Sprintf("Field ID = %d", fieldID), fmt.Sprintf("Field Length = %d", fieldLength)))
				fmt.Fprintf(w, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")
			}
		} else {
			// Optionally, print field specs (add more logic here)
			fours := setLen / 4
			for field := 0; field < int(fours)-1; field++ {
				o0 := data[i+4+field*4 : i+5+field*4]
				o1 := data[i+5+field*4 : i+6+field*4]
				o2 := data[i+6+field*4 : i+7+field*4]
				o3 := data[i+7+field*4 : i+8+field*4]
				fmt.Fprintln(w, centerRow(lineLen, 4, fmt.Sprintf("%02x", o0), fmt.Sprintf("%02x", o1), fmt.Sprintf("%02x", o2), fmt.Sprintf("%02x", o3)))
				fmt.Fprintf(w, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")
			}
		}
		// For Data Set (Set ID >= 256), print values as bytes or try to decode fields
		// (You can add more logic to parse fields by template, etc.)
		i += int(setLen)
		c++
	}
}

func hexDumpV9PacketToWriter(data []byte, label string, w io.Writer) {
	fmt.Fprintf(w, "%s (len=%d):\n", label, len(data))
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(w, "%04x: ", i)
		for j := i; j < i+16; j++ {
			if j < end {
				fmt.Fprintf(w, "%02x ", data[j])
			} else {
				fmt.Fprint(w, "   ")
			}
		}
		fmt.Fprint(w, " ")
		for j := i; j < end; j++ {
			b := data[j]
			if b >= 32 && b <= 126 {
				fmt.Fprintf(w, "%c", b)
			} else {
				fmt.Fprint(w, ".")
			}
		}
		fmt.Fprintln(w)
	}
}

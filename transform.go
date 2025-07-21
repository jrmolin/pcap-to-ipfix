package main

import (
	"fmt"
	"os"
	"reflect"
	"sort"

	"encoding/binary"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Field struct {
	id     uint16
	length uint16
}
type Template struct {
	id            uint16
	size          uint16
	data          []byte
	fields        []Field
	domain        uint32
	record_length uint
}

type ObsDomain struct {
	id        uint32
	templates map[uint16]Template
	messages  []Flow
}

type ObsDomainDumper struct {
	domain        *ObsDomain
	seq_number    uint32
	message_index int
	last_time     uint32
}

func (me *ObsDomainDumper) IsFirst() bool {
	return me.message_index == 0
}
func (me *ObsDomainDumper) Peek() uint32 {
	if me.message_index >= len(me.domain.messages) {
		return 0
	}

	flow := me.domain.messages[me.message_index]
	return flow.export_time

}

func (me *ObsDomainDumper) Next() []byte {
	if me.message_index >= len(me.domain.messages) {
		fmt.Printf("domain %d is now empty (%d messages\n", me.domain.id, me.message_index)
		return nil
	}

	// create a header now
	result := make([]byte, 16)
	put_u16(result[0:2], 10)

	// set the time
	put_u32(result[4:8], 0)

	// set the obsid
	put_u32(result[12:16], me.domain.id)
	message_length := uint16(16)

	if me.message_index == 0 {
		var message []byte

		// dump the templates
		for _, t := range me.domain.templates {
			message = append(message, t.data...)
			message_length += t.size
		}

		// compile the templates into that byte slice
		// templates map[uint16]Template
		fmt.Printf("domain %d has %d templates\n", me.domain.id, len(me.domain.templates))

		// set the sequence number
		put_u32(result[8:12], 1)

		result = append(result, message...)
	} else {
		// set the sequence number
		put_u32(result[8:12], uint32(me.message_index))
	}

	// get the first message with data
	flow := me.domain.messages[me.message_index]
	// set the time
	me.last_time = flow.export_time
	put_u32(result[4:8], flow.export_time)

	me.message_index += len(flow.records)

	data := flow.Dump()

	// if this one has data, add it
	if len(data) > 0 {
		result = append(result, data...)
		message_length += uint16(len(data))
	} else {
		fmt.Printf("flow has no data\n")
	}

	numPad := message_length % 4
	if numPad > 0 {
		n := 4 - numPad
		fmt.Printf("message needs %d bytes of padding", n)
		for _ = range n {
			result = append(result, 0)
			message_length += uint16(1)
		}
	}

	put_u16(result[2:4], message_length)

	return result
}

type IPFIXer struct {
	output_dir string
	sourceIP   string
	list       []Flow

	domains map[uint32]*ObsDomain

	cache map[uint32]uint32
}

func (me *Record) Length() uint16 {
	if len(me.pkt) > 0 {
		return as_u16(me.pkt[2:4])
	}
	return 0
}

type Record struct {
	pkt []byte
}
type Flow struct {
	export_time uint32
	records     []Record
}

func (me *Flow) Dump() []byte {
	var result []byte

	// if this one has data, break
	if len(me.records) > 0 {
		for _, rec := range me.records {
			if len(rec.pkt) < 4 {
				fmt.Printf("there are %d bytes of padding\n", len(rec.pkt))
				break
			}
			result = append(result, rec.pkt...)
		}
	}

	return result

}

func (me *ObsDomain) OnNewFlow(packet []byte) {
	//setID := as_u16(v9[0:2])

	length := uint(len(packet))
	var options []uint32

	// header := packet[0:20]
	// skip 20 bytes
	for i := uint(20); i < length; {
		flow := Flow{
			export_time: as_u32(packet[8:12]),
		}

		set_id := as_u16(packet[i : i+2])

		byte_count := as_u16(packet[i+2 : i+4])

		if set_id == 0 {
			id := as_u16(packet[i+4 : i+6])
			template := &Template{
				id:            id,
				size:          byte_count,
				domain:        me.id,
				fields:        []Field{},
				data:          packet[i : i+uint(byte_count)],
				record_length: uint(0),
			}
			put_u16(template.data[0:2], 2)

			fields_count := uint(as_u16(packet[i+6 : i+8]))
			for field_index := uint(0); field_index < fields_count; field_index++ {
				this_field := i + 6 + field_index*4
				field := Field{
					id:     as_u16(packet[this_field : this_field+2]),
					length: as_u16(packet[this_field+2 : this_field+4]),
				}
				template.record_length += uint(field.length)
				template.fields = append(template.fields, field)
			}

			me.AppendTemplate(template)
		} else if set_id == 1 {
			fmt.Println("got an options template")
			options = append(options, uint32(as_u16(packet[i+4:i+6])))
		} else {

			record := Record{
				pkt: packet[i : i+uint(byte_count)],
			}
			flow.records = append(flow.records, record)
		}
		if len(flow.records) > 0 {
			me.messages = append(me.messages, flow)
		}
		i += uint(byte_count)
	}
}

func as_u16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b[0:2])
}
func as_u32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b[0:4])
}
func put_u16(out []byte, value uint16) {
	binary.BigEndian.PutUint16(out[0:2], value)
}

func put_u32(out []byte, value uint32) {
	binary.BigEndian.PutUint32(out[0:4], value)
}

func NewObsDomain(id uint32) *ObsDomain {
	return &ObsDomain{
		id:        id,
		templates: make(map[uint16]Template),
		messages:  []Flow{},
	}
}
func NewFixer(path string) *IPFIXer {
	return &IPFIXer{
		output_dir: path,
		list:       make([]Flow, 0),
		sourceIP:   "",
		domains:    make(map[uint32]*ObsDomain),
	}
}

func (me *ObsDomain) AppendTemplate(t *Template) {
	// try to get this one
	p, ok := me.templates[t.id]
	if ok {
		if !reflect.DeepEqual(p, *t) {
			me.templates[t.id] = *t
			fmt.Printf("template %d replacing old one for %d\n", t.id, me.id)
		}
	} else {
		me.templates[t.id] = *t
	}
}

func (me *ObsDomain) GetTemplate(id uint16) *Template {
	// try to get this one
	for _, t := range me.templates {
		if id == t.id {
			return &t
		}
	}

	return nil
}

func (me *IPFIXer) OnNetFlow(data []byte) error {
	// make sure this is long enough
	if len(data) < 20 {
		return fmt.Errorf("v9 packet too short")
	}

	// make sure this is v9

	version := as_u16(data[0:2])
	if version != 9 {
		return fmt.Errorf("This is not a v9 packet: version found is %d", version)
	}

	domain := as_u32(data[16:20])

	// update this flow's domain to our map
	d, ok := me.domains[domain]
	if !ok {
		d = NewObsDomain(domain)
		me.domains[domain] = d
	}

	d.OnNewFlow(data)

	return nil
}

func (me *IPFIXer) OnPacket(packet gopacket.Packet) error {
	// process the packet
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()
	if networkLayer == nil || transportLayer == nil {
		return fmt.Errorf("Got an empty layer; bailing")
	}
	ip, ok := networkLayer.(*layers.IPv4)
	if !ok {
		return fmt.Errorf("This is not IPv4; bailing")
	}

	srcip := ip.SrcIP.String()
	if me.sourceIP == "" {
		me.sourceIP = srcip
	}

	// make sure it is udp
	udpLayer, ok := transportLayer.(*layers.UDP)
	if !ok {
		return fmt.Errorf("This is not UDP; bailing")
	}

	// make sure it is netflow-v9
	payload := udpLayer.Payload

	return me.OnNetFlow(payload)
}

type Uint32Slice struct {
	data []uint32
}

func NewUint32Slice() *Uint32Slice {
	return &Uint32Slice{
		data: make([]uint32, 0),
	}
}

func (me *Uint32Slice) Append(v uint32) {
	me.data = append(me.data, v)
}

func (me *Uint32Slice) Len() int {
	return len(me.data)
}

func (me *Uint32Slice) Less(i, j int) bool {
	return me.data[i] < me.data[j]
}

func (me *Uint32Slice) Swap(i, j int) {
	tmp := me.data[j]
	me.data[j] = me.data[i]
	me.data[i] = tmp
}

func (me *IPFIXer) dump_to_directory() error {

	filename := filepath.Join(me.output_dir, me.sourceIP+".ipfix")
	dumpf, ferr := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if ferr != nil {
		return fmt.Errorf("Failed to open file for exporter %s: %v", me.sourceIP, ferr)
	}

	defer dumpf.Close()

	// output:
	// version, total length
	// export time
	//
	// collect templates, per obs

	// collect all provided templates and make sure they're all the same

	// all templates collected by domains
	// sort the domains
	// for each domain in the domains
	//   compile all the templates into a binary blob
	//   create a header
	//   calculate the size of the full blob
	//   write it
	sorted_domains := NewUint32Slice()
	for _, dom := range me.domains {
		sorted_domains.Append(dom.id)
	}
	sort.Sort(sorted_domains)
	dumpers := make([]*ObsDomainDumper, 0)

	earliest_time := uint32(0xffffffff)
	for _, dom_id := range sorted_domains.data {
		dom := me.domains[dom_id]
		dumper := ObsDomainDumper{
			domain: dom,
		}

		// dump the first message
		blob := dumper.Next()
		dumpf.Write(blob)

		last_time := dumper.last_time

		if last_time < earliest_time && last_time > 0 {
			earliest_time = last_time
		}

		dumpers = append(dumpers, &dumper)
	}

	next_dumper := func(dumpers []*ObsDomainDumper) *ObsDomainDumper {

		var _dumper *ObsDomainDumper

		earliest_time := uint32(0xffffffff)
		// go back and forth, based on time
		for _, dumper := range dumpers {
			// dump one
			next_time := dumper.Peek()
			if next_time < earliest_time && next_time > 0 {
				earliest_time = next_time
				_dumper = dumper
			}
		}
		return _dumper

	}
	for true {
		dumper := next_dumper(dumpers)
		if dumper == nil {
			break
		}
		blob := dumper.Next()
		dumpf.Write(blob)
	}

	// for each flow in the flows
	//   filter out templates provided by this flow
	//   if there is anything left, compile the blob
	//   create a header with updated sequence number
	//   calculate the size of the full blob
	//   write it
	// for index,flow := range me.list {
	//
	// 	// are any templates defined?
	//
	//
	// }

	// first, dump all the templates
	// then, dump all the rest of the records

	// dump templates in order of having seen them
	// if we have overriding templates that are different, throw an error
	// origFilename := filepath.Join(outputDir, me.sourceIP+".orig")
	// dumpFilename := filepath.Join(outputDir, me.sourceIP+".dump")
	// var ferr error
	// loop and dump
	//annotatedV9Dump(udpLayer.Payload, dumpf)
	// origf, ferr := os.OpenFile(origFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	// if ferr != nil {
	// 	return fmt.Errorf("Failed to open file for exporter %s: %v", me.sourceIP, ferr)
	// }
	// loop and dump
	// f, ferr := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	// if ferr != nil {
	// 	return fmt.Errorf("Failed to open file for exporter %s: %v", me.sourceIP, ferr)
	// }
	// loop and dump
	/* if err := fixer.writeV9Payload(f, udpLayer.Payload); err != nil {
		log.Printf("Failed to write data block for %s: %v", filename, err)
		return err
	} */
	return nil
}

func copy_set(v9_slice, out_slice []byte, index int) int {

	if len(v9_slice) < (index + 4) {
		return 0
	}

	v9 := v9_slice[index:]
	out := out_slice[index:]

	setID := as_u16(v9[0:2])
	length := as_u16(v9[2:4])

	if length < 4 {
		return 0
	}

	if setID == 0 {
		setID = 2
	} else if setID == 1 {
		setID = 3
	}
	put_u16(out[0:2], setID)
	put_u16(out[2:4], length)

	var i uint16 = 4

	// if this is a template, do something
	if setID == 2 {
		templateID := as_u16(v9[i : i+2])
		fieldCount := as_u16(v9[i+2 : i+4])

		if templateID < 256 {
			fmt.Printf("invalid template id: %d\n", templateID)
		}
		put_u16(out[i:i+2], templateID)
		put_u16(out[i+2:i+4], fieldCount)

		i += 4
	}

	// copy the data
	for ; i < length; i++ {
		out[i] = v9[i]
	}
	return int(length)
}

func transformV9FlowSets(v9_orig, out_orig []byte) uint32 {
	var numSets uint32 = 0

	v9 := v9_orig[20:]
	out := out_orig[16:]

	i := 0
	for i+4 <= len(v9) {
		length := copy_set(v9, out, i)
		if length == 0 {
			fmt.Printf("reached the end with length 0 (index %d)\n", i)
			break
		}
		i += length
		numSets += 1
	}
	return numSets
}
func writeV9Bytes(f *os.File, payload []byte) error {
	if _, err := f.Write(payload); err != nil {
		return err
	}
	return nil
}

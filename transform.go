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
	data          []byte
	fields        []Field
	domain        uint32
	record_length uint
}

type ObsDomain struct {
	id        uint32
	templates map[uint16]Template
	messages  []*Flow
}

type ObsDomainDumper struct {
	domain        *ObsDomain
	seq_number    uint32
	message_index int
	last_time     uint32
}

type Record struct {
	pkt []byte
}
type Flow struct {
	num_records uint16
	export_time uint32
	data []byte
	records []Record
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

	// set the sequence number
	put_u32(result[8:12], me.seq_number)

	// set the obsid
	put_u32(result[12:16], me.domain.id)

	if me.IsFirst() {
		var message []byte

		// dump the templates
		for _, t := range me.domain.templates {
			t_header := make([]byte, 4)
			put_u16(t_header[0:2], 2)
			put_u16(t_header[2:4], uint16(len(t.data)+4))
			message = append(message, t_header...)
			message = append(message, t.data...)
		}

		result = append(result, message...)
	}

	// get the first message with data
	flow := me.domain.messages[me.message_index]

	// set the time
	me.last_time = flow.export_time
	put_u32(result[4:8], flow.export_time)

	data := flow.Dump(me.domain.templates)
	me.message_index += 1

	// if this one has data, add it
	if len(data) > 0 {
		result = append(result, data...)
	} else {
		fmt.Printf("flow has no data\n")
	}

	// update the sequence numbers
	me.seq_number += uint32(flow.num_records)

	message_length := len(result)
	numPad := message_length % 4
	if numPad > 0 {
		n := 4 - numPad
		fmt.Printf("message needs %d bytes of padding", n)
		for _ = range n {
			result = append(result, 0)
			message_length += 1
		}
	}

	put_u16(result[2:4], uint16(message_length))

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

func (me *Flow) DumpSet(index uint32, template Template) []byte {
	result := []byte{}
	data := me.data[index:]
	result = append(result, data[0:4]...)

	record_length := template.record_length
	so_far := uint(4)
	for recordidx := uint16(0); recordidx < me.num_records; recordidx++ {
		result = append(result, data[so_far:so_far + record_length]...)
		so_far += record_length
	}

	return result
}

func (me *Flow) Dump(templates map[uint16]Template) []byte {

	result := []byte{}

	index := uint32(0)
	length := uint32(len(me.data))
	for index < length {
		if index < length && index + 4 > length {
			break
		}

		t_id := as_u16(me.data[index:index+2])

		template, ok := templates[t_id]
		if ! ok {
			fmt.Printf("could not find template for %d\n", t_id)
			break
		}
		set := me.DumpSet(index, template)
		result = append(result, set...)
		index += uint32(len(set))
	}
	return me.data
}
func (me *ObsDomain) AppendTemplate(packet []byte, index uint) uint {

	// data is the start of the set
	data := packet[index:]
	byte_count := uint(as_u16(data[2:4]))

	offset := uint(4)
	for ; offset < byte_count ; {
		template := data[offset:]
		id := as_u16(template[0:2])
		t := &Template{
			id:            id,
			domain:        me.id,
			fields:        []Field{},
			data:          template[0: uint(byte_count - 4)],
			record_length: uint(0),
		}
		fields_count := uint(as_u16(template[2:4]))
		for field_index := uint(0); field_index < fields_count; field_index++ {
			this_field := uint(4) + field_index*4
			field := Field{
				id:     as_u16(template[this_field : this_field+2]),
				length: as_u16(template[this_field+2 : this_field+4]),
			}
			t.record_length += uint(field.length)
			t.fields = append(t.fields, field)
		}

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

		offset += 4 + fields_count * 4

		if offset < byte_count && offset + 4 > byte_count {
			break
		}
	}

	return offset
}

func (me *ObsDomain) OnNewFlow(packet []byte) {
	//setID := as_u16(v9[0:2])

	length := uint(len(packet))
	var options []uint32
	flow := &Flow{
		export_time: as_u32(packet[8:12]),
		num_records: as_u16(packet[2:4]),
	}

	// header := packet[0:20]
	// skip 20 bytes
	i := uint(20)
	for ; i < length; {
		set_id := as_u16(packet[i : i+2])

		byte_count := uint(as_u16(packet[i+2 : i+4]))

		if i < length && i + 4 > length {
			break
		}
		if set_id == 0 {
			_ = me.AppendTemplate(packet, i)
			//flow.data = append(flow.data, packet[i:i + byte_count_]...)
			//byte_count = byte_count_
			flow.num_records -= 1
		} else if set_id == 1 {
			options = append(options, uint32(as_u16(packet[i+4:i+6])))
		} else {
			flow.data = append(flow.data, packet[i:i + byte_count]...)
		}
		i += byte_count
	}
	if len(flow.data) > 0 {
		me.messages = append(me.messages, flow)
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
		messages:  []*Flow{},
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

	sorted_domains := NewUint32Slice()
	for _, dom := range me.domains {
		sorted_domains.Append(dom.id)
	}
	sort.Sort(sorted_domains)
	dumpers := make([]*ObsDomainDumper, 0)

	// all templates collected by domains
	// sort the domains
	// for each domain in the domains
	//   compile all the templates into a binary blob
	//   create a header
	//   calculate the size of the full blob
	//   write it
	for _, dom_id := range sorted_domains.data {
		dom := me.domains[dom_id]
		dumper := &ObsDomainDumper{
			domain: dom,
			seq_number: uint32(0),
			message_index: 0,
		}

		dumpers = append(dumpers, dumper)
	}

	next_dumper := func(dumpers []*ObsDomainDumper) *ObsDomainDumper {

		var _dumper *ObsDomainDumper

		earliest_ := uint32(0xffffffff)
		// go back and forth, based on time
		for _, dumper := range dumpers {
			// dump one
			next_time := dumper.Peek()
			if next_time < earliest_ && next_time > 0 {
				earliest_ = next_time
				_dumper = dumper
			}
		}
		return _dumper
	}

	// for each flow in the flows
	//   filter out templates provided by this flow
	//   if there is anything left, compile the blob
	//   create a header with updated sequence number
	//   calculate the size of the full blob
	//   write it
	for true {
		dumper := next_dumper(dumpers)
		if dumper == nil {
			break
		}
		blob := dumper.Next()
		dumpf.Write(blob)
	}

	return nil
}


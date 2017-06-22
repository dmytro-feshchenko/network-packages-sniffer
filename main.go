package main

import (
	"github.com/mattn/go-gtk/gtk"
	"os"
	"github.com/google/gopacket/pcap"
	"fmt"
	"log"
	"strconv"
	"flag"
	"time"
	"strings"
	"github.com/google/gopacket/dumpcommand"
	"github.com/google/gopacket/examples/util"
)

func main() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}

	ShowGui(devices)
}

func ShowGui(devices []pcap.Interface) {
	gtk.Init(&os.Args)
	window := gtk.NewWindow(gtk.WINDOW_TOPLEVEL)
	window.SetTitle("Network Sniffer")
	window.SetIconName("gtk-about")
	window.Connect("destroy", func() {
		gtk.MainQuit()
	})

	//--------------------------------------------------------
	// GtkVBox
	//--------------------------------------------------------
	vbox := gtk.NewVBox(false, 1)

	//--------------------------------------------------------
	// GtkVPaned
	//--------------------------------------------------------
	vpaned := gtk.NewVPaned()
	vbox.Add(vpaned)

	//--------------------------------------------------------
	// GtkFrame
	//--------------------------------------------------------

	frame1 := gtk.NewFrame("Devices & Sniffer Settings")
	framebox1 := gtk.NewVBox(false, 1)
	frame1.Add(framebox1)

	frame2 := gtk.NewFrame("Sniffer Results")
	framebox2 := gtk.NewVBox(false, 1)
	frame2.Add(framebox2)

	vpaned.Pack1(frame1, false, false)
	vpaned.Pack2(frame2, false, false)

	//--------------------------------------------------------
	// Devices TextView
	//--------------------------------------------------------
	swin := gtk.NewScrolledWindow(nil, nil)
	swin.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	swin.SetShadowType(gtk.SHADOW_IN)
	textview := gtk.NewTextView()
	var start, end gtk.TextIter
	buffer := textview.GetBuffer()
	buffer.GetStartIter(&start)

	// Print device information
	buffer.Insert(&start, "Devices found:")
	for i, device := range devices {
		buffer.GetEndIter(&end)
		buffer.Insert(&end, "\n\nDevice #" + strconv.Itoa(i) + ":")
		buffer.GetEndIter(&end)
		buffer.Insert(&end, "\n\tName: " + device.Name)
		buffer.GetEndIter(&end)
		buffer.Insert(&end, "\n\tDescription: " + device.Description)
		buffer.GetEndIter(&end)
		buffer.Insert(&end, "\n\tDevices addresses: ")
		for _, address := range device.Addresses {
			buffer.GetEndIter(&end)
			buffer.Insert(&end, "\n\t\tIP address: " + address.IP.String())
			buffer.GetEndIter(&end)
			buffer.Insert(&end, "\n\t\tSubnet mask: " + address.Netmask.String())
		}
	}
	//
	//tag := buffer.CreateTag("bold", map[string]string{
	//	"background": "#FF0000", "weight": "700"})
	//buffer.GetStartIter(&start)
	//buffer.GetEndIter(&end)
	//buffer.ApplyTag(tag, &start, &end)
	swin.Add(textview)
	framebox1.Add(swin)

	//--------------------------------------------------------
	// Sniffer settings
	//--------------------------------------------------------
	snifferSettings := gtk.NewHBox(false, 1)
	combobox := gtk.NewComboBoxEntryNewText()
	for _, device := range devices {
		combobox.AppendText(device.Name)
	}
	snifferSettings.Add(combobox)

	//--------------------------------------------------------
	// Sniffer results
	//--------------------------------------------------------
	resultsSwin := gtk.NewScrolledWindow(nil, nil)
	resultsSwin.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	resultsSwin.SetShadowType(gtk.SHADOW_IN)
	resultsTextView := gtk.NewTextView()
	//var startResults, endResuts gtk.TextIter
	//resultsBuffer := textview.GetBuffer()
	//buffer.GetStartIter(&start)
	resultsSwin.Add(resultsTextView)
	framebox2.Add(resultsSwin)

	//--------------------------------------------------------
	// Run button
	//--------------------------------------------------------
	buttons := gtk.NewHBox(false, 1)
	button := gtk.NewButtonWithLabel("Run sniffer")
	button.Clicked(func() {
		//println("button clicked:", button.GetLabel())
		//messagedialog := gtk.NewMessageDialog(
		//	button.GetTopLevelAsWindow(),
		//	gtk.DIALOG_MODAL,
		//	gtk.MESSAGE_INFO,
		//	gtk.BUTTONS_OK,
		//	entry.GetText())
		//messagedialog.Response(func() {
		//	println("Dialog OK!")
		//
		//	//--------------------------------------------------------
		//	// GtkFileChooserDialog
		//	//--------------------------------------------------------
		//	filechooserdialog := gtk.NewFileChooserDialog(
		//		"Choose File...",
		//		button.GetTopLevelAsWindow(),
		//		gtk.FILE_CHOOSER_ACTION_OPEN,
		//		gtk.STOCK_OK,
		//		gtk.RESPONSE_ACCEPT)
		//	filter := gtk.NewFileFilter()
		//	filter.AddPattern("*.go")
		//	filechooserdialog.AddFilter(filter)
		//	filechooserdialog.Response(func() {
		//		println(filechooserdialog.GetFilename())
		//		filechooserdialog.Destroy()
		//	})
		//	filechooserdialog.Run()
		//	messagedialog.Destroy()
		//})
		//messagedialog.Run()

		var iface = flag.String("i", combobox.GetActiveText(), "Interface to read packets from")
		var fname = flag.String("r", "", "Filename to read from, overrides -i")
		var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
		var tstype = flag.String("timestamp_type", "", "Type of timestamps to use")
		var promisc = flag.Bool("promisc", true, "Set promiscuous mode")
		var err error

		buffer := resultsTextView.GetBuffer()
		buffer.GetStartIter(&start)
		buffer.Insert(&start, "\n\tTest")


		defer util.Run()()
		var handle *pcap.Handle
		if *fname != "" {
			if handle, err = pcap.OpenOffline(*fname); err != nil {
				log.Fatal("PCAP OpenOffline error:", err)
			}
		} else {
			// This is a little complicated because we want to allow all possible options
			// for creating the packet capture handle... instead of all this you can
			// just call pcap.OpenLive if you want a simple handle.
			inactive, err := pcap.NewInactiveHandle(*iface)
			if err != nil {
				log.Fatalf("could not create: %v", err)
			}
			defer inactive.CleanUp()
			if err = inactive.SetSnapLen(*snaplen); err != nil {
				log.Fatalf("could not set snap length: %v", err)
			} else if err = inactive.SetPromisc(*promisc); err != nil {
				log.Fatalf("could not set promisc mode: %v", err)
			} else if err = inactive.SetTimeout(time.Second); err != nil {
				log.Fatalf("could not set timeout: %v", err)
			}
			if *tstype != "" {
				if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
					log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
				} else if err := inactive.SetTimestampSource(t); err != nil {
					log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
				}
			}
			if handle, err = inactive.Activate(); err != nil {
				log.Fatal("PCAP Activate error:", err)
			}
			defer handle.Close()
		}
		if len(flag.Args()) > 0 {
			bpffilter := strings.Join(flag.Args(), " ")
			fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
			if err = handle.SetBPFFilter(bpffilter); err != nil {
				log.Fatal("BPF filter error:", err)
			}
		}
		dumpcommand.Run(handle)
		// run sniffer

	})
	buttons.Add(button)
	snifferSettings.Add(buttons)

	framebox1.PackStart(snifferSettings, false, false, 0)

	window.Add(vbox)
	window.SetSizeRequest(600, 600)
	window.ShowAll()
	gtk.Main()
}
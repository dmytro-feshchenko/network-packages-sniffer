package main

import (
	"github.com/mattn/go-gtk/gtk"
	"os"
	"github.com/google/gopacket/pcap"
	"fmt"
	"log"
	"strconv"
)

//
//import (
//	"fmt"
//	"log"
//	"github.com/google/gopacket/pcap"
//	//"flag"
//	//"time"
//	//"strings"
//	"os"
//	//"github.com/google/gopacket/dumpcommand"
//	//"github.com/google/gopacket/examples/util"
//	"github.com/mattn/go-gtk/gtk"
//)
//
//func main() {
//	// Find all devices
//	devices, err := pcap.FindAllDevs()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Print device information
//	fmt.Println("Devices found:")
//	for _, device := range devices {
//		fmt.Println("\nName: ", device.Name)
//		fmt.Println("Description: ", device.Description)
//		fmt.Println("Devices addresses: ", device.Description)
//		for _, address := range device.Addresses {
//			fmt.Println("- IP address: ", address.IP)
//			fmt.Println("- Subnet mask: ", address.Netmask)
//		}
//	}
//
//	//var iface = flag.String("i", "en0", "Interface to read packets from")
//	//var fname = flag.String("r", "", "Filename to read from, overrides -i")
//	//var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
//	//var tstype = flag.String("timestamp_type", "", "Type of timestamps to use")
//	//var promisc = flag.Bool("promisc", true, "Set promiscuous mode")
//	//
//	//defer util.Run()()
//	//var handle *pcap.Handle
//	//if *fname != "" {
//	//	if handle, err = pcap.OpenOffline(*fname); err != nil {
//	//		log.Fatal("PCAP OpenOffline error:", err)
//	//	}
//	//} else {
//	//	// This is a little complicated because we want to allow all possible options
//	//	// for creating the packet capture handle... instead of all this you can
//	//	// just call pcap.OpenLive if you want a simple handle.
//	//	inactive, err := pcap.NewInactiveHandle(*iface)
//	//	if err != nil {
//	//		log.Fatalf("could not create: %v", err)
//	//	}
//	//	defer inactive.CleanUp()
//	//	if err = inactive.SetSnapLen(*snaplen); err != nil {
//	//		log.Fatalf("could not set snap length: %v", err)
//	//	} else if err = inactive.SetPromisc(*promisc); err != nil {
//	//		log.Fatalf("could not set promisc mode: %v", err)
//	//	} else if err = inactive.SetTimeout(time.Second); err != nil {
//	//		log.Fatalf("could not set timeout: %v", err)
//	//	}
//	//	if *tstype != "" {
//	//		if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
//	//			log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
//	//		} else if err := inactive.SetTimestampSource(t); err != nil {
//	//			log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
//	//		}
//	//	}
//	//	if handle, err = inactive.Activate(); err != nil {
//	//		log.Fatal("PCAP Activate error:", err)
//	//	}
//	//	defer handle.Close()
//	//}
//	//if len(flag.Args()) > 0 {
//	//	bpffilter := strings.Join(flag.Args(), " ")
//	//	fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
//	//	if err = handle.SetBPFFilter(bpffilter); err != nil {
//	//		log.Fatal("BPF filter error:", err)
//	//	}
//	//}
//	//dumpcommand.Run(handle)
//
//	gtk.Init(&os.Args)
//	gtk.Main()
//}

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
		//fmt.Println("\nName: ", device.Name)
		//fmt.Println("Description: ", device.Description)
		//fmt.Println("Devices addresses: ", device.Description)
		//for _, address := range device.Addresses {
		//	fmt.Println("- IP address: ", address.IP)
		//	fmt.Println("- Subnet mask: ", address.Netmask)
		//}
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
	combobox.AppendText("Element 1")
	combobox.AppendText("Element 2")
	combobox.AppendText("Element 3")
	snifferSettings.Add(combobox)

	framebox1.PackStart(snifferSettings, false, false, 0)


	window.Add(vbox)
	window.SetSizeRequest(600, 600)
	window.ShowAll()
	gtk.Main()
}
import threading
from Tkinter import *
import subprocess as sub

class CmdThread(threading.Thread):

    def __init__(self, cmd, textfield): 
        threading.Thread.__init__(self) 
        self.cmd       = cmd
        self.textfield = textfield
 
    def run(self):
        #self.gui.executer_set_state(True)
        p = sub.Popen(self.cmd, stdout=sub.PIPE, stderr=sub.STDOUT)
        while True:
            retcode = p.poll()
            line = p.stdout.readline()
            output = line.replace('\r', '')

            self.textfield.insert(END, output)
            self.textfield.pack()

            if retcode is not None:
                return


    def stop(self):
        self.stop = True

    def stopped(self):
        return self.stop



class IPProofGui(Frame):


    def run_script(self):

        no_transmissions = self.no_transmissions.get()

        print('ip destination:     %s'      % (self.config['ip-destination'].get()))
        print('port:               %s'      % (self.config['port'].get()))
        print('payload-pattern:    %s'      % (self.config['payload-pattern'].get()))
        print('transport-protocol: %s'      % (self.config['transport-protocol'].get()))
        print('network-protocol:   %s'      % (self.config['network-protocol'].get()))
        print('tx payload:         %s byte' % (self.config['tx-payload'].get()))
        print('rx payload:         %s byte' % (self.config['rx-payload'].get()))
        print('interval:           %s us'   % (self.config['interval'].get()))
        print('verify data:        %d'      % (self.config['verify-data'].get()))
        print('server delay:       %s ms'   % (self.config['server-delay'].get()))
        print('server delay var:   %s ms'   % (self.config['server-delay-var'].get()))
        print('bind:               %s'      % (self.config['bind'].get()))
        print('verbose:            %d'      % (self.config['verbose-output'].get()))

        path = 'Z:\\sdxr_platform\\tools\\ipproof\\win\\debug\\ipproof-client.exe'
        cmd = "%s -e %s -p %s -n %s --txpacketsize %s --rxpacketsize %s --transport %s --interval %s --server-delay %s --server-delay-variation %s" % \
            (path, self.config['ip-destination'].get(), self.config['port'].get(), no_transmissions,
                    self.config['tx-payload'].get(), self.config['rx-payload'].get(),
                    self.config['transport-protocol'].get(), self.config['interval'].get(),
                    self.config["server-delay"].get(), self.config["server-delay-var"].get())

        cmd += " --payload-pattern %s" % (self.config['payload-pattern'].get())

        if self.config["random-min"].get() and self.config["random-max"].get() and self.config["random-bw"].get():
                cmd += " --random %s:%s:%s" % (self.config["random-min"].get(), self.config["random-max"].get(), self.config["random-bw"].get())

        if self.config['verbose-output'].get():
            cmd += " -v -v"

        if self.config['bind'].get():
            cmd += " --bind %s" % (self.config['bind'].get())

        if self.config['verify-data'].get():
            cmd += " -c"

        proto = self.config['network-protocol'].get()
        if proto == "ipv4":
            cmd += " -4"
        elif proto == "ipv6":
            cmd += " -6"

        print("Now execute the following programm:\n%s" % (cmd))

        # clean screen
    	self.text1.pack()
        self.text1.delete("1.0", END)

        self.thread = CmdThread(cmd, self.text1)
        self.thread.start()



    def build_widgets(self):
        self.text1 = Text(self, bg="black", fg="green")
        self.text1.pack(side=TOP)


    def file_menu(self):
        help_btn = Menubutton(self.menu_frame, text='File', underline=0)
        help_btn.pack(side=LEFT, padx="1m")
        help_btn.menu = Menu(help_btn)
        help_btn.menu.add_command(label="Exit", underline=0, command=sys.exit)
        help_btn['menu'] = help_btn.menu
        return help_btn


    def help_menu(self):
        help_btn = Menubutton(self.menu_frame, text='Help', underline=0)
        help_btn.pack(side=RIGHT, padx="2m")
        help_btn.menu = Menu(help_btn)
        help_btn.menu.add_command(label="About", underline=0, command=None)
        help_btn['menu'] = help_btn.menu
        return help_btn


    def header(self, title):
        frame = Frame(self, width=500, bg="gray")
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text=title, bg="gray", font=("Helvetica", 9))
        label.grid(row=1, column=1)


    def ip_addr_fields(self):
        self.config["ip-destination"] = StringVar()
        self.config["ip-destination"].set("192.168.1.1")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="IPv{4,6} Destination Address:        ")
        entry = Entry(frame, textvariable=self.config["ip-destination"], width=25)

        label.grid(row=1, column=1)
        entry.grid(row=1, column=2)


    def port_fields(self):
        self.config["port"] = StringVar()
        self.config["port"].set("5001")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="Port:                                                ")
        entry = Entry(frame, textvariable=self.config["port"], width=6)

        label.grid(row=1, column=1)
        entry.grid(row=1, column=2)


    def interval_fields(self):
        self.config["interval"] = StringVar()
        self.config["interval"].set("1000000")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="Packet Interval [us]:                       ")
        entry = Entry(frame, textvariable=self.config["interval"], width=10)

        label.grid(row=1, column=1)
        entry.grid(row=1, column=2)



    def enfore_network_protocol_fields(self):
        self.config['network-protocol'] = StringVar()
        self.config['network-protocol'].set("unspec")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        b1 = Radiobutton(frame, text="UNSPEC", variable=self.config["network-protocol"], value="unspec")
        b2 = Radiobutton(frame, text="IPv4", variable=self.config["network-protocol"], value="ipv4")
        b3 = Radiobutton(frame, text="IPv6", variable=self.config["network-protocol"], value="ipv6")

        label = Label(frame, text="Enforce Network Protocol:            ")

        label.grid(row=1, column=1)
        b1.grid(row=1, column=2)
        b2.grid(row=1, column=3)
        b3.grid(row=1, column=4)

    def dscp_fields(self):
        self.config["dscp"] = StringVar()
        self.config["dscp"].set("")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        label  = Label(frame, text="Diffserv (DSCP, 0 - 63):                  ")
        entry  = Entry(frame, textvariable=self.config["dscp"], width=3)
        label2 = Label(frame, text="    Note: option has no effect under Microsoft Windows!", fg="red")

        label.grid(row=1, column=1)
        entry.grid(row=1, column=2)
        label2.grid(row=1, column=3)


    def tx_byte_fields(self):
        self.config["tx-payload"] = StringVar()
        self.config["tx-payload"].set("500")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="TX Packet Payload [byte]:              ")
        entry = Entry(frame, textvariable=self.config["tx-payload"], width=6)

        label.grid(row=1, column=1)
        entry.grid(row=1, column=2)


    def rx_byte_fields(self):
        self.config["rx-payload"] = StringVar()
        self.config["rx-payload"].set("0")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="RX Packet Payload [byte]:              ")
        entry = Entry(frame, textvariable=self.config["rx-payload"], width=6)

        label.grid(row=1, column=1)
        entry.grid(row=1, column=2)



    def no_transmissions_fields(self):
        self.no_transmissions = StringVar()
        self.no_transmissions.set("1")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="Number of Transmissions:               ")
        entry = Entry(frame, textvariable=self.no_transmissions, width=10)

        label.grid(row=1, column=1)
        entry.grid(row=1, column=2)


    def transport_protocol_fields(self):
        self.config['transport-protocol'] = StringVar()
        self.config['transport-protocol'].set("udp")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        b1 = Radiobutton(frame, text="UDP", variable=self.config["transport-protocol"], value="udp")
        b2 = Radiobutton(frame, text="TCP", variable=self.config["transport-protocol"], value="tcp")

        label = Label(frame, text="Transport Protocol:                       ")

        label.grid(row=1, column=1)
        b1.grid(row=1, column=2)
        b2.grid(row=1, column=3)


    def payload_pattern_fields(self):
        self.config['payload-pattern'] = StringVar()
        self.config['payload-pattern'].set("static")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        b1 = Radiobutton(frame, text="static (0xff)", variable=self.config["payload-pattern"], value="static")
        b2 = Radiobutton(frame, text="random", variable=self.config["payload-pattern"], value="random")
        b3 = Radiobutton(frame, text="ascii-random", variable=self.config["payload-pattern"], value="ascii-random")
        b4 = Radiobutton(frame, text="random-reduced", variable=self.config["payload-pattern"], value="random-reduced")

        label = Label(frame, text="Payload Pattern:                           ")

        label.grid(row=1, column=1)
        b1.grid(row=1, column=2)
        b2.grid(row=1, column=3)
        b3.grid(row=1, column=4)
        b4.grid(row=1, column=5)


    def server_delay_fields(self):
        self.config["server-delay"] = StringVar()
        self.config["server-delay"].set("0")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="Server Reply Delay [ms]:                ")
        entry = Entry(frame, textvariable=self.config["server-delay"], width=6)

        label.grid(row=1, column=1)
        entry.grid(row=1, column=2)


    def server_delay_var_fields(self):
        self.config["server-delay-var"] = StringVar()
        self.config["server-delay-var"].set("0")

        frame = Frame(self, width=500)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="Server Reply Delay Variation [ms]: ")
        entry = Entry(frame, textvariable=self.config["server-delay-var"], width=6)

        label.grid(row=1, column=1)
        entry.grid(row=1, column=2)


    def bind_fields(self):
        self.config["bind"] = StringVar()
        self.config["bind"].set("")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="Bind to Local Address:                     ")
        entry = Entry(frame, textvariable=self.config["bind"], width=25)

        label.grid(row=1, column=1)
        entry.grid(row=1, column=2)


    def random_fields(self):
        self.config["random-min"] = StringVar()
        self.config["random-min"].set("")

        self.config["random-max"] = StringVar()
        self.config["random-max"].set("")

        self.config["random-bw"] = StringVar()
        self.config["random-bw"].set("")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="Random Bandwidth:                       ")

        l1 = Label(frame, text="min [byte]:")
        e1 = Entry(frame, textvariable=self.config["random-min"], width=5)

        l2 = Label(frame, text="  max [byte]:")
        e2 = Entry(frame, textvariable=self.config["random-max"], width=5)

        l3 = Label(frame, text="  bandwidth [bit/sec]:")
        e3 = Entry(frame, textvariable=self.config["random-bw"], width=7)

        label.grid(row=1, column=1)

        l1.grid(row=1, column=2)
        e1.grid(row=1, column=3)

        l2.grid(row=1, column=4)
        e2.grid(row=1, column=5)

        l3.grid(row=1, column=6)
        e3.grid(row=1, column=7)


    def verify_fields(self):
        self.input_frame = Frame(self,width=500)
        self.input_frame.pack(expand=YES, fill=BOTH)

        self.config['verify-data'] = IntVar()
        label = Label(self.input_frame, text="Verify Payload:                              ")
        cb = Checkbutton(self.input_frame , text="", variable=self.config['verify-data'], command=None)

        label.grid(row=1, column=1)
        cb.grid(row=1, column=2)


    def verbose_fields(self):
        self.input_frame = Frame(self,width=500)
        self.input_frame.pack(expand=YES, fill=BOTH)

        self.config['verbose-output'] = IntVar()
        label = Label(self.input_frame, text="Verbose Output:                            ")
        cb = Checkbutton(self.input_frame , text="", variable=self.config['verbose-output'], command=None)

        label.grid(row=1, column=1)
        cb.grid(row=1, column=2)


    def seperator(self):
        frame = Frame(self, width=500)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="", font=("Helvetica", 9))
        label.grid(row=1, column=1)


    def start_test(self):
        frame = Frame(self, width=500)
        frame.pack(expand=YES, fill=BOTH)

        self.button = Button(frame)
        self.button["text"] = "Start IPProof"
        self.button["command"] = self.run_script
        self.button.pack(side=RIGHT)



    def menu(self):
        self.menu_frame = Frame(root)
        self.menu_frame.pack(fill=X, side=TOP)
        self.menu_frame.tk_menuBar(self.file_menu(), self.help_menu())


    def __init__(self, master=None):
        
        self.config = dict()
        self.executer_state = False

        Frame.__init__(self, master)
        self.menu()

        # network protocol
        self.header("Network Protocol")
        self.ip_addr_fields()
        self.bind_fields()
        self.enfore_network_protocol_fields()
        self.dscp_fields()


        # transport protocol
        self.header("Transport Protocol")
        self.port_fields()
        self.transport_protocol_fields()

        # data layer
        self.header("Data Layer")
        self.tx_byte_fields()
        self.rx_byte_fields()
        self.no_transmissions_fields()
        self.interval_fields()
        self.payload_pattern_fields()
        self.server_delay_fields()
        self.server_delay_var_fields()
        self.random_fields()
        self.verify_fields()

        self.header("Misc")
        self.verbose_fields()

        self.seperator()
        self.start_test()
        self.seperator()

        self.pack()
        self.build_widgets()




root = Tk()
root.title("IPProof Client GUI - Tikletta (C)")
app = IPProofGui(master = root)
app.mainloop()

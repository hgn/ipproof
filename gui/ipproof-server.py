import threading
from Tkinter import *
import subprocess as sub

class CmdThread(threading.Thread):

    def __init__(self, cmd, textfield): 
        threading.Thread.__init__(self) 
        self.cmd       = cmd
        self.textfield = textfield
        self.process = None
 
 
    def run(self):
        #self.gui.executer_set_state(True)
        self.process= sub.Popen(self.cmd, stdout=sub.PIPE, stderr=sub.STDOUT)
        while True:
            retcode = self.process.poll()
            line = self.process.stdout.readline()
            output = line.replace('\r', '')

            self.textfield.insert(END, output)
            self.textfield.pack()

            if retcode is not None:
            	self.process = None
                return


    def stop(self):
    	if self.process:
    		self.process.kill()

    def stopped(self):
        return self.process == None



class IPProofGui(Frame):


    def run_script(self):
        if self.thread and not self.thread.stopped():
    	    self.text1.insert(END, "Stop running process first ...")
    	    print('kill existing ipproof-server first ...')
            self.text1.pack()
            self.thread.stop()

        print('port:               %s'      % (self.config['port'].get()))
        print('transport-protocol: %s'      % (self.config['transport-protocol'].get()))
        print('network-protocol:   %s'      % (self.config['network-protocol'].get()))
        print('bind:               %s'      % (self.config['bind'].get()))
        print('verbose:            %d'      % (self.config['verbose-output'].get()))

        path = 'Z:\\sdxr_platform\\tools\\ipproof\\win\\debug\\ipproof-server.exe'
        cmd = "%s -p %s --transport %s" % \
            (path,
             self.config['port'].get(),
             self.config['transport-protocol'].get())

        if self.config['verbose-output'].get():
            cmd += " -v -v"

        if self.config['bind'].get():
            cmd += " --bind %s" % (self.config['bind'].get())

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
        frame = Frame(self, width=800, bg="gray")
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text=title, bg="gray", font=("Helvetica", 9))
        label.grid(row=1, column=1)


    def port_fields(self):
        self.config["port"] = StringVar()
        self.config["port"].set("5001")

        frame = Frame(self,width=500)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="Port:                                                ")
        entry = Entry(frame, textvariable=self.config["port"], width=6)

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


    def bind_fields(self):
        self.config["bind"] = StringVar()
        self.config["bind"].set("")

        frame = Frame(self,width=600)
        frame.pack(expand=YES, fill=BOTH)

        label = Label(frame, text="Bind to Local Address:                     ")
        entry = Entry(frame, textvariable=self.config["bind"], width=25)

        label.grid(row=1, column=1)
        entry.grid(row=1, column=2)


    def verbose_fields(self):
        self.input_frame = Frame(self,width=600)
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
        self.thread = None

        Frame.__init__(self, master)
        self.menu()

        # network protocol
        self.header("Network Protocol")
        self.bind_fields()
        self.enfore_network_protocol_fields()


        # transport protocol
        self.header("Transport Protocol")
        self.port_fields()
        self.transport_protocol_fields()

        self.header("Misc")
        self.verbose_fields()

        self.seperator()
        self.start_test()
        self.seperator()

        self.pack()
        self.build_widgets()




root = Tk()
root.title("IPProof Server GUI - Tikletta (C)")
app = IPProofGui(master = root)
app.mainloop()

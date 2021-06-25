import os, hashlib, math, time
from tkinter.ttk import Label,Entry,Style
from tkinter import Tk,messagebox,Text,Spinbox,Checkbutton,BooleanVar,END,Button

class AvalancheEffect:
	def __init__(self,x,y):
		self.x = str.encode(str(x))
		self.y = str.encode(str(y))
	def differentBits(self):
		self.x = (bin(int.from_bytes(self.x, byteorder="big"))[2:])
		self.y = (bin(int.from_bytes(self.y, byteorder="big"))[2:])
		nmax = max(len(self.x),len(self.y))
		self.x = list((nmax - len(self.x)) * str(0) + self.x)
		self.y = list((nmax - len(self.y)) * str(0) + self.y)
		counter = 0
		for i in range(nmax):
		    if (self.x[i] != self.y[i]):
		        counter += 1
		return counter/nmax

class DiffieHellman:
	def __init__(self,secret=None,auto=True,data=(2,5)):
		self.primes = {
			# 2048-bit (512-hex)
			"prime": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
			"generator": 2
		}
		if auto:
			self.p = self.primes["prime"]
			self.g = self.primes["generator"]
		else:
			self.p = data[1]
			self.g = data[0]

		if secret:
			self.scKey = secret
		else:
			self.scKey = int.from_bytes(os.urandom(5), "big")

	def get_private_key(self):
		return self.scKey

	def gen_public_key(self):
		return pow(self.g, self.scKey, self.p)

	def check_other_public_key(self, other_contribution):
		if math.gcd(self.p, self.g)==1:
			return True
		return False

	def gen_shared_key(self, other_contribution):
		if self.check_other_public_key(other_contribution):
			self.shared_key = pow(other_contribution, self.scKey, self.p)
			# return hashlib.sha256(str(self.shared_key).encode()).hexdigest(),hashlib.sha256(str(self.shared_key).encode()).hexdigest()
			return self.shared_key,hashlib.sha256(str(self.shared_key).encode()).hexdigest()

class Gui(Tk):
	def __init__(self):
		super().__init__()
		self.current = None
		self.counter = 0
		self.rates = 0

		#Windows
		self.iconbitmap("favicon.ico")
		self.title("Diffie Hellman")
		self.geometry("400x570")
		self.configure(bg="#51c4d3")

		#deklarasi style
		Style().configure('coloring.TLabel', foreground='#132c33', background='#51c4d3')
		Style().configure('coloring.TButton',bg="#126e82",activebackground="#132c33")
		Style().configure('coloring.TCheckbutton', foreground='red', background='#132c33')

		#Label
		self.lblTitle = Label(self, text="Diffie-Hellman Key Exchange", font=(9),style="coloring.TLabel")
		self.lblTitle.grid(row=0, column=0, columnspan=7, pady = (15,5))

		self.lblKeyA = Label(self, text="Private Key A :",style="coloring.TLabel")
		self.lblKeyA.grid(row=3, column=0, columnspan=3, pady = (0,3))

		self.lblKeyB = Label(self, text="Private Key B :",style="coloring.TLabel")
		self.lblKeyB.grid(row=3, column=4, columnspan=3, pady = (0,3))

		self.lblPg = Label(self, text="<", width=1,style="coloring.TLabel")
		self.lblPg.grid(row=2, column=1, pady=(0,15))

		self.lblLeft = Label(self, text="Generator(g)", width=12,style="coloring.TLabel")
		self.lblLeft.grid(row=1, column=0, pady=(10,0))

		self.lblMid = Label(self, text="Large Prime (2048 bit)", width=20,style="coloring.TLabel")
		self.lblMid.grid(row=1, column=4, columnspan=3, pady=(10,0))

		self.lblRight = Label(self, text="Prime(p)", width=8,style="coloring.TLabel")
		self.lblRight.grid(row=1, column=2, pady=(10,0))

		self.lblGen = Label(self, text="Symmetric Key :",style="coloring.TLabel")
		self.lblGen.grid(row=6, column=0, columnspan=7, pady = (10,0))

		self.lblSha = Label(self, text="SHA256 :",style="coloring.TLabel")
		self.lblSha.grid(row=9, column=0, pady=(10,0))

		self.lblPub = Label(self, text="Public Key :",style="coloring.TLabel")
		self.lblPub.grid(row=8, column=0, pady=(10,0))

		self.lblAF = Label(self, text="Avalanche Effect Symmetric Key :",style="coloring.TLabel")
		self.lblAF.grid(row=10, column=0, columnspan=7, pady=(10,0))

		self.lblRatec = Label(self, text="Rate/Counter : 0%", anchor="w", width=20,style="coloring.TLabel")
		self.lblRatec.grid(row=11, column=0, columnspan=3)

		self.lblRate = Label(self, text="Total Rate : 0%", anchor="w", width=20,style="coloring.TLabel")
		self.lblRate.grid(row=12, column=0, columnspan=3,)

		self.lblCounter = Label(self, text="Counter : 0", anchor="w", width=20,style="coloring.TLabel")
		self.lblCounter.grid(row=13, column=0, columnspan=3,)

		#Checkbutton
		self.chcValue = BooleanVar()
		self.chcPg = Checkbutton(self, text="2 < (2048-bit)", onvalue=1, offvalue=0, variable=self.chcValue, command=self.largePG,bg="#51c4d3",activebackground="#51c4d3")
		self.chcPg.grid(row = 2, column = 4, columnspan=3, pady=(0,15))

		#Text Area
		self.txtA = Text(self, height = 5, width = 22)
		self.txtA.grid(row=4, column=0, columnspan=3, padx=10)

		self.txtB = Text(self, height = 5, width = 22)
		self.txtB.grid(row=4, column=4, columnspan=3, padx=10)

		self.txtH = Text(self, height = 5, width = 47, bg = "light cyan", state="disabled")
		self.txtH.grid(row=7, column=0, columnspan=7, padx=10)

		self.txtSha = Text(self, height = 2, width = 37, bg = "light cyan", state="disabled")
		self.txtSha.grid(row=9, column=1, columnspan=6, padx=(0,10),pady=(10,0))

		self.txtPub = Text(self, height = 2, width = 37, bg = "light cyan", state="disabled")
		self.txtPub.grid(row=8, column=1, columnspan=6, padx=(0,10),pady=(10,0))

		#Spin Box
		self.spLeft = Spinbox(self, from_=2, to=3, width=5)
		self.spLeft.grid(row=2, column=0, pady=(0,15))

		self.spRight = Spinbox(self, from_=97, to=9999999, width=5)
		self.spRight.grid(row=2, column=2, pady=(0,15))

		#Button
		self.btnGenerate = Button(self, text="Generate", width=12, command = self.generate,bg="#126e82",activebackground="#132c33",fg="white",activeforeground="white")
		self.btnGenerate.grid(row=5, column=0, columnspan=7, pady=(10,0))

		self.btnRandom = Button(self, text="Range(500)", width=15, command = self.random,bg="#126e82",activebackground="#132c33",fg="white",activeforeground="white")
		self.btnRandom.grid(row=12, column=4, columnspan=3)

		self.btnReset = Button(self, text="Reset", width=15, command = self.reset,bg="#126e82",activebackground="#132c33",fg="white",activeforeground="white")
		self.btnReset.grid(row=13, column=4, columnspan=3)

	def reset(self,x=True):
		self.stateLock(False)
		if x:
			self.current = None
			self.counter = 0
			self.rates = 0
			self.lblCounter["text"] = f"Counter : {self.counter}"
			self.lblRatec["text"] = f"Rate/Counter : {self.rates}%"
			self.lblRate["text"] = f"Total Rate : {self.rates}%"
		self.txtSha.delete("1.0", END)
		self.txtH.delete("1.0", END)
		self.txtA.delete("1.0", END)
		self.txtB.delete("1.0", END)
		self.txtPub.delete("1.0", END)
		self.stateLock(True)

	def random(self):
		self.reset(False)
		self.stateLock(False)
		n=912369123746912409747120730923708273120931238712837914282013712948712047123905839598236413401240347612370
		# n=5
		for x in range(n,n+500):
			d1 = DiffieHellman(x,auto=int(self.chcValue.get()),data=(int(self.spLeft.get()),int(self.spRight.get())))
			d2 = DiffieHellman(n,auto=int(self.chcValue.get()),data=(int(self.spLeft.get()),int(self.spRight.get())))

			d1_public = d1.gen_public_key()
			d2_public = d2.gen_public_key()

			d1_simetri = d1.gen_shared_key(d2_public)
			d2_simetri = d2.gen_shared_key(d1_public)

			if d1_simetri==d2_simetri:
				time.sleep(0.1)
				self.txtA.delete("1.0", END)
				self.txtA.insert(END, x)
				self.txtB.delete("1.0", END)
				self.txtB.insert(END, n)
				self.txtH.delete("1.0", END)
				self.txtH.insert(END, d1_simetri[0])
				self.txtSha.delete("1.0", END)
				self.txtSha.insert(END, d1_simetri[1])
				self.txtPub.delete("1.0", END)
				self.txtPub.insert(END, f"{d1_public}|{d2_public}")
				rate = AvalancheEffect(x,d1_simetri[0])
				self.counter+=1
				now = rate.differentBits()
				self.rates += now
				show = self.rates/self.counter
				self.lblCounter["text"] = f"Counter : {self.counter}"
				self.lblRate["text"] = "Total Rate : {:.2f}%".format(float(show)*100)
				self.lblRatec["text"] = "Rate/Counter : {:.2f}%".format(float(now)*100)
				self.update()
		self.stateLock(True)

	def generate(self):
		self.stateLock(False)
		d1 = DiffieHellman(int(self.txtA.get("1.0", "end-1c")),int(self.chcValue.get()),(int(self.spLeft.get()),int(self.spRight.get())))
		d2 = DiffieHellman(int(self.txtB.get("1.0", "end-1c")),int(self.chcValue.get()),(int(self.spLeft.get()),int(self.spRight.get())))

		d1_public = d1.gen_public_key()
		d2_public = d2.gen_public_key()

		d1_simetri = d1.gen_shared_key(d2_public)
		d2_simetri = d2.gen_shared_key(d1_public)
		if d1_simetri==d2_simetri and d1_simetri is not None:
			self.txtH.delete("1.0", END)
			self.txtH.insert(END, d1_simetri[0])
			self.txtSha.delete("1.0", END)
			self.txtSha.insert(END, d1_simetri[1])
			self.txtPub.delete("1.0", END)
			self.txtPub.insert(END, f"{d1_public}|{d2_public}")
			rate = AvalancheEffect(d1.get_private_key(),d1_simetri[0])
			self.counter+=1
			now = rate.differentBits()
			self.rates += now
			show = self.rates/self.counter
			self.lblCounter["text"] = f"Counter : {self.counter}"
			self.lblRate["text"] = "Total Rate : {:.2f}%".format(float(show)*100)
			self.lblRatec["text"] = "Rate/Counter : {:.2f}%".format(float(now)*100)
		else:
			messagebox.showinfo("Warning", "GCD(g, p) != 1")
		self.stateLock(True)

	def largePG(self):
		if self.chcValue.get():
			self.spLeft["state"] = "disabled"
			self.spRight["state"] = "disabled"
		else:
			self.spLeft["state"] = "normal"
			self.spRight["state"] = "normal"

	def stateLock(self,x):
		if x:
			self.txtH["state"] = "disabled"
			self.txtSha["state"] = "disabled"
			self.txtPub["state"] = "disabled"
		else:
			self.txtH["state"] = "normal"
			self.txtSha["state"] = "normal"
			self.txtPub["state"] = "normal"

if __name__ == '__main__':
	rt = Gui()
	rt.resizable(width=False, height=False)
	rt.mainloop()
	# dh = DiffieHellman()
	# print(bin(dh.primes["prime"]))
else:
	print("Run the main program.")
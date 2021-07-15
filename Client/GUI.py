# import everything from tkinter module
from tkinter import *
from functools import partial
from functools import update_wrapper
from tkinter import messagebox
from tkinter import filedialog
from Client import ClientNetworkInterface


class Gui:
    def __init__(self):
        self.client_obj = ClientNetworkInterface.ClientNetworkInterface()
        self.list_of_buttons = list()
        self.logged_in = None
        self.login_button = None
        self.register_button = None
        self.viewfiles_button = None
        self.view_shared_user_files_button= None
        self.get_cocks_params_button = None
        self.send_file_button = None
        self.download_file_button = None
        self.register_button = None
        self.logout_button = None
        self.delete_file_button = None
        self.view_file_access_list_button = None
        self.update_file_access_list_button = None
        self.download_shared_file_button = None
        self.upload_shared_file_button = None
        self.listbox = None

    def start(self):
        self.root = Tk()
        self.root.geometry('500x450')

        self.logged_in = Label(self.root)
        self.logged_in.config(text="Logged in as: ")
        self.logged_in.place(x=10, y=10)

        self.login_button = Button(self.root)
        self.login_button.config(text='Login', command=self.login)
        self.login_button.place(x=200, y=10)

        self.register_button = Button(self.root)
        self.register_button.config(text='Register', command=self.register)
        self.register_button.place(x=250, y=10)

        self.logout_button = Button(self.root)
        self.logout_button.config(text='Logout', command=self.logout, state=DISABLED)
        self.logout_button.place(x=310, y=10)

        self.viewfiles_button = Button(self.root)
        self.viewfiles_button.config(text='View Stored Files', command=self.viewfiles, state=DISABLED)
        self.viewfiles_button.place(x=300, y=80)

        self.view_shared_user_files_button = Button(self.root)
        self.view_shared_user_files_button.config(text='View All Files Shared with you', command=self.view_shared_files, state=DISABLED)
        self.view_shared_user_files_button.place(x=300, y=110)

        self.get_cocks_params_button = Button(self.root)
        self.get_cocks_params_button.config(text='Get Cocks Parameters', command=self.get_cocks_params, state=DISABLED)
        self.get_cocks_params_button.place(x=300, y=140)

        self.send_file_button = Button(self.root)
        self.send_file_button.config(text='Upload File', command=self.uploadfile, state=DISABLED)
        self.send_file_button.place(x=300, y=170)

        self.download_file_button = Button(self.root)
        self.download_file_button.config(text='Download File', command=self.downloadfile, state=DISABLED)
        self.download_file_button.place(x=300, y=200)

        self.delete_file_button = Button(self.root)
        self.delete_file_button.config(text='Delete File', command=self.deletefile, state=DISABLED)
        self.delete_file_button.place(x=300, y=230)

        self.view_file_access_list_button = Button(self.root)
        self.view_file_access_list_button.config(text='View File Access List', command=self.view_file_access_list, state=DISABLED)
        self.view_file_access_list_button.place(x=300, y=260)

        self.update_file_access_list_button = Button(self.root)
        self.update_file_access_list_button.config(text='Update File Access List', command=self.edit_access_list, state=DISABLED)
        self.update_file_access_list_button.place(x=300, y=290)

        self.download_shared_file_button = Button(self.root)
        self.download_shared_file_button.config(text='Download Shared File', command=self.download_shared_file, state=DISABLED)
        self.download_shared_file_button.place(x=300, y=320)

        self.upload_shared_file_button = Button(self.root)
        self.upload_shared_file_button.config(text='Upload Shared File', command=self.upload_shared_file, state=DISABLED)
        self.upload_shared_file_button.place(x=300, y=350)

        self.listbox = Listbox(self.root)
        self.listbox.config(width=30, height=20)
        self.listbox.place(x=70,y=70)

        # disconnect button will be the x

        self.root.mainloop()
        # 14 buttons??

    def login(self):
        login = Tk()
        login.geometry('300x150')
        login.title("Login")

        user_name = Label(login, text="Username").place(x=10, y=20)
        user_password = Label(login, text="Password").place(x=10, y=50)

        user_name_input_area = Entry(login)
        user_name_input_area.config(width=30)
        user_name_input_area.place(x=70, y=20)
        user_password_entry_area = Entry(login)
        user_password_entry_area.config(width=30, show='*')
        user_password_entry_area.place(x=70, y=50)

        #self.validate_login = partial(self.validate_login, user_name_input_area, user_password_entry_area, login)

        submit_button = Button(login, text="Submit", command=lambda: self.validate_login(user_name_input_area,user_password_entry_area, login)).place(x=40, y=90)

        login.mainloop()

    def validate_login(self, username, password, window):
        command = "login|" + username.get() + "|" + password.get()

        if username.get() == '' or password.get() == '':
            messagebox.showinfo("Information", "Password/Username field cannot be empty.")
            return -1

        self.client_obj.process_command_and_send(command)
        result = self.client_obj.process_received_message(self.client_obj.receive_message())

        if result == "Login successful.":
            messagebox.showinfo("Information", "Login successful.")
            # enable/disable all the buttons
            if self.client_obj.r == -1:
                messagebox.showinfo("Information", "Local Private parameters have been compromised.")

            self.logged_in.config(text="Logged in as: " + self.client_obj.logged_in_as)

            self.login_button.config(state=DISABLED)
            self.logout_button.config(state=NORMAL)
            self.viewfiles_button.config(state=NORMAL)
            self.view_shared_user_files_button.config(state=NORMAL)
            self.get_cocks_params_button.config(state=NORMAL)
            self.send_file_button.config(state=DISABLED)
            self.download_file_button.config(state=DISABLED)
            self.delete_file_button.config(state=DISABLED)
            self.view_file_access_list_button.config(state=DISABLED)
            self.update_file_access_list_button.config(state=DISABLED)
            self.download_shared_file_button.config(state=DISABLED)
            self.upload_shared_file_button.config(state=DISABLED)
            window.destroy()
        else:
            # do nothing
            messagebox.showinfo("Information", result)

    def logout(self):
        command = "logout"
        self.client_obj.process_command_and_send(command)
        result = self.client_obj.process_received_message(self.client_obj.receive_message())

        if result == "Logged out succesfully":
            messagebox.showinfo("Information", result)

            self.logged_in.config(text="Logged in as: " + self.client_obj.logged_in_as)

            self.login_button.config(state=NORMAL)
            self.logout_button.config(state=DISABLED)
            self.viewfiles_button.config(state=DISABLED)
            self.view_shared_user_files_button.config(state=DISABLED)
            self.get_cocks_params_button.config(state=DISABLED)
            self.send_file_button.config(state=DISABLED)
            self.download_file_button.config(state=DISABLED)
            self.delete_file_button.config(state=DISABLED)
            self.view_file_access_list_button.config(state=DISABLED)
            self.update_file_access_list_button.config(state=DISABLED)
            self.download_shared_file_button.config(state=DISABLED)
            self.upload_shared_file_button.config(state=DISABLED)
            self.listbox.delete(0, 'end')
        else:
            #do nothing
            messagebox.showinfo("Information", result)

    def register(self):
        register = Tk()
        register.geometry('300x150')
        register.title("Register")

        user_name = Label(register, text="Username").place(x=10, y=20)
        user_password = Label(register, text="Password").place(x=10, y=50)

        user_name_input_area = Entry(register)
        user_name_input_area.config(width=30)
        user_name_input_area.place(x=70, y=20)
        user_password_entry_area = Entry(register)
        user_password_entry_area.config(width=30, show='*')
        user_password_entry_area.place(x=70, y=50)

        #self.register_request = partial(self.register_request, user_name_input_area, user_password_entry_area, register)

        submit_button = Button(register, text="Submit", command=lambda: self.register_request(user_name_input_area, user_password_entry_area, register)).place(x=40, y=90)

        register.mainloop()

    def register_request(self, username, password, window):
        command = "register|" + username.get() + "|" + password.get()

        if username.get() == '' or password.get() == '':
            messagebox.showinfo("Information", "Password/Username field cannot be empty.")
            return -1

        self.client_obj.process_command_and_send(command)
        result = self.client_obj.process_received_message(self.client_obj.receive_message())

        if result == "Registering successful.":
            window.destroy()
            messagebox.showinfo("Information", result)
        else:
            messagebox.showinfo("Information", result)

    def viewfiles(self):
        command = "viewfiles"
        self.client_obj.process_command_and_send(command)
        result = self.client_obj.process_received_message(self.client_obj.receive_message())

        self.send_file_button.config(state=NORMAL)
        self.download_file_button.config(state=NORMAL)
        self.download_shared_file_button.config(state=DISABLED)
        self.upload_shared_file_button.config(state=DISABLED)
        self.delete_file_button.config(state=NORMAL)
        self.view_file_access_list_button.config(state=NORMAL)
        self.update_file_access_list_button.config(state=NORMAL)

        self.listbox.delete(0, 'end')
        for i in range(0, len(result)):
            self.listbox.insert('end', result[i])

    def filebrowser(self):
        file = filedialog.askopenfilename(initialdir=r"C:\Users\lazar\Desktop\Files_to_upload", title="Select a File")
        return file

    def uploadfile(self):
        file = self.filebrowser()
        #print(file)
        if file != '':
            file = file.replace("/", "\\")
            command = "send_file|"+file
            self.client_obj.process_command_and_send(command)
            result = self.client_obj.process_received_message(self.client_obj.receive_message())
            self.viewfiles_button.invoke()
            messagebox.showinfo("Information", result)

    def downloadfile(self):
        if self.listbox.get(self.listbox.curselection()[0]) != '':
            command = "download_file|" + self.listbox.get(self.listbox.curselection()[0]) + "|" + r"C:\Users\lazar\Desktop\Scheme\Download"
            self.client_obj.process_command_and_send(command)
            result = self.client_obj.process_received_message(self.client_obj.receive_message())
            messagebox.showinfo("Information", result)
            if self.client_obj.viewed_var == 1:
                messagebox.showinfo("Information", "The file has been accessed by someone else.")
                self.client_obj.viewed_var = 0
            if self.client_obj.modified_var == 1:
                messagebox.showinfo("Information", "The file has been modified by someone else.")
                self.client_obj.modified_var = 0

            self.viewfiles_button.invoke()

    def deletefile(self):
        if self.listbox.get(self.listbox.curselection()[0]) != '':
            command = "delete_file|" + self.listbox.get(self.listbox.curselection()[0])
            self.client_obj.process_command_and_send(command)
            result = self.client_obj.process_received_message(self.client_obj.receive_message())
            messagebox.showinfo("Information", result)
            self.viewfiles_button.invoke()

    def view_file_access_list(self):
        if self.listbox.get(self.listbox.curselection()[0]) != '':
            command = "view_file_access_list|" + self.listbox.get(self.listbox.curselection()[0])
            self.client_obj.process_command_and_send(command)
            result = self.client_obj.process_received_message(self.client_obj.receive_message())
            messagebox.showinfo("File access list", "The following users have access to this file: \n" + result)

    def view_shared_files(self):
        command = "view_shared_user_files"
        self.client_obj.process_command_and_send(command)
        result = self.client_obj.process_received_message(self.client_obj.receive_message())

        self.send_file_button.config(state=DISABLED)
        self.download_file_button.config(state=DISABLED)
        self.download_shared_file_button.config(state=NORMAL)
        self.upload_shared_file_button.config(state=NORMAL)
        self.delete_file_button.config(state=DISABLED)
        self.view_file_access_list_button.config(state=DISABLED)
        self.update_file_access_list_button.config(state=DISABLED)

        self.listbox.delete(0, 'end')
        for i in range(0, len(result)):
            self.listbox.insert('end', result[i])

    def edit_access_list(self):
        if self.listbox.get(self.listbox.curselection()[0]) != '':
            access_list = Tk()
            access_list.geometry('300x150')
            access_list.title("Modify Access List")

            user = Label(access_list, text="Username").place(x=10, y=20)

            user_input_area = Entry(access_list)
            user_input_area.config(width=30)
            user_input_area.place(x=70, y=20)

            #self.add_to_access_list = partial(self.add_to_access_list, user_input_area, access_list)
            #self.remove_from_access_list = partial(self.remove_from_access_list, user_input_area, access_list)

            add_button = Button(access_list, text="Add User", command=lambda: self.add_to_access_list(user_input_area, access_list)).place(x=40, y=90)
            remove_button = Button(access_list, text="Remove User", command=lambda: self.remove_from_access_list(user_input_area, access_list)).place(x=120, y=90)

            access_list.mainloop()

    def add_to_access_list(self, user, window):
        if user.get() !='' and self.listbox.get(self.listbox.curselection()[0]) != '':
            command = "update_file_access_list|" + self.listbox.get(self.listbox.curselection()[0]) + "|add|" + user.get()
            self.client_obj.process_command_and_send(command)
            result = self.client_obj.process_received_message(self.client_obj.receive_message())

            if result == "Access list updated successfully":
                messagebox.showinfo("Information", result)
                window.destroy()
            else:
                messagebox.showinfo("Information", result)

    def remove_from_access_list(self, user, window):
        if user.get() != '' and self.listbox.get(self.listbox.curselection()[0]) != '':
            command = "update_file_access_list|" + self.listbox.get(
                self.listbox.curselection()[0]) + "|delete|" + user.get()
            self.client_obj.process_command_and_send(command)
            result = self.client_obj.process_received_message(self.client_obj.receive_message())

            if result == "Access list updated successfully":
                messagebox.showinfo("Information", result)
                window.destroy()
            else:
                messagebox.showinfo("Information", result)

    def get_cocks_params(self):
        cocks_params = Tk()
        cocks_params.geometry('300x150')
        cocks_params.title("Parameter recovery")

        password = Label(cocks_params, text="Password")
        password.place(x=10, y=20)

        user_input_area = Entry(cocks_params,show="*")
        user_input_area.config(width=30)
        user_input_area.place(x=70, y=20)

        #self.cocks_request = partial(self.cocks_request, user_input_area, cocks_params)

        request_send_button = Button(cocks_params, text="Send request", command=lambda: self.cocks_request(user_input_area, cocks_params)).place(x=40, y=90)

        cocks_params.mainloop()

    def cocks_request(self, password, window):
        if password.get() != '':
            command = "get_cocks_params|" + password.get()
            self.client_obj.process_command_and_send(command)
            result = self.client_obj.process_received_message(self.client_obj.receive_message())
            if result == "Cocks params redownloaded successfully":
                messagebox.showinfo("Information", result)
                window.destroy()
            else:
                messagebox.showinfo("Information", result)

    def download_shared_file(self):
        if self.listbox.get(self.listbox.curselection()[0]) != '':
            listbox_line = self.listbox.get(self.listbox.curselection()[0])
            listbox_line = listbox_line.split("|")
            file = listbox_line[1][5:]
            owner = listbox_line[0][6:]
            command = "download_shared_file|" + owner + "|" + file + r"|C:\Users\lazar\Desktop\Scheme\Download"
            self.client_obj.process_command_and_send(command)
            result = self.client_obj.process_received_message(self.client_obj.receive_message())
            messagebox.showinfo("Information", result)

    def browsefunction(self, field, window):
        file = filedialog.askopenfilename(initialdir=r"C:\Users\lazar\Desktop\Files_to_upload", title="Select a File")
        field.delete(0, END)
        field.insert(END, file)
        window.focus_force()

    def upload_shared_file(self):
        upload_file = Tk()
        upload_file.geometry('400x150')
        upload_file.title("Upload Window")

        username = Label(upload_file, text="Username").place(x=10, y=20)
        file_location = Label(upload_file, text="File Location").place(x=10, y=50)

        browse_button = Button(upload_file)
        browse_button.config(text="Browse", command=lambda: self.browsefunction(file_location_entry_area, upload_file))
        browse_button.place(x=300, y=50)

        username_input_area = Entry(upload_file)
        username_input_area.config(width=30)
        username_input_area.place(x=90, y=20)
        file_location_entry_area = Entry(upload_file)
        file_location_entry_area.config(width=30)
        file_location_entry_area.place(x=90, y=50)

        # self.register_request = partial(self.register_request, user_name_input_area, user_password_entry_area, register)

        submit_button = Button(upload_file, text="Upload file",command=lambda: self.upload_shared_file_form(username_input_area, file_location_entry_area, upload_file)).place(x=40, y=90)

        upload_file.mainloop()

    def upload_shared_file_form(self, user, file, window):
        if user.get() != '' and file.get() != '':
            command = "upload_shared_file|" + user.get() +"|"+ file.get().replace("/", "\\")
            self.client_obj.process_command_and_send(command)
            result = self.client_obj.process_received_message(self.client_obj.receive_message())
            if result == "Hash result Ok":
                messagebox.showinfo("Information", result)
                window.destroy()
            else:
                messagebox.showinfo("Information", result)
                window.focus_force()


obj = Gui()
obj.start()
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
import json

class MedicalIntakeForm:
    def __init__(self, root):
        self.root = root
        self.root.title("Physician Group 1.0")
        self.root.geometry("600x800")
        self.root.configure(bg='#f0f0f0')
        
        # Create main frame with scrollbar
        self.canvas = tk.Canvas(root, bg='#f0f0f0')
        self.scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Initialize variables
        self.init_variables()
        
        # Create the form
        self.create_form()
        
        # Pack canvas and scrollbar
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Bind mousewheel to canvas
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
    
    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def init_variables(self):
        # Personal Information
        self.first_name = tk.StringVar()
        self.last_name = tk.StringVar()
        self.date_of_birth = tk.StringVar()
        self.gender = tk.StringVar()
        self.phone = tk.StringVar()
        self.email = tk.StringVar()
        self.ssn = tk.StringVar()
        self.address = tk.StringVar()
        self.emergency_contact = tk.StringVar()
        self.emergency_phone = tk.StringVar()
        
        # Insurance Information
        self.insurance_provider = tk.StringVar()
        self.policy_number = tk.StringVar()
        self.group_number = tk.StringVar()
        
        # Medical History
        self.primary_care_physician = tk.StringVar()
        self.allergies = tk.StringVar()
        self.chronic_conditions = []
        self.previous_surgeries = tk.StringVar()
        self.family_history = tk.StringVar()
        
        # Current Health
        self.current_medications = tk.StringVar()
        self.symptoms = tk.StringVar()
        self.pain_level = tk.IntVar()
        
        # Lifestyle
        self.smoking_status = tk.StringVar()
        self.alcohol_consumption = tk.StringVar()
        self.exercise_frequency = tk.StringVar()
        
    def create_form(self):
        # Title
        title_label = tk.Label(self.scrollable_frame, text="PATIENT INTAKE AND HISTORY", 
                              font=("Arial", 16, "bold"), bg='#f0f0f0', fg='#2c3e50')
        title_label.grid(row=0, column=0, columnspan=3, pady=20, padx=20)
        
        row = 1
        
        # Personal Information Section
        self.create_section_header("Personal Information", row)
        row += 1
        
        # First Name
        tk.Label(self.scrollable_frame, text="First Name:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.first_name, width=25).grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Last Name
        tk.Label(self.scrollable_frame, text="Last Name:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.last_name, width=25).grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Date of Birth
        tk.Label(self.scrollable_frame, text="Date of Birth (MM/DD/YYYY):", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.date_of_birth, width=25).grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Gender
        tk.Label(self.scrollable_frame, text="Gender:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        gender_frame = tk.Frame(self.scrollable_frame, bg='#f0f0f0')
        gender_frame.grid(row=row, column=1, sticky="w", padx=10, pady=5)
        tk.Radiobutton(gender_frame, text="Male", variable=self.gender, value="Male", bg='#f0f0f0').pack(side="left")
        tk.Radiobutton(gender_frame, text="Female", variable=self.gender, value="Female", bg='#f0f0f0').pack(side="left")
        tk.Radiobutton(gender_frame, text="Other", variable=self.gender, value="Other", bg='#f0f0f0').pack(side="left")
        row += 1
        
        # Phone
        tk.Label(self.scrollable_frame, text="Phone Number:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.phone, width=25).grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Email
        tk.Label(self.scrollable_frame, text="Email:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.email, width=25).grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Social Security Number
        tk.Label(self.scrollable_frame, text="Social Security Number:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        ssn_entry = tk.Entry(self.scrollable_frame, textvariable=self.ssn, width=25, show="*")
        ssn_entry.grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Address
        tk.Label(self.scrollable_frame, text="Address:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.address, width=40).grid(row=row, column=1, columnspan=2, padx=10, pady=5)
        row += 1
        
        # Emergency Contact
        tk.Label(self.scrollable_frame, text="Emergency Contact Name:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.emergency_contact, width=25).grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Emergency Phone
        tk.Label(self.scrollable_frame, text="Emergency Contact Phone:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.emergency_phone, width=25).grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Insurance Information Section
        self.create_section_header("Insurance Information", row)
        row += 1
        
        # Insurance Provider
        tk.Label(self.scrollable_frame, text="Insurance Provider:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.insurance_provider, width=25).grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Policy Number
        tk.Label(self.scrollable_frame, text="Policy Number:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.policy_number, width=25).grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Group Number
        tk.Label(self.scrollable_frame, text="Group Number:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.group_number, width=25).grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Medical History Section
        self.create_section_header("Medical History", row)
        row += 1
        
        # Primary Care Physician
        tk.Label(self.scrollable_frame, text="Primary Care Physician:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        tk.Entry(self.scrollable_frame, textvariable=self.primary_care_physician, width=25).grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Allergies
        tk.Label(self.scrollable_frame, text="Known Allergies:", bg='#f0f0f0').grid(row=row, column=0, sticky="nw", padx=20, pady=5)
        self.allergies_text = scrolledtext.ScrolledText(self.scrollable_frame, width=30, height=2)
        self.allergies_text.grid(row=row, column=1, columnspan=2, padx=10, pady=5)
        row += 1
        
        # Chronic Conditions
        tk.Label(self.scrollable_frame, text="Chronic Conditions:", bg='#f0f0f0').grid(row=row, column=0, sticky="nw", padx=20, pady=5)
        conditions_frame = tk.Frame(self.scrollable_frame, bg='#f0f0f0')
        conditions_frame.grid(row=row, column=1, columnspan=2, sticky="w", padx=10, pady=5)
        
        self.condition_vars = {}
        conditions = ["Diabetes", "Hypertension", "Heart Disease", "Asthma", "Arthritis"]
        for i, condition in enumerate(conditions):
            var = tk.BooleanVar()
            self.condition_vars[condition] = var
            cb = tk.Checkbutton(conditions_frame, text=condition, variable=var, bg='#f0f0f0')
            cb.grid(row=i//2, column=i%2, sticky="w", padx=5)
        row += 1
        
        # Previous Surgeries
        tk.Label(self.scrollable_frame, text="Previous Surgeries:", bg='#f0f0f0').grid(row=row, column=0, sticky="nw", padx=20, pady=5)
        self.surgeries_text = scrolledtext.ScrolledText(self.scrollable_frame, width=30, height=2)
        self.surgeries_text.grid(row=row, column=1, columnspan=2, padx=10, pady=5)
        row += 1
        
        # Current Medications
        tk.Label(self.scrollable_frame, text="Current Medications:", bg='#f0f0f0').grid(row=row, column=0, sticky="nw", padx=20, pady=5)
        self.medications_text = scrolledtext.ScrolledText(self.scrollable_frame, width=30, height=2)
        self.medications_text.grid(row=row, column=1, columnspan=2, padx=10, pady=5)
        row += 1
        
        # Current Symptoms
        tk.Label(self.scrollable_frame, text="Current Symptoms:", bg='#f0f0f0').grid(row=row, column=0, sticky="nw", padx=20, pady=5)
        self.symptoms_text = scrolledtext.ScrolledText(self.scrollable_frame, width=30, height=2)
        self.symptoms_text.grid(row=row, column=1, columnspan=2, padx=10, pady=5)
        row += 1
        
        # Pain Level
        tk.Label(self.scrollable_frame, text="Pain Level (0-10):", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        pain_scale = tk.Scale(self.scrollable_frame, from_=0, to=10, orient="horizontal", variable=self.pain_level)
        pain_scale.grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Lifestyle Section
        self.create_section_header("Lifestyle Information", row)
        row += 1
        
        # Smoking Status
        tk.Label(self.scrollable_frame, text="Smoking Status:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        smoking_combo = ttk.Combobox(self.scrollable_frame, textvariable=self.smoking_status, width=20)
        smoking_combo['values'] = ("Never smoked", "Former smoker", "Current smoker")
        smoking_combo.grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Exercise Frequency
        tk.Label(self.scrollable_frame, text="Exercise Frequency:", bg='#f0f0f0').grid(row=row, column=0, sticky="w", padx=20, pady=5)
        exercise_combo = ttk.Combobox(self.scrollable_frame, textvariable=self.exercise_frequency, width=20)
        exercise_combo['values'] = ("Never", "Rarely", "1-2 times/week", "3-4 times/week", "Daily")
        exercise_combo.grid(row=row, column=1, padx=10, pady=5)
        row += 1
        
        # Buttons
        button_frame = tk.Frame(self.scrollable_frame, bg='#f0f0f0')
        button_frame.grid(row=row, column=0, columnspan=3, pady=20)
        
        submit_btn = tk.Button(button_frame, text="Submit Form", command=self.submit_form, 
                              bg='#3498db', fg='white', font=("Arial", 12, "bold"), padx=20)
        submit_btn.pack(side="left", padx=10)
        
        clear_btn = tk.Button(button_frame, text="Clear Form", command=self.clear_form, 
                             bg='#e74c3c', fg='white', font=("Arial", 12, "bold"), padx=20)
        clear_btn.pack(side="left", padx=10)
        
        save_btn = tk.Button(button_frame, text="Save to File", command=self.save_to_file, 
                            bg='#27ae60', fg='white', font=("Arial", 12, "bold"), padx=20)
        save_btn.pack(side="left", padx=10)
    
    def create_section_header(self, title, row):
        separator = tk.Frame(self.scrollable_frame, height=2, bg='#34495e')
        separator.grid(row=row, column=0, columnspan=3, sticky="ew", padx=20, pady=(20, 5))
        
        header_label = tk.Label(self.scrollable_frame, text=title, font=("Arial", 14, "bold"), 
                               bg='#f0f0f0', fg='#34495e')
        header_label.grid(row=row, column=0, columnspan=3, pady=(5, 10), padx=20)
    
    def submit_form(self):
        # Validate required fields
        if not self.first_name.get() or not self.last_name.get() or not self.date_of_birth.get():
            messagebox.showerror("Error", "Please fill in all required fields (Name and Date of Birth)")
            return
        
        # Collect all form data
        form_data = self.collect_form_data()
        
        # Display summary
        self.show_summary(form_data)
    
    def collect_form_data(self):
        # Get selected chronic conditions
        selected_conditions = [condition for condition, var in self.condition_vars.items() if var.get()]
        
        form_data = {
            "submission_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "personal_info": {
                "first_name": self.first_name.get(),
                "last_name": self.last_name.get(),
                "date_of_birth": self.date_of_birth.get(),
                "gender": self.gender.get(),
                "phone": self.phone.get(),
                "email": self.email.get(),
                "ssn": self.ssn.get(),
                "address": self.address.get(),
                "emergency_contact": self.emergency_contact.get(),
                "emergency_phone": self.emergency_phone.get()
            },
            "insurance": {
                "provider": self.insurance_provider.get(),
                "policy_number": self.policy_number.get(),
                "group_number": self.group_number.get()
            },
            "medical_history": {
                "primary_care_physician": self.primary_care_physician.get(),
                "allergies": self.allergies_text.get("1.0", tk.END).strip(),
                "chronic_conditions": selected_conditions,
                "previous_surgeries": self.surgeries_text.get("1.0", tk.END).strip(),
                "family_history": self.family_history_text.get("1.0", tk.END).strip()
            },
            "current_health": {
                "medications": self.medications_text.get("1.0", tk.END).strip(),
                "symptoms": self.symptoms_text.get("1.0", tk.END).strip(),
                "pain_level": self.pain_level.get()
            },
            "lifestyle": {
                "smoking_status": self.smoking_status.get(),
                "alcohol_consumption": self.alcohol_consumption.get(),
                "exercise_frequency": self.exercise_frequency.get()
            }
        }
        return form_data
    
    def show_summary(self, form_data):
        summary_window = tk.Toplevel(self.root)
        summary_window.title("Form Summary")
        summary_window.geometry("500x400")
        summary_window.configure(bg='#f0f0f0')
        
        text_widget = scrolledtext.ScrolledText(summary_window, width=60, height=25, bg='white')
        text_widget.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Format the summary
        summary_text = f"""MEDICAL INTAKE FORM SUMMARY
Submitted on: {form_data['submission_date']}

PERSONAL INFORMATION:
Name: {form_data['personal_info']['first_name']} {form_data['personal_info']['last_name']}
Date of Birth: {form_data['personal_info']['date_of_birth']}
Gender: {form_data['personal_info']['gender']}
Phone: {form_data['personal_info']['phone']}
Email: {form_data['personal_info']['email']}
SSN: ***-**-{form_data['personal_info']['ssn'][-4:] if len(form_data['personal_info']['ssn']) >= 4 else '****'}
Address: {form_data['personal_info']['address']}
Emergency Contact: {form_data['personal_info']['emergency_contact']} ({form_data['personal_info']['emergency_phone']})

INSURANCE INFORMATION:
Provider: {form_data['insurance']['provider']}
Policy Number: {form_data['insurance']['policy_number']}
Group Number: {form_data['insurance']['group_number']}

MEDICAL HISTORY:
Primary Care Physician: {form_data['medical_history']['primary_care_physician']}
Allergies: {form_data['medical_history']['allergies']}
Chronic Conditions: {', '.join(form_data['medical_history']['chronic_conditions']) if form_data['medical_history']['chronic_conditions'] else 'None reported'}
Previous Surgeries: {form_data['medical_history']['previous_surgeries']}
Family History: {form_data['medical_history']['family_history']}

CURRENT HEALTH:
Current Medications: {form_data['current_health']['medications']}
Current Symptoms: {form_data['current_health']['symptoms']}
Pain Level: {form_data['current_health']['pain_level']}/10

LIFESTYLE:
Smoking Status: {form_data['lifestyle']['smoking_status']}
Alcohol Consumption: {form_data['lifestyle']['alcohol_consumption']}
Exercise Frequency: {form_data['lifestyle']['exercise_frequency']}
"""
        
        text_widget.insert("1.0", summary_text)
        text_widget.config(state=tk.DISABLED)
        
        messagebox.showinfo("Success", "Form submitted successfully! Review the summary in the new window.")
    
    def clear_form(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all form data?"):
            # Clear all string variables
            for var in [self.first_name, self.last_name, self.date_of_birth, self.gender, 
                       self.phone, self.email, self.address, self.emergency_contact, 
                       self.emergency_phone, self.insurance_provider, self.policy_number, 
                       self.group_number, self.primary_care_physician, self.smoking_status, 
                       self.alcohol_consumption, self.exercise_frequency]:
                var.set("")
            
            # Clear text widgets
            for text_widget in [self.allergies_text, self.surgeries_text, 
                               self.medications_text, self.symptoms_text]:
                text_widget.delete("1.0", tk.END)
            
            # Clear checkboxes
            for var in self.condition_vars.values():
                var.set(False)
            
            # Reset pain level
            self.pain_level.set(0)
    
    def save_to_file(self):
        form_data = self.collect_form_data()
        filename = f"medical_intake_{form_data['personal_info']['last_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(form_data, f, indent=2)
            messagebox.showinfo("Success", f"Form data saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MedicalIntakeForm(root)
    root.mainloop()
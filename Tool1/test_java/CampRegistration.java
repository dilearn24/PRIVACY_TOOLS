import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;

public class CampRegistration extends JFrame {
    // Parent Information Fields
    private JTextField parentFirstNameField;
    private JTextField parentLastNameField;
    private JTextField parentEmailField;
    private JTextField parentPhoneField;
    private JTextField parentAddressField;
    private JTextField parentCityField;
    private JTextField parentStateField;
    private JTextField parentZipField;
    
    // Child Information Fields
    private JTextField childFirstNameField;
    private JTextField childLastNameField;
    private JTextField childAgeField;
    private JTextField childBirthdateField;
    private JComboBox<String> childGenderCombo;
    private JTextArea emergencyContactArea;
    private JTextArea medicalInfoArea;
    
    // Payment Information
    private JTextField paymentReferenceField;
    private JLabel paymentInstructionLabel;
    
    private JButton submitButton;
    private JButton clearButton;
    
    public CampRegistration() {
        initializeComponents();
        setupLayout();
        setupEventHandlers();
        
        setTitle("Summer Camp Registration");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 800);
        setLocationRelativeTo(null);
        setResizable(true);
    }
    
    private void initializeComponents() {
        // Parent Information
        parentFirstNameField = new JTextField(20);
        parentLastNameField = new JTextField(20);
        parentEmailField = new JTextField(20);
        parentPhoneField = new JTextField(20);
        parentAddressField = new JTextField(30);
        parentCityField = new JTextField(20);
        parentStateField = new JTextField(5);
        parentZipField = new JTextField(10);
        
        // Child Information
        childFirstNameField = new JTextField(20);
        childLastNameField = new JTextField(20);
        childAgeField = new JTextField(5);
        childBirthdateField = new JTextField(15);
        childBirthdateField.setToolTipText("MM/DD/YYYY");
        
        String[] genderOptions = {"Select Gender", "Male", "Female", "Other", "Prefer not to say"};
        childGenderCombo = new JComboBox<>(genderOptions);
        
        emergencyContactArea = new JTextArea(3, 30);
        emergencyContactArea.setLineWrap(true);
        emergencyContactArea.setWrapStyleWord(true);
        emergencyContactArea.setBorder(BorderFactory.createLoweredBevelBorder());
        
        medicalInfoArea = new JTextArea(4, 30);
        medicalInfoArea.setLineWrap(true);
        medicalInfoArea.setWrapStyleWord(true);
        medicalInfoArea.setBorder(BorderFactory.createLoweredBevelBorder());
        
        // Payment Information
        paymentReferenceField = new JTextField(20);
        paymentInstructionLabel = new JLabel("<html><div style='width: 400px;'>" +
            "<b>Payment Instructions:</b><br>" +
            "For security reasons, payment will be processed through our secure online portal. " +
            "After submitting this form, you will receive an email with a secure payment link. " +
            "Please enter any reference number if you've already made a payment." +
            "</div></html>");
        
        submitButton = new JButton("Submit Registration");
        clearButton = new JButton("Clear Form");
        
        // Style buttons
        submitButton.setBackground(new Color(34, 139, 34));
        submitButton.setForeground(Color.WHITE);
        submitButton.setFont(new Font("Arial", Font.BOLD, 14));
        
        clearButton.setBackground(new Color(220, 220, 220));
        clearButton.setFont(new Font("Arial", Font.PLAIN, 12));
    }
    
    private void setupLayout() {
        setLayout(new BorderLayout());
        
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Title
        JLabel titleLabel = new JLabel("Summer Camp Registration Form");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 18));
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER);
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        mainPanel.add(titleLabel, gbc);
        
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        
        // Parent Information Section
        addSectionHeader(mainPanel, "Parent/Guardian Information", gbc, 1);
        
        addLabelAndField(mainPanel, "First Name*:", parentFirstNameField, gbc, 2);
        addLabelAndField(mainPanel, "Last Name*:", parentLastNameField, gbc, 3);
        addLabelAndField(mainPanel, "Email*:", parentEmailField, gbc, 4);
        addLabelAndField(mainPanel, "Phone*:", parentPhoneField, gbc, 5);
        addLabelAndField(mainPanel, "Address*:", parentAddressField, gbc, 6);
        addLabelAndField(mainPanel, "City*:", parentCityField, gbc, 7);
        addLabelAndField(mainPanel, "State*:", parentStateField, gbc, 8);
        addLabelAndField(mainPanel, "ZIP Code*:", parentZipField, gbc, 9);
        
        // Child Information Section
        addSectionHeader(mainPanel, "Child Information", gbc, 10);
        
        addLabelAndField(mainPanel, "First Name*:", childFirstNameField, gbc, 11);
        addLabelAndField(mainPanel, "Last Name*:", childLastNameField, gbc, 12);
        addLabelAndField(mainPanel, "Age*:", childAgeField, gbc, 13);
        addLabelAndField(mainPanel, "Birthdate* (MM/DD/YYYY):", childBirthdateField, gbc, 14);
        addLabelAndComponent(mainPanel, "Gender:", childGenderCombo, gbc, 15);
        
        // Emergency Contact
        gbc.gridx = 0; gbc.gridy = 16;
        mainPanel.add(new JLabel("Emergency Contact*:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.BOTH;
        mainPanel.add(new JScrollPane(emergencyContactArea), gbc);
        gbc.fill = GridBagConstraints.NONE;
        
        // Medical Information
        gbc.gridx = 0; gbc.gridy = 17;
        mainPanel.add(new JLabel("Medical Info/Allergies:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.BOTH;
        mainPanel.add(new JScrollPane(medicalInfoArea), gbc);
        gbc.fill = GridBagConstraints.NONE;
        
        // Payment Section
        addSectionHeader(mainPanel, "Payment Information", gbc, 18);
        
        gbc.gridx = 0; gbc.gridy = 19; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        mainPanel.add(paymentInstructionLabel, gbc);
        
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        addLabelAndField(mainPanel, "Payment Reference (if applicable):", paymentReferenceField, gbc, 20);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.add(submitButton);
        buttonPanel.add(clearButton);
        
        gbc.gridx = 0; gbc.gridy = 21; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        mainPanel.add(buttonPanel, gbc);
        
        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        add(scrollPane, BorderLayout.CENTER);
    }
    
    private void addSectionHeader(JPanel panel, String text, GridBagConstraints gbc, int row) {
        JLabel sectionLabel = new JLabel(text);
        sectionLabel.setFont(new Font("Arial", Font.BOLD, 14));
        sectionLabel.setForeground(new Color(0, 100, 200));
        
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(sectionLabel, gbc);
        
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
    }
    
    private void addLabelAndField(JPanel panel, String labelText, JTextField field, GridBagConstraints gbc, int row) {
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel(labelText), gbc);
        gbc.gridx = 1;
        panel.add(field, gbc);
    }
    
    private void addLabelAndComponent(JPanel panel, String labelText, JComponent component, GridBagConstraints gbc, int row) {
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel(labelText), gbc);
        gbc.gridx = 1;
        panel.add(component, gbc);
    }
    
    private void setupEventHandlers() {
        submitButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (validateForm()) {
                    submitRegistration();
                }
            }
        });
        
        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                clearForm();
            }
        });
    }
    
    private boolean validateForm() {
        StringBuilder errors = new StringBuilder();
        
        // Validate required parent fields
        if (isFieldEmpty(parentFirstNameField)) errors.append("- Parent first name is required\n");
        if (isFieldEmpty(parentLastNameField)) errors.append("- Parent last name is required\n");
        if (isFieldEmpty(parentEmailField)) errors.append("- Parent email is required\n");
        if (isFieldEmpty(parentPhoneField)) errors.append("- Parent phone is required\n");
        if (isFieldEmpty(parentAddressField)) errors.append("- Parent address is required\n");
        if (isFieldEmpty(parentCityField)) errors.append("- Parent city is required\n");
        if (isFieldEmpty(parentStateField)) errors.append("- Parent state is required\n");
        if (isFieldEmpty(parentZipField)) errors.append("- Parent ZIP code is required\n");
        
        // Validate required child fields
        if (isFieldEmpty(childFirstNameField)) errors.append("- Child first name is required\n");
        if (isFieldEmpty(childLastNameField)) errors.append("- Child last name is required\n");
        if (isFieldEmpty(childAgeField)) errors.append("- Child age is required\n");
        if (isFieldEmpty(childBirthdateField)) errors.append("- Child birthdate is required\n");
        if (emergencyContactArea.getText().trim().isEmpty()) errors.append("- Emergency contact is required\n");
        
        // Validate email format
        if (!isFieldEmpty(parentEmailField) && !isValidEmail(parentEmailField.getText())) {
            errors.append("- Please enter a valid email address\n");
        }
        
        // Validate age is numeric
        if (!isFieldEmpty(childAgeField)) {
            try {
                int age = Integer.parseInt(childAgeField.getText().trim());
                if (age < 5 || age > 18) {
                    errors.append("- Child age must be between 5 and 18\n");
                }
            } catch (NumberFormatException ex) {
                errors.append("- Child age must be a valid number\n");
            }
        }
        
        // Validate birthdate format
        if (!isFieldEmpty(childBirthdateField) && !isValidDate(childBirthdateField.getText())) {
            errors.append("- Please enter birthdate in MM/DD/YYYY format\n");
        }
        
        if (errors.length() > 0) {
            JOptionPane.showMessageDialog(this, 
                "Please correct the following errors:\n\n" + errors.toString(),
                "Validation Errors", 
                JOptionPane.ERROR_MESSAGE);
            return false;
        }
        
        return true;
    }
    
    private boolean isFieldEmpty(JTextField field) {
        return field.getText().trim().isEmpty();
    }
    
    private boolean isValidEmail(String email) {
        String emailRegex = "^[A-Za-z0-9+_.-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})$";
        return Pattern.matches(emailRegex, email);
    }
    
    private boolean isValidDate(String date) {
        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MM/dd/yyyy");
            LocalDate.parse(date, formatter);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    private void submitRegistration() {
        String message = "Registration submitted successfully!\n\n" +
                        "Parent: " + parentFirstNameField.getText() + " " + parentLastNameField.getText() + "\n" +
                        "Child: " + childFirstNameField.getText() + " " + childLastNameField.getText() + "\n" +
                        "Email: " + parentEmailField.getText() + "\n\n" +
                        "You will receive a confirmation email with payment instructions shortly.";
        
        JOptionPane.showMessageDialog(this, message, "Registration Successful", JOptionPane.INFORMATION_MESSAGE);
        clearForm();
    }
    
    private void clearForm() {
        // Clear parent fields
        parentFirstNameField.setText("");
        parentLastNameField.setText("");
        parentEmailField.setText("");
        parentPhoneField.setText("");
        parentAddressField.setText("");
        parentCityField.setText("");
        parentStateField.setText("");
        parentZipField.setText("");
        
        // Clear child fields
        childFirstNameField.setText("");
        childLastNameField.setText("");
        childAgeField.setText("");
        childBirthdateField.setText("");
        childGenderCombo.setSelectedIndex(0);
        emergencyContactArea.setText("");
        medicalInfoArea.setText("");
        
        // Clear payment field
        paymentReferenceField.setText("");
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new CampRegistration().setVisible(true);
            }
        });
    }
}
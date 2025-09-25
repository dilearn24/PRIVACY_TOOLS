#include <iostream>
#include <string>
#include <iomanip>
#include <limits>
#include <cstdlib>
#include <ctime>

using namespace std;

struct PersonalInfo {
    string firstName;
    string lastName;
    string ssn;
    string dateOfBirth;
    string address;
    string city;
    string state;
    string zipCode;
    string phoneNumber;
    string email;
    double annualIncome;
    string employmentStatus;
};

class CreditScoreChecker {
private:
    PersonalInfo userInfo;
    
public:
    void displayMenu() {
        cout << "\n" << string(50, '=') << endl;
        cout << "     CREDIT SCORE CHECKING SYSTEM" << endl;
        cout << string(50, '=') << endl;
        cout << "1. Enter Personal Information" << endl;
        cout << "2. Review Submitted Information" << endl;
        cout << "3. Check Credit Score (Simulation)" << endl;
        cout << "4. Clear All Data" << endl;
        cout << "5. Exit Program" << endl;
        cout << string(50, '=') << endl;
        cout << "Select an option (1-5): ";
    }
    
    void collectPersonalInfo() {
        cout << "\n" << string(40, '-') << endl;
        cout << "    PERSONAL INFORMATION FORM" << endl;
        cout << string(40, '-') << endl;
        
        cout << "First Name: ";
        cin.ignore();
        getline(cin, userInfo.firstName);
        
        cout << "Last Name: ";
        getline(cin, userInfo.lastName);
        
        cout << "Social Security Number (XXX-XX-XXXX): ";
        getline(cin, userInfo.ssn);
        
        cout << "Date of Birth (MM/DD/YYYY): ";
        getline(cin, userInfo.dateOfBirth);
        
        cout << "Street Address: ";
        getline(cin, userInfo.address);
        
        cout << "City: ";
        getline(cin, userInfo.city);
        
        cout << "State: ";
        getline(cin, userInfo.state);
        
        cout << "ZIP Code: ";
        getline(cin, userInfo.zipCode);
        
        cout << "Phone Number: ";
        getline(cin, userInfo.phoneNumber);
        
        cout << "Email Address: ";
        getline(cin, userInfo.email);
        
        cout << "Annual Income ($): ";
        while (!(cin >> userInfo.annualIncome) || userInfo.annualIncome < 0) {
            cout << "Please enter a valid income amount: $";
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
        cin.ignore();
        
        cout << "Employment Status (Employed/Unemployed/Self-Employed/Retired): ";
        getline(cin, userInfo.employmentStatus);
        
        cout << "\nInformation collected successfully!" << endl;
        cout << "Press Enter to continue...";
        cin.get();
    }
    
    void reviewInformation() {
        if (userInfo.firstName.empty()) {
            cout << "\nNo information has been entered yet." << endl;
            cout << "Please select option 1 to enter your information first." << endl;
            return;
        }
        
        cout << "\n" << string(40, '-') << endl;
        cout << "    SUBMITTED INFORMATION REVIEW" << endl;
        cout << string(40, '-') << endl;
        cout << left << setw(20) << "Name:" << userInfo.firstName << " " << userInfo.lastName << endl;
        cout << left << setw(20) << "SSN:" << userInfo.ssn << endl;
        cout << left << setw(20) << "Date of Birth:" << userInfo.dateOfBirth << endl;
        cout << left << setw(20) << "Address:" << userInfo.address << endl;
        cout << left << setw(20) << "City:" << userInfo.city << endl;
        cout << left << setw(20) << "State:" << userInfo.state << endl;
        cout << left << setw(20) << "ZIP Code:" << userInfo.zipCode << endl;
        cout << left << setw(20) << "Phone:" << userInfo.phoneNumber << endl;
        cout << left << setw(20) << "Email:" << userInfo.email << endl;
        cout << left << setw(20) << "Annual Income:" << "$" << fixed << setprecision(2) << userInfo.annualIncome << endl;
        cout << left << setw(20) << "Employment:" << userInfo.employmentStatus << endl;
        cout << string(40, '-') << endl;
        
        cout << "Press Enter to continue...";
        cin.ignore();
        cin.get();
    }
    
    void simulateCreditCheck() {
        if (userInfo.firstName.empty()) {
            cout << "\nNo information has been entered yet." << endl;
            cout << "Please select option 1 to enter your information first." << endl;
            return;
        }
        
        cout << "\n" << string(40, '-') << endl;
        cout << "    PROCESSING CREDIT CHECK..." << endl;
        cout << string(40, '-') << endl;
        cout << "Contacting credit bureaus..." << endl;
        cout << "Analyzing credit history..." << endl;
        cout << "Calculating score..." << endl;
        
        // Simple simulation based on income - demonstration purposes only
        int creditScore;
        string creditRating;
        
        if (userInfo.annualIncome >= 75000) {
            creditScore = 750 + (rand() % 100);
            creditRating = "Excellent";
        } else if (userInfo.annualIncome >= 50000) {
            creditScore = 650 + (rand() % 100);
            creditRating = "Good";
        } else if (userInfo.annualIncome >= 30000) {
            creditScore = 550 + (rand() % 100);
            creditRating = "Fair";
        } else {
            creditScore = 450 + (rand() % 150);
            creditRating = "Poor";
        }
        
        cout << "\n" << string(40, '=') << endl;
        cout << "    CREDIT SCORE RESULTS" << endl;
        cout << string(40, '=') << endl;
        cout << "Hello " << userInfo.firstName << " " << userInfo.lastName << "!" << endl;
        cout << "Your Credit Score: " << creditScore << endl;
        cout << "Credit Rating: " << creditRating << endl;
        cout << string(40, '=') << endl;
        
        cout << "\nNote: This is a simulated result for demonstration purposes only." << endl;
        cout << "For actual credit scores, please contact authorized credit reporting agencies." << endl;
        
        cout << "Press Enter to continue...";
        cin.ignore();
        cin.get();
    }
    
    void clearData() {
        userInfo = PersonalInfo(); // Reset to default values
        cout << "\nAll data has been cleared successfully!" << endl;
        cout << "Press Enter to continue...";
        cin.ignore();
        cin.get();
    }
    
    void run() {
        int choice;
        
        cout << "Welcome to the Credit Score Checking System!" << endl;
        cout << "This program will help you submit information for credit score verification." << endl;
        
        do {
            displayMenu();
            
            while (!(cin >> choice) || choice < 1 || choice > 5) {
                cout << "Invalid input. Please enter a number between 1 and 5: ";
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }
            
            switch (choice) {
                case 1:
                    collectPersonalInfo();
                    break;
                case 2:
                    reviewInformation();
                    break;
                case 3:
                    simulateCreditCheck();
                    break;
                case 4:
                    clearData();
                    break;
                case 5:
                    cout << "\nThank you for using the Credit Score Checking System!" << endl;
                    cout << "Goodbye!" << endl;
                    break;
                default:
                    cout << "Invalid option. Please try again." << endl;
            }
            
        } while (choice != 5);
    }
};

int main() {
    srand(time(0)); // Seed for random number generation
    
    CreditScoreChecker checker;
    checker.run();
    
    return 0;
}
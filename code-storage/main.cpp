#include <iostream>
#include <iomanip>
#include <ctime>

void displayCurrentMonth() {
    // Get current date
    time_t now = time(0);
    tm *ltm = localtime(&now);

    // Get current year and month
    int year = 1900 + ltm->tm_year; // Year since 1900
    int month = 1 + ltm->tm_mon; // Month is 0-11

    // Print month and year header
    std::cout << "   " << ltm->tm_mon + 1 << " " << year << std::endl;
    std::cout << "Mo Tu We Th Fr Sa Su" << std::endl;

    // Calculate the first day of the month and number of days in the month
    tm firstDay = *ltm;
    firstDay.tm_mday = 1; // Set to the first day of the month
    mktime(&firstDay); // Normalize the tm structure

    // Print leading spaces for the first week
    for (int i = 0; i < firstDay.tm_wday; i++) {
        std::cout << "   "; // 3 spaces for each day
    }

    // Calculate number of days in the month
    int daysInMonth = 31;
    if (month == 2) {
        // Check for leap year
        daysInMonth = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) ? 29 : 28;
    } else if (month == 4 || month == 6 || month == 9 || month == 11) {
        daysInMonth = 30;
    }

    // Print the days of the month
    for (int day = 1; day <= daysInMonth; day++) {
        std::cout << std::setw(2) << day << " "; // Print day with padding
        if ((firstDay.tm_wday + day) % 7 == 0) { // Move to the next line after Saturday
            std::cout << std::endl;
        }
    }
    std::cout << std::endl; // Add a newline after the calendar
}

int main() {
    displayCurrentMonth();
    return 0;
}
